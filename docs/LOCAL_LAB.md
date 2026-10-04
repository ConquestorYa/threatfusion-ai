# Local Zeek / ThreatFusion lab

Status (2026-10-04): the capture smoke test and the first **periodic-controls-v1**
live/replay comparison passed their input-validation gates. RITA v5.1.2 is
installed as an isolated comparison CLI. These are synthetic engineering
observations, not a malware benchmark, ML evaluation or runtime promotion.

## Current local instance

- QEMU/KVM VM named `threatfusion-lab`, managed by `qemu:///session`.
- Ubuntu Server 24.04, four virtual CPUs, 16 GiB RAM, sparse 250 GiB disk.
- Official Ubuntu cloud image verified against its published SHA-256 manifest.
- Docker Engine and Compose installed inside the guest.
- VM files, private SSH key, seed ISO, packet captures and logs live **outside
  this repository**, in the sibling `threatfusion-lab` workspace directory.
- Management SSH is forwarded only through `127.0.0.1:22220`. No guest UI,
  public site, tunnel, VM autostart or existing libvirt-network change is added.
- The VM management interface has outbound connectivity for installation.
  The separate synthetic Docker test network uses `--internal` and publishes
  no ports. Do not describe the entire VM as air-gapped.
- The existing Kali VM and its networks are unchanged.
- Graceful shutdown/restart and SSH reconnection were verified. Autostart stays
  disabled. The follow-up respects an already-open user SSH session and leaves
  the VM running; `./lab stop` releases its host RAM when the user is finished.

The local launcher belongs to this configured instance; it is not the product's
Linux installer or a portable one-command VM installer. From the workspace:

```bash
cd ../threatfusion-lab
./lab start   # boot the lab
./lab ssh     # boot if needed, then open its Ubuntu terminal
./lab smoke   # run the synthetic capture test; VM must be ready
./lab status
./lab stop    # graceful shutdown; allow time for it to finish
./lab view    # virt-manager console using the user/session connection
./lab scenario # new 60-second live control run, then host-side DNS validation
./lab results  # read the frozen replay comparison summary, no VM required
./lab rita     # open RITA's terminal interface on the replay dataset
```

Ubuntu Server has no desktop. SSH uses the newly generated lab-only key; no
developer feed credentials or other private files are copied into the VM.
The VM appears under the **QEMU/KVM user session**, not the system connection
that contains Kali. Closing virt-manager does not stop the VM.

## Reusable smoke-test sources

`scripts/lab/` contains the synthetic server, client and guest runner. On an
Ubuntu guest with Docker, Python 3 and tcpdump, place the three files in
`~/threatfusion-lab/`, then run:

```bash
bash ~/threatfusion-lab/run_smoke_guest.sh
```

The normal user needs Docker access and sudo access for **guest-only** packet
capture. The runner downloads pinned image digests only when missing; after the
images are present it can rerun without image downloads. Existing resources
with the same names are rejected rather than reused or removed.

Three short-lived clients (`172.30.80.11` through `.13`) query `normal.test`
against the synthetic DNS server (`172.30.80.53`), then request `/normal` from
its HTTP server. The server never forwards DNS to real resolvers. Neither
actual malware nor known-malicious destinations are used.

tcpdump captures only the dedicated `br-tflab` bridge inside the guest. Zeek
then processes the resulting PCAP offline with network access disabled and
the guest user's UID/GID. This demonstrates visibility of traffic from three
clients; merely connecting a sensor container to the same network would not
provide that visibility. It is not yet a continuously running sensor.

The pinned Active Countermeasures Zeek 8.0.6 image sets a `ZEEKPATH` that omits
the built-in plugin directory. The offline invocation unsets this override so
Zeek uses its compiled defaults. `-C` disables checksum verification for virtual
capture/offloading; it is recorded in the summary and is not a universal
production configuration recommendation.

Each run saves timestamped PCAP/logs, image identities and aggregate assertions
in the **guest's local** `results/` directory. The current host wrapper also
copies them into its private workspace. It removes its test server/network on
exit. Never upload packet captures, keys, VM disks or real telemetry to GitHub.

## Evidence and next gate

The final digest-pinned smoke run observed three successful DNS exchanges and
three HTTP 200 responses. ThreatFusion's existing Zeek reader accepted all
three DNS events with correct client addresses, query, answer, response code
and valid timestamps. Its related reader/behavior tests passed (29 tests).
The complete project regression passed (850 tests), together with Ruff, Bash
syntax and the tracked-tree/history privacy audit.

## Periodic-control comparison

The predeclared `periodic-controls-v1` protocol (seed 20261004) assigns three
clients inside an internal-only `198.18.0.0/16` guest Docker network:

| Role | Client | Intended behavior |
| --- | --- | --- |
| Browser | `198.18.1.11` | Irregular DNS/HTTP requests to three synthetic sites |
| Updater | `198.18.1.12` | Legitimate periodic update checks |
| Heartbeat | `198.18.1.13` | Periodic communication simulating suspicious behavior |

The last two deliberately share timing and fixed harmless payloads. Ground
truth describes **the lab's intent**, not confirmed malware. Each request
explicitly queries DNS; real clients may cache answers. No malware runs and
all destinations stay in the lab. Client labels are used to validate counts
and report results, never supplied to either detector.

- **Live:** three concurrent clients, a 60-second schedule, two-second periodic
  interval, 18/30/30 requests. Actual bridge capture validated 78 DNS exchanges
  and 78 HTTP 200 responses, with zero kernel drops in this small run.
- **Replay:** deterministic checksum-valid Ethernet/IP/UDP/TCP/HTTP packets
  representing a synthetic day on 2026-09-01, with 240/288/288 requests and a
  five-minute periodic interval. Zeek processed it offline **without `-C`** and
  all 816 DNS exchanges / 816 HTTP responses matched the manifest. This is not
  a 24-hour live capture or strict temporal ML evidence.

The manifest/hash is saved before capture or replay generation. Reports record
hashes of the exact shared Zeek inputs. The datasets use separate non-rolling
RITA imports (`periodic_controls_v1`, `periodic_controls_live_v1`). CTI feeds and
ML are disabled in **both** comparison baselines; no developer key/cache/model
is copied. RITA receives DNS/connection/HTTP logs, while ThreatFusion's existing
behavior verdict consumes DNS only; their scores/verdict labels are not equal
units or calibrated malware probabilities.

### Observed outcome, without tuning

| Synthetic replay role | ThreatFusion DNS-only baseline | RITA native output |
| --- | --- | --- |
| Browser | Low; no periodic context | Medium/High HTTP findings, beacon 0.739–0.794 |
| Legitimate updater | Low; periodic context present | Critical, beacon 1.0 |
| Suspicious simulation | Low; periodic context present | Critical, beacon 1.0 |

The first live capture also exported Critical findings for both periodic
controls. ThreatFusion records regularity as context but does not independently
escalate these events to an alert without other qualifying evidence. RITA's
export includes `mime_type_mismatch` and, in replay, `rare_signature` modifiers;
our artificial URI/MIME/user-agent and fixed-size traffic can influence its
severity. Neither result proves superiority or malware-detection accuracy.
Keep this v1 input/output intact; do not tune thresholds on these observations.

### Reproduce and inspect

Inside the current Ubuntu terminal:

```bash
bash ~/threatfusion-lab/run_periodic_live.sh
# In a second terminal while it runs:
docker ps
docker logs -f tf-periodic-heartbeat-client
# After completion:
cd ~/threatfusion-lab
RUN=$(cat latest-periodic-live)
cat "$RUN/zeek/dns.log"
bash rita-runtime/rita_lab.sh view periodic_controls_v1
```

The seven traffic containers are temporary and removed after a run. RITA's
ClickHouse backend is separately controlled; the terminal viewer starts it on
demand. Stop it with `bash ~/threatfusion-lab/rita-runtime/rita_lab.sh stop`.
It publishes no ports, has an internal-only analysis network, no restart policy
and a local persistent Docker volume. Native terminal display is optional;
plain text/JSON comparison reports are also copied into the guest.

For a new checkout, use the project's Python environment for the generator and
reporter; guest live clients need only standard Python. The new scripts are:

```bash
.venv/bin/python scripts/lab/periodic_scenario.py replay --output-dir /path/outside/repo/new-replay
.venv/bin/python scripts/lab/prepare_rita_lab.py --output-dir /path/outside/repo/new-rita-runtime
.venv/bin/python scripts/lab/analyze_periodic.py --directory /path/to/captured-run --rita-csv /path/to/rita.csv
```

Place the prepared RITA directory and scenario scripts in the guest. The
preparer verifies the fixed official release archive SHA-256, preserves its
upstream license/assets locally and refuses existing output directories.
The wrapper uses pinned RITA/ClickHouse image digests (pull these before running
it). Only update checks, online feeds and the lab's internal subnet differ from
the official release config; scoring/modifiers remain byte-identical. Both
detectors and the replay use the same frozen input records. The source code and
method are shareable; VM disks, downloaded upstream assets, CSV/JSON evaluation
outputs and telemetry remain outside Git.

Six regression checks cover checksum-valid wire records, deterministic replay,
the benign periodic control, DNS destination boundaries, immutable manifests,
native CSV parsing and invalid-release rejection. The next evidence gate is
more realistic benign traffic and independent permitted recordings, with
explicit test plans. Tunneling, long connections, encrypted DNS, continuous
ingestion, production scale and device incident workflow remain untested.

References: [Ubuntu images](https://cloud-images.ubuntu.com/noble/),
[Zeek image](https://github.com/activecm/docker-zeek),
[RITA](https://github.com/activecm/rita).
