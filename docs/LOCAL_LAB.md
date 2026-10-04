# Local Zeek / ThreatFusion lab

Status: the first **capture and DNS-ingestion smoke test** passed on 2026-10-04.
RITA is not installed yet. No detection comparison, production-readiness claim,
ML evaluation or runtime promotion follows from this test.

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
- Graceful shutdown/restart and SSH reconnection were verified. The lab is
  left shut down with autostart disabled; use `./lab ssh` to boot and enter it.

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

Next, freeze labeled normal/controlled-suspicious scenarios, record expected
outcomes and generate a sufficiently long observation window before installing
RITA for comparison. Compare the same immutable Zeek records and keep tuning
data separate from evaluation data. Include legitimate periodic traffic to
measure false alarms. This smoke dataset is far too small to measure beaconing,
DNS tunneling, long-connection detection or enterprise load.

References: [Ubuntu images](https://cloud-images.ubuntu.com/noble/),
[Zeek image](https://github.com/activecm/docker-zeek),
[RITA](https://github.com/activecm/rita).
