# Device DNS investigation and collector reliability

## Local workflow

Start the Linux application and its foreground collector as described in
[TELEMETRY_COLLECTOR.md](TELEMETRY_COLLECTOR.md). In **Collected connections →
Collected DNS observations**, include Observe groups when investigating ordinary
queries, select an observed device, then a queried domain. The same investigation
is available for uploaded DNS telemetry in the device triage view. English and
Turkish are supported.

`dns-device-timeline-v1` charts retained query counts in UTC and lists response
categories per bucket: NOERROR, NXDOMAIN, SERVFAIL, REFUSED, other and unanswered.
Numeric response-code equivalents are normalized. Existing priority/evidence
remains visible. This is an investigation view; it adds no detector, threshold,
DNS/connection join, malware verdict or ML promotion.

- At most 200 eligible client/domain groups have timelines, each with 48 buckets.
  Bucket width starts at 60 seconds and grows to fit the observed span. Empty
  buckets retain gaps; they do not prove that no DNS traffic occurred.
- Unknown clients and IP fallback targets have no DNS chart. Missing/naive times
  remain explicit untimed query counts. Upload duplicates retain the existing
  observation semantics; collector copies/conflicts follow its existing policy.
- Group numbers refer to this report. DNS aliases and connection host aliases
  are independent. A resolver/NAT address need not identify the original device.
- Querying a domain does not prove a connection, download, execution or compromise.
  DNS over HTTPS/TLS and sensor placement can limit upstream visibility.
- The table/selector uses the first 500 visible groups. Collection exports retain
  the first 1,000 prioritized DNS groups with omitted counts; upload device exports
  retain all findings within input limits. Chart limits apply separately.

Device JSON schema 1 gains optional `Group` references and `timelines`; old
snapshots remain readable and prompt for collector restart to obtain charts.
Aggregate analysis/history output does not gain this private investigation block.
Default exports omit client/answer IPs and raw rows; the existing upload-only
explicit client-IP toggle remains available locally. Aliases, domain names and
timing are sensitive telemetry, not anonymization. Keep reports/state outside Git.

## Collector operation

Completed-log policy and SQLite schema remain `closed-zeek-collector-v2` / 2.
Three indexes cover timestamp retention, ingestion expiry and DNS-name pruning.
Within one process, unchanged evidence and CTI reuse analysis; new/pruned rows or
CTI changes recompute it. Mutable CTI records are compared against a private copy.
Expected-connection declarations are still evaluated on every scan, including
expiry while analysis is cached. Restart rebuilds analysis from checkpoints.

Snapshots add bounded scan metadata: candidate and attempted file counts,
unexamined candidates after the 64-attempt budget, categorized format/limit,
archive, access and encoding rejections, and whether analysis was recomputed.
Remaining candidates may be open or unchanged; they are **not a ready backlog**.
Scan timing ends before connection report serialization and atomic publication;
it is not full tick or packet-to-alert latency. The UI reports stale snapshots,
rejections and capacity loss. A disk-full CLI error tells the user to free space
and restart the same state without exposing exception paths/content.

A random `selection_revision` survives idle refresh/restart while ordered group
identity mappings match, keeping an analyst's selection. Mapping changes reset
it. Raw endpoint identities and their comparison hash stay in private SQLite;
the exported epoch is not an endpoint hash or stable asset identifier. Legacy
snapshots fall back to the earlier refresh-reset behavior. DNS report generation
time reflects its last analysis, while collector `updated_at` reflects each scan.

## Declared evaluation scope

Before implementation, `collector-reliability-v1` declared a 20-minute internal
UDP/TCP `.test` workload, 30-second Zeek rotation, 10-second collector polling,
SIGTERM/restart at observer second 240, SIGKILL/restart at 480 and a 45-second
pause at 720. Runtime modules were copied/hashed before observation; they must
still match when reconciling. Workload/manifest/policy hashes precede capture.
The SSH relay only targets the local VM forward and writes checksummed private
copies every five seconds. Sampled RSS/state size and file delivery/publication
latencies are separate from detection accuracy.

The guest sensor uses its dedicated internal bridge, no forwarded DNS, a pinned
image and NET_RAW capability inside the isolated VM. Output/policy group access
is confined to a private run directory. Initial setup failures (capture capability
and policy read permission) remain private failed receipts; the corrected
30-second preflight reconciles 72 queries and six connections. A first evaluation
incorrectly omitted final `dns.log`/`conn.log`; including both final and rotated
files restored exact agreement without changing runtime or input records.

Malformed gzip, actual unreadable-file/repaired-file retry, fair scan progression,
atomic snapshot ENOSPC with retained checkpoints, actionable SQLite-full handling,
mutable CTI refresh, retention and idle-rule expiry have regression controls.
ENOSPC is injected at the publication boundary; it is not a real full-filesystem
or power-loss experiment.

## Live result (2026-10-05 local date)

New UTC-named recording `rotation-live-20261004T231339Z` ran for 1,200 seconds.
The observer attached after startup and ran 1,195.19 seconds with 115 snapshot
ticks. All 84 closed files, including final `dns.log`/`conn.log`, were processed.
Packets, Zeek and collector reconcile **2,880 DNS queries** (UDP/TCP 1,440/1,440)
plus **240 connections**. NOERROR/NXDOMAIN/SERVFAIL/unanswered counts are
960/720/720/480. Original findings/timelines/attempts and DNS findings/timelines/
coverage match offline. SQLite integrity is `ok`; restart adds zero records and
two gzip copies are duplicates. No rejected files, pruning or tcpdump-reported
kernel drops. Zero review groups on this short control does not validate the
30-minute/one-hour behavior gates or establish benign FPR.

Owned-process actions occurred at observer seconds 240.93 (SIGTERM), 480.79
(SIGKILL), 720.54 (pause) and 765.73 (resume). After catch-up all 3,120 evidence
records remain. Sampled process RSS peak **217,874,432 bytes** and owned-state
peak **2,564,349 bytes** are 1-second observations, not guaranteed peaks.

| Measured component, 84 files | p50 | p95 | Max |
| --- | --- | --- | --- |
| Closed-file mtime proxy → SSH delivery | 2.630 s | 5.012 s | 5.178 s |
| Delivery → snapshot observed | 5.426 s | 10.658 s | 44.852 s |

These components include the planned pause/restarts. The first uses guest mtime,
not a precise close event (one SSH clock check bounds guest-minus-host between
-0.004 and +0.180 seconds). The second includes 10-second polling and 1-second
observation. Neither is packet-to-alert latency; packet time still precedes log
closure/30-second rotation. The SSH relay is an experiment delivery mechanism,
not a newly installed production service. Twenty minutes of small synthetic
traffic is not multi-day/enterprise evidence.

After frozen live evaluation passed, only `ui_dns_timeline.py` changed: a
multi-domain device-switch regression caught a stale target/formatting state.
The UI now clears targets outside the selected device and safely formats old
widget state. The frozen bundle and final delta receipt remain private; collector
and analysis module hashes are unchanged. Final tests and actual live-snapshot
English/Turkish selector checks pass: **1,119 tests, 91% coverage**. All 34
preexisting local data files retain checksums. Source audit has no findings;
Ruff/Bash/diff checks pass. The test VM returned to its initial stopped state.

Only method/source/aggregate receipts are published:

| External receipt | SHA-256 |
| --- | --- |
| Preimplementation plan | `09e490857c4179b9f136960a446dc973e0d6358ef02281128cc75e97c45a64e5` |
| Frozen live source catalog | `a5d5c495cc631009d61ebd3bbc96e3c44b3965bf0f7a82a1b136d10b3933ad46` |
| Live aggregate proof | `2285821a7b26082b3f29685206a39915c0a68c25d4b8f96107bfac27c314d809` |
| Capacity aggregate proof | `1f0e6b77fc8bf95a0587dcba3063424f7f12ffc8cd6e25d0aa4d753a55f0bfbd` |

## Private reproduction

The separate synthetic capacity check generates 120 files with 1,000 rows each
(60k connection + 60k DNS). Scans attempt 64 then 56 files; the shared 100k limit
discloses 20k pruned records, retaining 40k connections + 60k DNS. The idle third
scan adds none, reuses analysis and does not reintroduce pruned rows. Integrity,
snapshot validation and capacity-loss disabling of declarations pass.
One local measurement: full tick walls **8.611 / 12.293 / 0.103 seconds**, sampled
process RSS peak **456,998,912 bytes**, sampled owned-state peak **82,087,782 bytes**
(50 ms sampling, includes SQLite sidecars, excludes fixture generation).
This is a single synthetic backlog, not enterprise throughput or guaranteed peak
memory/disk. Evidence capacity is a logical bound, not a filesystem quota.

Use the existing isolated guest in [LOCAL_LAB.md](LOCAL_LAB.md). Copy
`dns_collector_workload.py`, `rotation_workload.py` and `run_rotation_live.sh`
from `scripts/lab/` into its `~/threatfusion-lab`. Run inside that guest:

```bash
bash ~/threatfusion-lab/run_rotation_live.sh 1200
```

Read `~/threatfusion-lab/latest-rotation-live` after startup. In a host checkout
with its environment installed, observe that run concurrently in a **fresh**
private directory outside the repository:

```bash
python -m scripts.lab.observe_rotation \
  --root /absolute/private/new-observation \
  --run results/rotation-live-YYYYMMDDTHHMMSSZ \
  --key /private/lab/ssh-key --known-hosts /private/lab/known_hosts
```

The default SSH target is `lab@127.0.0.1:22220`. The harness signals only its own
collector subprocess. Wait for capture cleanup and observation completion, copy
the entire new guest result directory privately outside Git, then run:

```bash
python -m scripts.lab.evaluate_rotation \
  --root /absolute/private/new-observation \
  --capture-dir /absolute/private/rotation-live-YYYYMMDDTHHMMSSZ
python -m scripts.lab.measure_collector_capacity \
  --root /absolute/private/new-capacity-run
```

Reconciliation includes final and rotated closed files, packet query counts,
original connection findings/timelines/attempts, DNS findings/timelines/coverage,
SQLite integrity and restart/gzip copies. The packet counter deliberately accepts
only this fixture's small unfragmented queries/single-segment TCP frames; it is
not a general stream reassembler. Scripts use exclusive receipts and refuse
repo-contained/nonprivate experiment roots. New runs need fresh roots; previously
inspected evidence must keep its original identity.

## Remaining acceptance gates

Active-log incremental tailing is deferred: closed-file latency still includes
rotation, delivery and polling. Configure rotation deliberately; see the
[official logging framework source](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/logging/main.zeek).
Longer permitted benign/malicious windows, representative multi-day load/security
review, installation/recovery checks and human analyst tasks remain open. These
synthetic controls do not establish enterprise FPR, recall, RITA parity, saved
analyst time or production readiness. Predeclare DNS tunneling/general UDP and
sparse-failure controls separately before tuning; obtain new reserved recordings.
ML identities/thresholds, missing original artifact, insufficient strict-temporal
evidence and deferred augmented runtime promotion are unchanged. Hosting remains
suspended; no new public listener or site is part of this increment.
