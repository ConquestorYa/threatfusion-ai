# Connection investigation and real termination controls

Status: 2026-10-05 (Turkey). Capture filenames use UTC 2026-10-04.

## Analyst workflow

Keep the local web interface. In **Connection activity** or **Collected
connections**, choose a visible group under **Connection investigation**.
The chart shows connection starts in UTC; the table shows observed Zeek states,
known payload byte sums and separate counts of connections with unknown bytes.
Disable the reviews-only filter to investigate Observe groups. Expected-activity
filtering remains reversible, and CTI conflicts remain visible.

These are connection-start aggregates, not packet or transfer timelines.
A long session's entire recorded bytes/state belong to its start bucket.
An empty bucket means no retained starts, not proof of an idle network. A reset,
rejection or incomplete close is an observation, not a malware verdict. TLS
contents, URLs, downloads, execution and software identity are not inferred.
Zeek defines `ts` as the first packet's time and documents the termination
states in its [official connection script](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/conn/main.zeek).

## Bounds, missing evidence and privacy

- At most **200 groups**, in existing detector order (Review first), receive
  timelines. Every finding remains in the JSON download, including omitted
  timelines. No CTI reranking or detector/ML threshold changes.
- Each timeline has at most **48** consecutive buckets. Resolution starts at
  **300 seconds** and expands in 300-second multiples to cover the group's span.
  Empty intermediate buckets are included. No interpolation or invented samples.
- Global UID deduplication/conflict exclusion matches connection findings.
  Missing UIDs and globally conflicting UIDs contribute no timeline evidence.
  Missing/naive timestamps are counted as untimed and excluded from the chart.
  Unknown byte counts are never represented as complete known zero totals.
  Unrecognized state text becomes `unknown`; raw input state strings are omitted.
- Both views render/select at most **500 filtered groups**. Exports retain all
  groups. Collector snapshots retain the existing 64 MiB read limit; optional
  timeline blocks validate bounds, UTC spacing and count reconciliation.
- Schema **2** is extended additively with `Group` in each finding and a
  `timelines` block (`connection-start-timeline-v1`). Its `group` references the
  one-based finding index in that report. Group numbers and host aliases are
  report-local, not persistent asset identities. Collector selection resets on
  each new snapshot so an old group selection cannot silently move to a new host.
- Default exports omit endpoint IPs, raw rows, UIDs, source paths and declaration
  IDs/configuration. Uploaded local reports retain their explicit IP opt-in;
  collector reports remain aliased. Time/ports/counts are still sensitive.
  No new raw-row persistence, history table, credentials or external requests.
- Older schema-2 snapshots without timelines still render and prompt a collector
  restart. The private SQLite state schema remains 1 and needs no migration.

The connection/DNS/device findings are unchanged for identical inputs. This
increment does not measure analyst time saved; a human workload study is needed.

## Predeclared live control

`tcp-termination-live-v1` creates harmless TCP exchanges on a **guest-only internal
Docker bridge**, with no published ports. Pinned Python/Zeek images match the
existing lab. Containers drop capabilities, have read-only roots and carry a
per-run ownership label; existing names/networks are refused. Cleanup affects
only resources created by that run. Packet capture is restricted to that bridge
and ports 18001–18006, never the user's real interface.

Before capture the immutable manifest declares **12 attempts each**:

| State | Construction | Expected count per run |
| --- | --- | ---: |
| SF | Bidirectional payload and orderly close | 12 |
| RSTO | Bidirectional payload, originator reset | 12 |
| RSTR | Bidirectional payload, responder reset | 12 |
| S2 | Originator FIN, responder left open until capture ends | 12 |
| S3 | Responder FIN, originator left open until capture ends | 12 |
| REJ | SYN to a deliberately closed local port | 12 |

The workload/script/manifest hashes are recorded before tcpdump starts.
The host also retains a private pre-capture source receipt. CTI, ML and analyst
rules are disabled. No state remapping, threshold tuning or time scaling.
Zeek runs offline with `-C` for the existing guest offload/checksum limitation;
zero capture drops does not prove universal sensor visibility.

Two separately captured runs passed the same contract:

| UTC run | Accepted rows | States | Connection reviews | Restart added | Gzip duplicate files |
| --- | ---: | --- | ---: | ---: | ---: |
| 20261004T205817Z | 72 | 12 of each declared state | 0/6 | 0 | 1 |
| 20261004T210023Z | 72 | 12 of each declared state | 0/6 | 0 | 1 |

Both had zero invalid/skipped metadata and zero reported kernel drops. Offline
findings/timelines equaled the collector snapshots. Timelines retained exactly
72 starts and the same state totals after restart and gzip replay.

Conn-log SHA-256 receipts:

- First: `fee490f099d8eb4adc3a9eefa5a1b8ea7533f724eee93c93abbe5cd3ee6fb952`
- Second: `4ba257a88293258348f5ead7d488aae58a04d78981bcfffb506c8ce779c7c0e8`

These short synthetic live captures validate packet-to-Zeek-to-investigation
plumbing and repeatability. They do **not** evaluate the one-hour/30-minute
review gates, malware recall, false positives, production throughput, RITA parity
or human analyst efficacy. The original/previously inspected experiment inputs
and metrics are not rewritten or presented as untouched evidence.

## Reproduce privately

Use the existing isolated guest setup in [LOCAL_LAB.md](LOCAL_LAB.md).
Copy `scripts/lab/termination_workload.py` and `run_termination_live.sh` into the
guest's `~/threatfusion-lab`, then inside that guest:

```bash
bash ~/threatfusion-lab/run_termination_live.sh
```

Copy its new `results/termination-live-*` directory into a private host directory
outside Git. With the project runtime installed:

```bash
.venv/bin/python scripts/lab/analyze_termination.py --directory /private/path/to/new-run
```

The analyzer rejects a changed manifest, unexpected per-port state/count,
invalid metadata, nonzero/unknown drops, workload errors or inconsistent
collector/offline/restart results. Output files are exclusive (rerun in a new
result directory) and owner-only. Keep PCAPs, logs, reports and collector SQLite
state local; only source, method and aggregate receipts belong in GitHub.

## Bounded sizing check

One constructed local 100,000-record/200-group check retained all starts in
9,400 buckets and produced 1,848,205 bytes of timeline JSON. Building timelines
alone took 2.53 seconds with a traced Python allocation peak of 11,000,850 bytes.
Input allocation, detector/CTI/report phases and total process RSS are excluded.
This is one sizing check, not a production throughput or capacity guarantee.

## Next evidence gates

Predeclare failed-attempt/scan and UDP/DNS development controls before changing
detection. Reserve new independent inputs; the existing IoT-23 captures are
already inspected. Test longer live rotation/resources and make an explicit
active-file latency decision. Run an actual analyst task study before any
usefulness/time-saved claim. Strict-temporal ML evidence remains insufficient,
the trusted original runtime artifact is still absent and promotion is deferred.
