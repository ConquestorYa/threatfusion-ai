# Automatic Zeek DNS investigation

Status date: 2026-10-05. This increment closes the completed-file DNS ingestion
gap; it does not introduce a DNS tunneling detector or general UDP beaconing.

## Local workflow

Upgrade the Linux installation with the README command after stopping it. In
real CTI mode, run the existing collector command in another terminal:

```bash
threatfusion-ai collect --input-dir /absolute/path/to/zeek/logs
```

Open **Collected connections**, then **Collected DNS observations**. The same
archive root can contain `conn.log` and `dns.log`, rotated variants and gzip
copies. No extra API key is needed for ingestion. CTI comes only from the user's
optional existing cache; feed refresh remains a separate operation. An empty
cache still allows behavior review. This path keeps ML disabled.

The DNS section shows analyzed transaction counts, UDP/TCP counts, exclusions,
client/domain priorities and evidence from existing `dns-device-triage-v1`.
Its Observe filter is independent of the connection review/expected filters.
The existing JSON download includes a separate `dns` block. At most 1,000
prioritized DNS groups are exported, with total/omitted counts; the table renders
at most 500. `dns_review_groups` counts Review/Investigate groups **in that bounded
snapshot**, not all omitted groups. Original connection findings, timelines,
attempts and their export semantics remain unchanged.

DNS aliases (`Device …`) and connection aliases (`Host …`) are independent,
report-local labels. They are not stable asset IDs or an inferred hostname/flow
join. Endpoints can be resolvers/NATs. Queries do not prove connections, downloads,
payload content, malware or execution. Domains, times and CTI remain sensitive
telemetry even when client IPs are omitted. Keep snapshots private.

## Identity and conservative coverage

Zeek's DNS UID identifies the **connection**, while `trans_id` identifies DNS
transactions; one UDP socket or persistent TCP connection can carry multiple
queries. See the [official DNS record definition](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/dns/main.zeek).
The collector uses UID + transaction ID + UTC timestamp, not UID alone.
Different transaction IDs/times survive, and different UIDs at coarse identical
times survive. Identical full-row copies across archives are stored once.
Different full source rows at the same key are excluded from DNS analysis, with
conflicting transaction/excluded record counts. The row fingerprint includes
all columns, including answers, TTLs and endpoints; only its hash is retained
alongside typed event/identity metadata. No raw DNS rows or identities are in
the dashboard/export. Conflicts apply only within retained evidence.

Timestamp precision loss or legitimate differing log representations can cause
conservative conflict exclusions; the key is an engineering reconciliation
contract, not a universal DNS packet identity. Response events with missing
queries/transaction identity and multicast-style records are outside this strict
collector contract. A rejected file contributes no partial import. The existing
manual upload parser remains permissive and unchanged in its supported scope.

Collection requires a query/query type, valid timestamp, bounded UID, transaction
ID 0–65,535, valid source/resolver IPs, ports 1–65,535, TCP/UDP protocol, unique
header fields and complete row width. Missing response code/answers are allowed:
unanswered queries stay observations. The existing DNS parser retains the first
IP answer, not every answer, CNAME/TTL evidence or query/response pairing details.
Do not interpret the typed event as complete DNS response coverage.

Names must identify their log kind; conflicting `#path` headers are rejected.
Completed standard TSV only, final `#close` required; active files wait for
rotation. DoH/DoT contents and JSON logging are not extracted. Never add a close
marker to an actively written log. There is no new packet sensor or listener.

## State migration and bounds

Collector policy is now `closed-zeek-collector-v2`; private SQLite schema is 2.
Schema-1 state is automatically backed up into an owner-only
`collector.schema1-*.sqlite` inside the private state directory before migration.
Old connection rows/hashes/checkpoints/source binding are preserved. Old software
rejects schema 2; it cannot silently discard DNS state. For a deliberate rollback,
stop collection and restore a preserved schema-1 backup to a **separate** private
state location for the same source/limits. The backup is outside active retention;
manage/delete it explicitly under your organization's local data policy.

Directory mode remains 0700, files 0600, one writer and atomic snapshots. Old
v1 JSON snapshots remain readable; restart an updated collector to produce DNS.
The web process reads only the bounded private JSON, not the SQLite database.
Public/demo profiles still hide the collector.

The existing 100,000-record cap and event/ingestion window are **shared** between
connection and DNS evidence. A newer DNS timestamp can advance the shared
watermark and prune older connection rows. Separate state directories are needed
for independently retained archive roots; mixed roots should use aligned sensor
windows. DNS additionally keeps at most 25,000 normalized query names (newest
first). Capacity/name pruning reports coverage loss and disables expected
connection filtering for one ingestion window. Snapshot truncation is disclosed
separately and does not delete its underlying records.

`retained_records` remains the connection count; `retained_dns_records`,
`retained_total_records`, `analyzed_dns_events`, `new_connection_records` and
`new_dns_records` make the kinds explicit. `new_records` is their shared import
count. Rejections/open files remain aggregate per scan. Existing 16 MiB file/
expanded-gzip, 8,192 scan entries, 64 changed-file attempts, 10,000 checkpoints
and 64 MiB snapshot limits remain. See [collector operation](TELEMETRY_COLLECTOR.md).

## Predeclared controls and new live evidence

`dns-collector-v1` wrote immutable external input manifests before product
implementation. Development and reserved identifier sets each contain the same
11 declared operational scenarios: UDP/TCP periodic benign updates, coarse-time
distinct UIDs, exact copies, conflicting transactions, transaction-ID reuse at
different times, ordinary response codes, unanswered queries, missing transaction
ID, future clock and an active file. **11/11 pass in each set**. Both periodic
benign updates enter Review under the unchanged policy; legitimate behavior
still creates review work. The identifier sets are software contracts, not
independent benign/malicious holdouts or malware truth.

Candidate runtime/workload fingerprints were frozen before the new live capture.
An experiment-directory traversal/symlink guard was strengthened afterwards;
the original receipt remains, runtime/workload hashes stayed unchanged, and a
final tooling freeze preceded a second new capture. The reserved contract inputs
were rerun without rewriting them or claiming a new untouched evaluation.

| Recording (UTC filename) | DNS / connection records | UDP / TCP DNS | NOERROR / NXDOMAIN / SERVFAIL / unanswered | DNS reviews | Restart new / gzip duplicates |
| --- | ---: | ---: | ---: | ---: | ---: |
| `dns-collector-live-20261004T222024Z` | 24 / 2 | 12 / 12 | 8 / 6 / 6 / 4 | 0 | 0 / 2 |
| `dns-collector-live-20261004T222416Z` | 24 / 2 | 12 / 12 | 8 / 6 / 6 / 4 | 0 | 0 / 2 |

These are new real packet captures of a short **synthetic** workload: two .test
clients, one reused UDP socket and one persistent TCP connection, an internal
guest-only bridge, no published ports and no real DNS forwarding. Each capture
uses two connection UIDs for all 24 distinct DNS transactions, no rejected/
invalid records and zero reported kernel drops. Offline DNS findings and original
connection findings/timelines/attempts exactly match the collector, including
restart/gzip replay. Packet loss counters do not establish universal visibility.
The UTC filenames are October 4; the Turkey date is October 5.

The pinned image digests are in `run_dns_collector_live.sh`. TCP/UDP port-53
capture is limited to that dedicated bridge; offline Zeek has `--network none`.
`-C` accommodates the documented guest checksum offload issue; it is not a
production capture configuration recommendation. Raw PCAP/logs/SQLite/proofs
remain outside Git, CI and hosting.

Aggregate receipts (SHA-256):

| Receipt | SHA-256 |
| --- | --- |
| Input plan | `65f9ee79194919544a580d5aa2de19aa8b9694eb9245f1f2a082e418afdb2756` |
| Development inputs | `94013b4f02ba9659eaa02ba068f6642608e78afd55a386fa93cee8dc625a841e` |
| Reserved inputs | `52b22e579568acb8893af70d0b45293b396f9707e82ea50bfb73dd9cfe3bfa7e` |
| Original source/tooling freeze | `2285daa2af039d31fa7a219440a258d99d43b3b325fcaa6e39a208fba4a083f5` |
| Final source/tooling freeze | `87569dba3a1b4d17e7152cbd424e078ca486d972b35374724c744e55da06530e` |
| First DNS log | `577b5c117b74e6d54a81a3384b0d3694235feb9453f1a1e0804d6501af7f50ed` |
| First connection log | `959c49eb5a04f04399eb6f53d5785f102b8484a9ce28fb2be30ddeb8eaf1eaad` |
| Second DNS log | `79e4a04d7c437f4c97dd8622c9b3aa7685f9a3ac24e6598edc026b54a78fed9c` |
| Second connection log | `0f8b2fe755d280fef2d61d2cbc9f255b5a629b40c8e5531fd1ea7ef192d886b8` |

Validation: **1,091 project tests passed, 90% coverage**, Ruff/Bash/diff checks
pass. Tests cover state upgrade/backup, preserved original connection outputs,
privacy, CTI reload without traffic and client/answer evidence isolation,
reconciliation, malformed snapshots, bounded exports and bilingual/public UI.
An early runner clock assumption was corrected: a +301-second input becomes
valid after advancing the trusted clock one second. The fixed-clock restart
contract keeps it rejected. The UI fixture now aligns timestamps to its actual
test clock. Prior failed receipts are preserved; no detector gate was weakened.

One constructed 10,000-record collector tick retained all records, exported 1,000
DNS groups and disclosed 9,000 omitted; 5.57 seconds, 47.03 MB traced Python
allocation peak and 716,115 snapshot bytes. This includes import/analysis/report
for one run, excludes preallocated fixture rows/text and total RSS, and is not
production throughput or representative multi-day resource evidence.

## Reproduce locally

From the source checkout and its environment, using an external private root:

```bash
TF_DNS_RUN=$(mktemp -d /tmp/threatfusion-dns-collector.XXXXXX)
python -m scripts.lab.evaluate_dns_collector create --root "$TF_DNS_RUN"
python -m scripts.lab.evaluate_dns_collector evaluate --root "$TF_DNS_RUN" --phase development
python -m scripts.lab.evaluate_dns_collector_live freeze --root "$TF_DNS_RUN"
python -m scripts.lab.evaluate_dns_collector evaluate --root "$TF_DNS_RUN" --phase reserved
```

The runner uses exclusive writes; choose a new `--run-id` for a declared retry.
Create/freeze operate on fresh roots and never overwrite receipts. Paths resolving
into the repository, including traversal and parent symlinks, are refused.

In the existing isolated Linux Docker lab guest, copy `dns_collector_workload.py`
and `run_dns_collector_live.sh` into `~/threatfusion-lab`, then run
`bash ~/threatfusion-lab/run_dns_collector_live.sh`. Existing fixture containers/
network are refused; cleanup removes only resources owned by that run. Copy the
new result directory into the external experiment root, keeping it private, then:

```bash
python -m scripts.lab.evaluate_dns_collector_live live \
  --root "$TF_DNS_RUN" --capture-dir /absolute/private/path/to/new-capture
```

Verification requires matching frozen runtime/workload/tooling hashes and the
pre-capture manifest/script hashes. Old experiments are inspected evidence and
must use their recorded source identity; do not overwrite/relabel them as new.

## Remaining gates

No new independent real benign recording, operational FPR/recall, RITA parity,
human analyst evaluation or production security/throughput claim. DNS tunneling
still needs proper public-suffix aggregation, query-label/type/size evidence,
benign CDN/telemetry controls and new reserved recordings. General UDP sessions
and sparse TCP failure behavior remain separate uncovered scopes. Next operational
increment: [rotating-log/recovery measurements and device DNS investigation
timelines](DNS_INVESTIGATION.md). Representative multi-day operation remains open.
ML artifacts/thresholds/promotion are
unchanged; strict temporal evidence remains insufficient. Hosting stays suspended.
