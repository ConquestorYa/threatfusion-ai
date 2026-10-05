# Private preparation of completed Zeek logs

Large completed standard TSV `conn.log` / `dns.log` files can now be prepared
locally into bounded, validated shards. This addresses the collector's 16 MiB
per-file limit; its shared 100,000-record analysis window remains unchanged.
The local web interface remains the analyst workspace.

## Installed Linux application

Upgrade with the README installation command after stopping the app. Choose
an existing private directory **outside every Git checkout**. Each output
bundle must be new; existing directories/files are never replaced.

```bash
mkdir -m 700 -p "$HOME/threatfusion-prepared"
threatfusion-ai prepare-logs --input /absolute/private/conn.log \
  --output-dir "$HOME/threatfusion-prepared/connections"
threatfusion-ai prepare-logs --input /absolute/private/dns.log \
  --output-dir "$HOME/threatfusion-prepared/dns"
threatfusion-ai collect --input-dir "$HOME/threatfusion-prepared"
```

Open `threatfusion-ai`, select real CTI mode, and use **Collected connections**.
The collector must run separately; Ctrl+C stops it and repeating its command
resumes its checkpoints. Preparation does not need keys, refresh feeds, capture
packets or contact observed destinations. Collection uses your existing local
CTI cache, or behavior only when that cache is empty; ML remains disabled here.

For a checkout, `python -m threatfusion.log_preparation` has the same preparation
options; the installed package also exposes `threatfusion-prepare-logs`.

## Explicit incomplete-DNS handling

The default rejects a whole source containing missing query identity or both
missing named/numeric query type. If you deliberately accept incomplete coverage,
use a new output bundle and opt in:

```bash
threatfusion-ai prepare-logs --input /absolute/private/dns.log \
  --output-dir "$HOME/threatfusion-prepared/dns-with-quarantine" \
  --quarantine-incomplete-dns
```

Such rows are preserved in private `quarantine.jsonl` with their original raw
bytes, source line, reason and integrity hash. Nothing invents a domain/type for
analysis. All other identity/metadata checks still apply; structural or unrelated
metadata errors abort preparation. If query and type are both missing, the row
is counted once under missing query. Quarantine is a coverage limitation, not
an assertion that those rows were harmless.

The dashboard/export disclose source, eligible, quarantined and pending counts.
Only those aggregates enter the report; raw quarantine, source names and integrity
digests stay in the private bundle. Bundle counts include copies and are source
accounting, not unique retained events. Manifests are local operator accounting,
not signed proof of capture completeness. Missing, altered or nonprivate bundle
files cannot silently import. Invalid inventory aborts the scan before import;
the previous snapshot becomes stale. Content mismatches report rejection/pending.

Rejected, quarantined or pending prepared input disables expected-activity
declarations. After the cause disappears, that guard persists for one ingestion
window and survives restart. Capacity loss has its existing separate guard.
Original findings remain; an incomplete volume cannot become declared expected.

## Work and privacy bounds

| Preparation limit | Bound |
| --- | --- |
| Raw input / expanded gzip | 256 MiB each |
| Source rows / line / headers | 500,000 / 256 KiB / 256 KiB |
| One shard | 25,000 rows, 8 MiB, 4 million cells |
| Bundle | At most 64 shards |
| Raw quarantine | 64 MiB |

Only closed standard TSV logs are supported. Active logs, changing sources,
links/special files, bad UTF-8/CRC, unsupported metadata and exhausted budgets
publish no prefix. Shards retain original rows, timestamps and UIDs with repeated
headers/close marker. Staging directories are ignored by the collector; Linux
atomic no-replace publication protects a concurrently created destination. A
process killed during preparation can leave its private staging directory for
manual inspection/removal; it cannot become an imported partial bundle.

Directories/files are 0700/0600. The original source is read only. Never commit,
upload to CI, share or host the source, manifest, quarantine or collector state.
Data-provider attribution/redistribution constraints still apply.

**All eligible source rows imported** and **all rows retained for analysis** are
different. The collector retains at most 100k mixed records and 25k DNS names,
within its event/ingestion window; older evidence can be pruned during import.
The 64 MiB snapshot and 1,000 exported DNS groups remain separate bounds.
The collector now analyzes connection IP diversity independently of the DNS
25k-name bound. Above 1,000 connection groups, a bounded snapshot discloses
omissions and a separate private gzip retains every connection group in retained
evidence (256 MiB expanded / 64 MiB compressed budgets). Upload/legacy bounds
remain unchanged. See [capacity contracts and recovery](CONNECTION_CAPACITY.md).
This feature is bounded preparation, not active tailing or unlimited ingestion.

## Known-source regression protocol

This section records the original preparation experiment and its failures.
The later separately frozen [capacity replay](CONNECTION_CAPACITY.md) completes
IoT-3 with the default 100k window, pruning 56,462 records explicitly; none of
these original receipts were replaced or relabeled.

`bounded-log-preparation-v1` seals main `e6da57b`, unchanged source hashes and
contracts before implementation. The verifier seals candidate runtime/method/
tests before replay. It checks raw row conservation including every quarantine
row, independently calculates retained payloads, reconciles original findings,
timelines/DNS, and repeats after restart with gzip copies. Windows and known
IoT-8 findings are compared with their original full baseline.

The first strict IoT-3 DNS failure remains preserved. A separate amended replay
explicitly opts in to existing quarantine for Linux and IoT-3; runtime policies
do not change. Its two predeclared IoT-3 arms use default 100k and an explicit
20k window. The next default unique-target failure remains preserved; a further
method amendment records that existing bound as an exclusion and proceeds to
the already declared 20k arm. No runtime fix or threshold tuning follows.
Any default analysis/snapshot failure remains excluded, never relabeled as
full-retention success. Local plans, frozen hashes and all receipts stay outside
Git. With those private inputs/plans, reproduce using:

```bash
python -m scripts.lab.verify_log_preparation \
  --root /absolute/private/new-experiment \
  --baseline-root /absolute/private/independent-replay-v1
```

These are previously inspected engineering inputs. They do not establish new
malicious recall, false-positive rate, RITA parity, human effectiveness or
enterprise throughput/security. Reserved independent sources remain untouched;
detector/ML thresholds and deferred runtime promotion remain unchanged.

The final replay additionally corrects the verifier's equal-timestamp tie order
to SQL's timestamp descending/hash ascending, with a dedicated control; previous
successful receipts remain intact. All candidate/runtime/source hashes are
checked again after evaluation.

| Known recording | Source / eligible / quarantine | Operational result |
| --- | --- | --- |
| CTU-Normal-20 | 33,981 mixed / 33,981 / 0 | Two shards; full retention, original findings/timelines/DNS unchanged |
| CTU-Normal-21 | 19,409 mixed / 19,360 / 49 | Two shards; 8 missing-query + 41 missing-type rows preserved; full eligible retention, incomplete-input guard |
| IoT-23 3-1 | 156,468 mixed / 156,462 / 6 | Eight shards; default 100k analysis excluded by 25k unique-target bound; separate 20k arm works with 136,462 pruned and explicit coverage loss |
| IoT-23 8-1 | 10,403 connections / 10,403 / 0 | One shard; full retention and original evidence unchanged; already inspected source |

Every source data row is byte-conserved in a shard or raw quarantine. Successful
arms have zero rejected/pending files and zero new records after restart; gzip
copies add 2/2/8/1 duplicate files respectively. Original TCP/DNS/attempt reports
and timelines match offline calculation **within the retained window**. The
limited IoT-3 window yields two attempt reviews, not a full-source malware success
claim; default analysis remains failed. Linux yields 11 DNS reviews within its
eligible observations, not a false-positive estimate. No thresholds were tuned.
Final local validation: **1,233 tests / approximately 91% coverage**, including
30 preparation/coverage/verifier controls; Ruff and Bash/diff checks pass.

The source attributions and original failures are retained in
[independent replay](INDEPENDENT_REPLAY.md). See [collector setup and limits](TELEMETRY_COLLECTOR.md).
