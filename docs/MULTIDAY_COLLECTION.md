# Multi-day collection and process resource protocol

This gate exercises **72 accelerated event hours**, not a 72-hour wall-clock
soak. Synthetic completed Zeek logs rotate hourly, using only reserved IPs and
`.test` names. No traffic is transmitted and no destinations or live CTI feeds
are queried. It measures collection/retention/recovery, not malicious recall,
false-positive rate, RITA parity or analyst effectiveness.

## Contracts declared before outcomes

`multiday-collector-v1` freezes baseline `36b1823`, all 83 runtime-module hashes,
and permits no runtime changes. Method/tests and the complete 144 immutable
source files are sealed before the first collector scan. All original source,
cache, model and prior evaluation files remain outside this experiment.

- Each event hour adds 3,200 TCP connections and 1,800 TCP/UDP DNS transactions:
  360,000 base observations over 72 hours. Twelve reserved clients, a 24-hour
  destination cycle and 120 synthetic DNS names exercise mixed grouping.
- The existing 24-hour ingestion/event window and 100k shared capacity apply.
  An independent hash/timestamp/ingestion/capacity model reconciles SQL payloads
  on every ordinary and idle scan. Parsing is shared with production; the
  retention oracle is independent, not an independent Zeek parser.
- Full retained findings/timelines/attempt/DNS exports match offline calculation
  at event hours 0, 23, 24, 35, 36, 47, 48 and 71. Aliases, omission counts and
  original CTI evidence remain; no detector or threshold is tuned.
- Hour 36 switches a synthetic IP indicator. New evidence must invalidate caches;
  ordinary idle scans reuse analysis and the private archive.
- After hours 24 and 48, only the owned idle worker is SIGKILLed. The previous
  snapshot survives and restart adds zero records/preserves selections. An open
  log stays deferred across restart; closing it imports 60 rows exactly once.
  Renaming and a gzip copy add two duplicate files, no new observations.
- After eight more event days, unchanged source files cannot resurrect expired
  evidence. After removing only generated input copies and eight further days,
  private record/file/path ledgers and intact managed archives must be empty.
- Linux link/FIFO source controls reject input without reading/exporting
  unrelated private contents. These controls supplement existing integrity,
  permissions, budget, concurrent-file and archive-recovery tests; they do not
  establish a comprehensive security audit or power-loss durability.

## Resource scope and acceptance

Fixture generation and offline/oracle verification run in the **parent**. A
separate long-lived collector worker supplies OS process RSS high-water marks;
the parent also samples its RSS and private state file sizes every 50 ms. Worker
protocol/import overhead is included. Parent memory, input files and evaluator
receipts are excluded from collector/state measurements. File sizes are logical
bytes, not physical allocated disk blocks. Sampling may miss transient disk/RSS
peaks; RSS also has the worker's OS high-water measurement.

Predeclared engineering acceptance for this one workload/machine:

| Measurement | Acceptance |
| --- | --- |
| Collector RSS high-water | At most 1.5 GiB |
| Sampled collector state | At most 256 MiB |
| Maximum ordinary hour scan | At most 30 seconds |
| Warm idle median / p95 | At most 1 / 3 seconds |
| Last worker segment median idle RSS / previous | At most 1.25 |
| Last event day maximum state / previous full day | At most 1.25 |

These are experiment qualification limits, not configurable runtime budgets or
enterprise guarantees. Threshold failures remain in the receipts and summary;
they do not justify changing acceptance after seeing outcomes. A new scope or
product repair requires a separately declared experiment preserving the first.

## Reproduce with a private predeclared root

Use a source checkout and its development environment. Create the root outside
any Git checkout; keep it 0700. Before any source generation or outcomes, write
`plan.json` and its SHA-256 receipt. The required declaration fields are:

```python
from pathlib import Path
import hashlib, json, subprocess
from scripts.lab.measure_multiday import fingerprints

root = Path('/absolute/private/new-multiday-run')
root.mkdir(mode=0o700)
plan = {
    'protocol': 'multiday-collector-v1',
    'baseline_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'baseline_runtime': fingerprints()['runtime'],
    'permitted_runtime_changes': [],
    'event_start': '2026-10-01T00:00:00+00:00',
    'hours': 72, 'connections_per_hour': 3200, 'dns_per_hour': 1800,
    'record_limit': 100000, 'window_seconds': 86400, 'idle_seconds': 1,
    'checkpoint_hours': [0, 23, 24, 35, 36, 47, 48, 71],
    'kill_after_hours': [24, 48], 'cti_change_hour': 36,
    'engineering_acceptance': {
        'worker_peak_sampled_rss_bytes': 1610612736,
        'worker_peak_state_bytes': 268435456,
        'hour_tick_max_seconds': 30,
        'warm_idle_p95_max_seconds': 3, 'warm_idle_median_max_seconds': 1,
        'last_segment_idle_rss_vs_previous_max_ratio': 1.25,
        'state_last_day_vs_first_full_window_max_ratio': 1.25,
    },
}
raw = json.dumps(plan, indent=2) + '\n'
for name, value in [('plan.json', raw),
                    ('plan.sha256', hashlib.sha256(raw.encode()).hexdigest() + '\n')]:
    with (root / name).open('x') as file:
        file.write(value)
    (root / name).chmod(0o600)
```

Then run:

```bash
python -m scripts.lab.measure_multiday --root /absolute/private/new-multiday-run
```

The method creates immutable source/candidate freezes, per-hour checkpoints,
private stderr, scan/resource receipts and a final summary. It refuses an altered
declaration/runtime and does not overwrite experiment receipts. Worker deadlines
and own-child cleanup prevent abandoned processes. Keep every first failure;
declare an amendment into a new root before rerunning. Do not send any generated
logs, snapshots, gzip archives, SQLite state or receipts to GitHub or CI. CI runs
small synthetic contract tests, not this private workload.

The previous capacity CI run `37364427665` was cancelled while queued during
the GitHub Actions incident. Attempt 2 subsequently passed all six jobs on exact
commit `36b1823`; its original local receipts remain intact. Hosting stayed
user-suspended, previews off, with no new deploy.

The first full 72-hour accelerated run passed all functional and predeclared
engineering checks. A separate deterministic monitor probe exposed a
temporary-file disappearance between `is_file()` and `stat()`; its receipt and
the first successful run/frozen method remain intact. A method-only amendment
uses one non-following stat per entry, skips vanished stages and rechecks the
declaration/candidate/source bytes at completion. It adds four controls and
repeats the same immutable sources and acceptance into a new private root.
No fixture, runtime, detector/ML or acceptance tuning follows these outcomes.

## Real bounded SQLite exhaustion

A separately declared `sqlite-page-budget-v1` uses two isolated synthetic states:
3 or 1,001 initial connections, followed by 1,200 new connections. Setting only
that owned connection's `max_page_count` to its current allocated pages provokes
an actual `SQLITE_FULL`. The failed source file's rows/checkpoint roll back
together; the original record count and database integrity remain. Published
snapshot and referenced full gzip remain byte-identical. Restoring the test
budget imports all 1,200 rows exactly once; restart adds none and full retained
exports reconcile. No host disk is filled and no user/cache database is opened.
Both controls pass alongside existing actionable CLI error tests. This tests
SQLite page exhaustion, not every physical filesystem/IO/corruption failure.

## Measured outcome (2026-10-06)

Both original and method-amended 72-event-hour runs pass **every predeclared
functional and engineering acceptance check**. All 144 fixture hashes are
identical across runs. Each run reconciles all 144 ordinary/idle hour scans,
eight full-export checkpoints and both interruption/late-close/duplicate cases.
The final hour retains 100k mixed observations, with capacity loss disclosed;
its full export has 63,981 connection groups versus 1,000 snapshot groups.
This is full retained export, not full 360,120-source-record retention.

| Measurement | Original | Method-amended |
| --- | --- | --- |
| Worker OS RSS high-water | 648.7 MiB | 648.5 MiB |
| Peak sampled state logical bytes | 131.7 MiB | 131.7 MiB |
| Maximum ordinary hour scan | 7.473 s | 7.181 s |
| Warm idle median / p95 | 0.322 / 0.379 s | 0.304 / 0.347 s |
| Last segment median idle RSS ratio | 1.0041 | 1.0030 |
| Last day maximum state ratio | 1.0031 | 1.0031 |

At declared expiry/cleanup, records/files/paths are all zero, managed archives
are removed and logical state is 60,843 bytes. Empty ledgers do not imply secure
erasure of physical media. Checkpoints only guarantee deduplication within their
documented lifecycle, not unlimited history. Two real SQLite-full cases also
pass. All **83 runtime modules** and **34 original local data files** remain
byte-identical. Original successful receipts, monitor failure probe and frozen
method/test copies remain privately available. No product policy or ML promotion.

Final validation: **1,276 local tests / approximately 91% coverage**, with twelve
new multi-day and real SQLite-full controls. Ruff, Bash/diff checks and the public
tree/history audit pass. The first full-suite run's two socket permission denials
remain recorded; the authorized loopback/Unix-socket run passes the entire suite.

Resources reflect this synthetic workload and two indicators on one local host;
they do not include the web process, a large real CTI cache, input archives or
parent evaluator. The method repair qualifies stable measurement, not a measured
product speedup. See [collector bounds](TELEMETRY_COLLECTOR.md) and
[diverse-target full export](CONNECTION_CAPACITY.md).

## Remaining gates

Accelerated event time cannot expose every long-running wall-clock resource,
network/filesystem or operational failure. A real bounded wall-clock soak,
broader filesystem/database failure recovery, representative permitted site
traffic and security review remain. Independent timing/sparse/tunneling efficacy,
SIEM contracts and a human analyst pilot follow. Frozen ML identities and
fresh-disjoint/strict-temporal/promotion decisions remain unchanged. No public site.
