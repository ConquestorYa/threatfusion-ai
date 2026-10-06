# Operational confidence: fault matrix and wall-clock soak

This is the first increment of product-plan gate **P1**. It exercises the real
foreground collector CLI and the local Streamlit app on one Linux host, using
owned synthetic Zeek logs (reserved addresses, `.test` names) and either a
synthetic CTI cache or a private SQLite backup copy of the developer's existing
cache. No packets, destinations or CTI feeds are contacted. Results are
engineering evidence for this host and workload; they are not detection
efficacy, enterprise sizing, a security audit or the user's manual acceptance.

Methods: [`scripts/lab/operational_faults.py`](../scripts/lab/operational_faults.py)
and [`scripts/lab/wallclock_soak.py`](../scripts/lab/wallclock_soak.py). Each
writes `plan.json` plus its SHA-256 into a private 0700 root outside Git before
any outcome, refuses a changed candidate/method/acceptance and never overwrites
receipts. Amendments go into a new root that records the earlier plan/summary
hashes and the reason. Receipts, logs, state and the cache copy stay private.

## Fault matrix `operational-faults-v1`

Each case starts `python -m threatfusion.telemetry_collector` with a one-second
poll in its own state directory. Acceptance was declared before the first run:

| Case | Declared acceptance |
| --- | --- |
| `concurrent_refresh` | Six real 200k-record source replacements while polling: collector alive, never a zero-indicator status, final count within 15 s, 500 rows exactly once |
| `exclusive_lock` | A 12 s exclusive CTI lock (above the 5 s busy timeout) does not stop collection; snapshot stays valid; a later CTI change appears within 15 s |
| `state_readonly` | Read-only state keeps the last snapshot bytes; any exit is nonzero, actionable, traceback-free; after restore (and restart) the new file imports once, no temporary outputs |
| `unreadable_file` | One unreadable completed log is rejected as access with input coverage loss while another imports; restored, it imports exactly once; collector stays alive |
| `unreadable_subdir` | An unreadable dated subdirectory fails before import (no sibling rows), preserved snapshot, actionable exit; restore and resume import every row once |
| `corrupt_state` | A corrupted private collector database is refused at start, not deleted or replaced; the snapshot remains |
| `truncated_gzip` | A truncated archive is rejected as archive with zero rows and coverage loss; a complete replacement imports once |
| `expected_rules_missing` | A removed declaration path stops with an actionable exit and preserved snapshot; restart adds zero duplicates |
| `sigterm` | SIGTERM exits 0 within 15 s with a valid snapshot; restart adds zero records |

### Outcomes, in order (all receipts preserved)

1. **Original root** (`8d93abe` runtime = `35423bc`): 0/9. Every case hit a method
   error: the readiness probe opened the collector database before it existed.
   The same error left that run's nine own collector processes running; they were
   later stopped by PID (only processes started by this experiment).
2. **Amendment 1** (method only): **7/9**. `exclusive_lock` exposed a real
   defect: a CTI lock longer than the SQLite busy timeout stopped the collector
   with “check private state, source limits and optional local files”, although
   the collector is documented to run independently of CTI refresh.
   `unreadable_subdir` behaved correctly (zero sibling rows, actionable exit,
   full recovery) but failed its snapshot-byte check: healthy ticks rewrite
   generated timestamps, so bytes captured *before* installing the fault were not
   a valid baseline. This was diagnosed as a method race, not counted as a pass.
3. **Amendment 2** (CTI-lock repair + capture-after-fault method): 8/9;
   `exclusive_lock` passes. The new unreadable-directory staging rename failed
   because Linux requires write permission on a directory to move it across
   parents (method error).
4. **Amendment 3** (method only): **9/9**. Failed cases now stop their own
   collectors. Its summary field `runtime_changed: false` was a hard-coded method
   value and is wrong for amendments 2–3; later runs compute it from Git.
5. **Amendment 4** (final candidate, adds the indicator-cache memory repair
   below): **9/9**, `runtime_changed_from_baseline_commit: true`, zero orphaned
   processes. Real 200k-record refreshes never exceeded the busy timeout here.

Final-candidate observations: corrupt state is refused without deleting it;
read-only state and unreadable subdirectories stop collection actionably with the
previous snapshot intact and resume exactly once; missing declaration files stop
as documented; SIGTERM exits in 0.26 s with zero duplicate records on restart.

## Repairs made from this evidence

- **CTI busy/locked reads no longer stop collection.** On `SQLITE_BUSY` /
  `SQLITE_LOCKED` the CLI keeps the last *complete* indicator view, scans, sets
  `cti_reload_deferred: true` in status and shows a bilingual dashboard warning;
  the reader retries on the next poll. A first read that is busy never scans as
  an empty cache: the CLI waits (stderr notice) or, with `--once`, exits 1 with
  “the CTI cache is busy”. Other SQLite/IO errors still stop actionably.
- **Indicator cache comparison no longer deep-copies the cache.** The collector
  stored `copy.deepcopy(indicators)` after every recompute. With the 616,308
  active indicators of the developer cache this cost about 430 MiB and 6.8 s per
  recompute (measured in isolation). It now keeps a shared immutable field view
  (~0.4 s to build per tick, no measurable extra RSS) and still detects replaced
  and in-place changed records, including list tags.

Seven regression tests cover the real exclusive lock, the first busy read,
`--once`, non-busy errors, health validation, the dashboard warning and the
field-view cache semantics; six of them fail on the unrepaired `8d93abe` source
(the seventh checks the method fixtures).

## Wall-clock soak `wallclock-soak-v1`

Declared on local commit `d006771` (runtime + app + method fingerprints) before
outcomes: **6 real hours**; every 5 minutes a closed conn log (1,000 rows) and a
closed DNS log (600 rows) appear atomically with current timestamps — 115,200
observations, so the 100k shared record limit must be reached and disclosed.
The collector runs with its default 10 s poll against a private backup copy of
the 196 MiB developer cache (616k active indicators). A local Streamlit server on
an unused loopback port keeps one emulated tab on **Collected connections**,
following both 10 s fragment reruns, plus a fresh session every 15 minutes. At
hour 3 a synthetic indicator for one generated destination is added to the copy.

Declared acceptance: both processes alive at every 10 s sample; collector RSS
≤ 1.5 GiB, web RSS ≤ 2 GiB, state ≤ 512 MiB; snapshot age ≤ 60 s; persistent
view gap ≤ 60 s; every fresh session renders within 60 s; no exception element
or session error; CTI change visible ≤ 60 s; imported rows equal generated rows
with zero rejections; final retained = min(generated, 100k) with matching
capacity disclosure; clean exit; original cache hash unchanged; last-hour versus
second-hour median RSS ≤ 1.25 and fd/thread growth ≤ 16 for each process.

Two declared 4-minute **method smokes** (not soak evidence) preceded it. The
first exposed the deep-copy cost above (collector RSS 1.74 GB with 1,800 rows)
and a shutdown-ordering artifact in the method. The second (after both repairs)
reached collector 1.26 GB / web 310 MB and showed a one-time RSS step after the
CTI reload: repeated in-process reloads plateau near 1.2 GB (old and new
indicator lists briefly coexist; Python keeps the high-water). The growth limit
was **not** changed; a separately labeled diagnostic compares the last hour with
the hour after the CTI change.

Outcome: the first full run was interrupted about 45 minutes in when Claude Code
was restarted (its own children ended; partial receipts and an interruption note
are preserved, no summary). This is not a product outcome. A rerun with the same
declaration and candidate, detached from Claude Code, is **in progress**; no soak
result is claimed until it completes. Two pushes' worth of local test/audit runs
overlap its first minutes and are recorded as operator notes.

## Limits and what remains

- One host, synthetic traffic shape, one sensor; not 72 hours, not enterprise
  rates, not browser rendering cost. Physical disk exhaustion, power loss,
  filesystem corruption beyond the SQLite header and network filesystems are out
  of scope. Corrupt state is refused, not repaired.
- The collector loads every active CTI indicator into memory (~0.65 GiB for
  616k indicators before analysis). An indexed lookup design would lower this; it
  is not implemented.
- Representative permitted traffic, analyst usefulness, detection coverage and
  the user's manual acceptance (P0) remain open.
