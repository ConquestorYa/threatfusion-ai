# Operational confidence: fault matrix and wall-clock soak

This is the first increment of product-plan gate **P1**. It exercises the real
foreground collector CLI and the local Streamlit app on one Linux host, using
owned synthetic Zeek logs (reserved addresses, `.test` names) and either a
synthetic CTI cache or a private SQLite backup copy of the developer's existing
cache. No packets, destinations or CTI feeds are contacted. Results are
engineering evidence for this host and workload; they are not detection
efficacy, enterprise sizing, a security audit or the user's manual acceptance.

Methods: [`scripts/lab/operational_faults.py`](../../scripts/lab/operational_faults.py)
and [`scripts/lab/wallclock_soak.py`](../../scripts/lab/wallclock_soak.py). Each
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

The first full run was interrupted about 45 minutes in when Claude Code was
restarted (its own children ended; partial receipts and an interruption note are
preserved, no summary). This is not a product outcome.

**Outcome of the detached rerun (same plan `f9a8da85…`, summary `6f7d10e8…`):
15 of 16 declared checks passed; `all_passed` is false.** The failing check is
the declared RSS growth limit: collector last-hour median / second-hour median
= **1.32** (limit 1.25); web 1.11. Every other check passed over 21,600 s:

| Measure | Result | Declared limit |
| --- | ---: | ---: |
| Collector RSS max | 1,253 MiB | 1.5 GiB |
| Web RSS max | 364 MiB | 2 GiB |
| State max | 74 MiB | 512 MiB |
| Snapshot age max | 18.9 s | 60 s |
| Persistent view gap max (2,162 reruns) | 10.1 s | 60 s |
| Fresh sessions rendered / slowest | 24 of 24 / 2.1 s | all / 60 s |
| CTI change visible | 19.9 s | 60 s |
| Generated = imported, rejected files | 115,200 = 115,200, 0 | exact, 0 |
| Final retained / capacity disclosed | 100,000 / yes | 100k / yes |
| fd / thread growth (collector, web) | −1, 0 / 0, 0 | ≤ 16 |
| Exceptions, session errors, clean exit, cache hash | 0, none, yes, unchanged | — |

Hourly collector RSS medians: 888, 921, 939, **1,227**, 1,219, 1,217 MiB. The
increase is a single ~290 MiB step at the hour-3 CTI reload, followed by a flat
or slightly falling level while retained rows grew to the 100k cap. The labeled
diagnostic declared before this run (last hour / hour after the CTI change) is
**1.00**. This matches the method-smoke observation: old and new indicator lists
coexist during reload and the process keeps that high-water. The declared check
still fails and is reported as failed; it is not reinterpreted as a pass.

Product interpretation: no progressive leak was observed in six hours, but one
CTI reload permanently costs ~290 MiB of collector RSS with the 616k cache, and
only one reload occurred. Next P1 work: (1) reduce the reload high-water (build
the new view without holding both lists, or an indexed lookup instead of a full
in-memory list) and (2) declare a new soak root with several reloads to show the
level plateaus, both measured on a new candidate. Local test/audit runs
overlapping the first hour are recorded as operator notes.

## Soak reruns on the memory repair (`7957395`)

**Rerun-2** (same protocol and acceptance) was interrupted after ~2 h 20 min by
a host shutdown (laptop closed). No summary and no verdict; receipts kept.

**Rerun-3 (plan `5093d989…`, summary `ebfe8b42…`): 16 of 16 declared checks
passed; `all_passed` is true.** Same workload, limits and growth rule as the
failed run; runtime identical to `7957395` (declared at `a5d6775`, docs/tests
only). Operator notes record short overlapping test runs, screenshot captures
and the user's app use; the host stayed awake under a sleep inhibitor.

| Measure | Rerun-1 (failed) | Rerun-3 | Declared limit |
| --- | ---: | ---: | ---: |
| Collector RSS max | 1,253 MiB | **684 MiB** | 1.5 GiB |
| Collector last-hour / second-hour median RSS | 1.32 | **1.11** | ≤ 1.25 |
| Web RSS max / growth | 364 MiB / 1.11 | 361 MiB / 1.09 | 2 GiB / ≤ 1.25 |
| State max | 74 MiB | 74 MiB | 512 MiB |
| Snapshot age max | 18.9 s | 20.5 s | 60 s |
| Persistent view gap max (reruns) | 10.1 s (2,162) | 10.2 s (2,162) | 60 s |
| Fresh sessions / slowest | 24 of 24 / 2.1 s | 24 of 24 / 2.4 s | all / 60 s |
| CTI change visible | 19.9 s | 19.9 s | 60 s |
| Generated = imported, rejected | 115,200 = 115,200, 0 | 115,200 = 115,200, 0 | exact, 0 |
| Final retained / capacity disclosed | 100,000 / yes | 100,000 / yes | 100k / yes |
| fd / thread growth (collector, web) | −1, 0 / 0, 0 | −1, 0 / 0, 0 | ≤ 16 |

Hourly collector RSS medians: 514, 618, 623, 668, 672, 684 MiB (previously 888,
921, 939, 1,227, 1,219, 1,217). The CTI reload step is now small: the declared
post-reload diagnostic is 1.02. The rise tracks retained rows growing to the
100k cap. P1's wall-clock gate is met for this workload on this host.

## Security review (P1, 2026-10-07)

A source review of the local attack surface covered HTML/Markdown rendering of
log-derived values, CSV export formula injection, CTI HTTP fetching (redirects,
size/decompression bounds, error text), credential storage, SQL construction,
upload parsing bounds, installer integrity/archive extraction and model loading.
Those areas were found consistent with their stated safeguards. Two defects
were fixed:

- **DNS rebinding to the loopback workspace (medium).** Streamlit accepted any
  `Host` and treated a matching `Origin` as same-origin, so a web page could
  rebind its own name to `127.0.0.1` and drive the local session (read collected
  telemetry, change settings). Outside public mode the app now renders nothing
  unless `Host` is `127.0.0.1`, `localhost` or `::1`, or a name the operator lists
  in `THREATFUSION_ALLOWED_HOSTS`. Verified with a raw Streamlit websocket using a
  pre-connected loopback socket: unpatched `main` rendered the workspace for
  `Host: rebind.test`; the repaired source shows only the refusal for
  `rebind.test`/`attacker.example` and renders normally for `127.0.0.1`/`localhost`.
- **ThreatFox API key on redirect (low).** The recent-IOC API request (used by a
  developer script) followed redirects with the `Auth-Key` header; redirects are
  now refused like every other feed request.

Known limitation, not changed: there is no app login. Another local OS account
on the same machine can reach the loopback port; the product assumes a
single-user workstation or sensor host.

## Security review, round 2 (P1, 2026-10-09)

Focused on surfaces added after round 1: bundled-font static serving, the theme
switch script, the background CTI refresh thread, widget callbacks and the
local control socket. Checked on a disposable real Streamlit server:

- **Widget callbacks under a foreign Host.** Streamlit runs callbacks before the
  script body, i.e. before the Host guard. A session opened as `Host:
  rebind.test` replayed the real widget ids of *Update CTI now*, *Operating
  mode* and *Stop local application* taken from a loopback session: it saw only
  the refusal message; no refresh started, the mode did not change and the app
  kept running. Streamlit ignores callbacks for widgets never rendered in that
  session. No change needed.
- **Static serving.** `/app/static/` is served without the Host guard. Fonts and
  their README are returned (public data, `nosniff`); `..`, `%2e%2e` and `%2f`
  traversal attempts return 400 and directory listing returns 404. A new test
  keeps `static/` limited to font assets and their license/readme files.
- **Theme switch script.** A fixed template rendered through `st.iframe`; the
  only variable is a theme name validated against `("Dark", "Light")` and
  JSON-encoded. **Background refresh.** Keys stay in process memory; status
  files store only safe aggregates (source, status, counts). **Control socket.**
  Unix socket inside the 0700 installation, mode 0600, fixed two-command
  protocol; no TCP listener.

Known low-severity limitations, not changed: no app login (single-user host
assumption, as in round 1); a rebinding page can still reach Streamlit's
health and upload endpoints, which are XSRF-protected and whose uploads are
never processed for a refused session (bounded by the 100 MB upload limit).

## Limits and what remains

- One host, synthetic traffic shape, one sensor; not 72 hours, not enterprise
  rates, not browser rendering cost. Physical disk exhaustion, power loss,
  filesystem corruption beyond the SQLite header and network filesystems are out
  of scope. Corrupt state is refused, not repaired.
- The collector loads every active CTI indicator into memory (about 0.5–0.7 GiB
  for ~616k indicators after the slots/streaming repair). An indexed lookup
  design would lower this further; it is not implemented.
- Representative permitted traffic, analyst usefulness and detection coverage
  remain open (P2). Manual acceptance (P0) passed on 2026-10-09.
