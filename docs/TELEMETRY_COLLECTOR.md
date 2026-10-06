# Local completed-log collection

The Linux collector reads completed standard TSV Zeek connection and DNS logs from a
user-selected directory. It does not capture packets, install Zeek, access
observed destinations or open a listening service. It is an optional foreground
process, separate from the local web application and CTI feed updater.

## Installed application

The [multi-day engineering protocol](MULTIDAY_COLLECTION.md) qualifies rotating
mixed inputs, bounded retention, own-process resource measurements and restart/
expiry behavior. Accelerated event hours do not establish a wall-clock soak or
enterprise capacity.

Upgrade with the README installation command after stopping the app. Select
real CTI mode, then run in a second terminal:

```bash
threatfusion-ai collect --input-dir /absolute/path/to/zeek/logs
```

Open `threatfusion-ai` and select **Collected connections** in the sidebar.
The English/Turkish view refreshes every ten seconds, warns about stale snapshots,
rejected inputs, empty CTI and capacity loss, and defaults to unexplained reviews.
Expected-activity filtering is reversible. Small JSON reports retain all connection
groups; above 1,000 groups, JSON is a prioritized snapshot with explicit omissions
and a separate verified full JSON.gz download. Summary counts cover every retained
group before filtering. See [capacity and recovery limits](CONNECTION_CAPACITY.md).
CTI conflicts remain visible even for Observe-priority groups.

Ctrl+C stops the collector. Repeat the same command to resume from checkpoints;
it works independently of the web process. `threatfusion-ai stop` stops the web
app, not a collector in another terminal. No boot/login service is installed.
Use `--once` for one scan. The collector uses the installation's existing private
CTI cache without collecting feeds or using API credentials. Cache refresh is
configured separately in Local setup & CTI updates; the next collector scan
reloads the cache. Check that panel for source freshness and upstream failures.
An empty cache still permits behavior analysis. ML is disabled on this path.
If the cache is busy or locked by a refresh/maintenance writer beyond SQLite's
5 s busy timeout, the scan keeps the last complete indicator view, records
`cti_reload_deferred` and the dashboard warns; the next poll retries. A busy
first read waits rather than scanning as an empty cache (`--once` exits 1).
Other CTI read errors still stop the collector. The collector holds every active
indicator in memory: the 616k-indicator developer cache used about 0.86 GiB RSS
at steady state and about 1.2 GiB after a reload in the
[operational protocol](OPERATIONAL_CONFIDENCE.md).

Optional local declarations are reevaluated on every scan:

```bash
threatfusion-ai collect --input-dir /absolute/path/to/zeek/logs \
  --expected-connections /private/path/expected-connections.json
```

The rule path must remain available. Invalid rules stop processing without
printing their contents. See [declaration requirements](EXPECTED_CONNECTIONS.md).
Declarations do not establish software identity or safety.

## Completion and rotation

Candidate names start with `conn.`, `conn_`, `conn-`, `dns.`, `dns_` or `dns-` and end in `.log` or
`.log.gz`; date subdirectories are scanned. Symlink directories are skipped,
including ZeekControl's `current` link. Point at the archive root or the actual
spool directory, using one sensor per state. Never merge different sensors that
may reuse UIDs. Source/state directories must be separate.

Only files ending in standard `#close\t…` are imported. Open logs wait for
closure/rotation; JSON logging is unsupported. Zeek closes rotated files and
ZeekControl can archive/compress them. Configure rotation for the latency you
need; a ten-second polling interval does not make an hourly rotation immediate.
See [Zeek logging](https://docs.zeek.org/en/new-tutorial/frameworks/logging.html)
and [ZeekControl rotation](https://github.com/zeek/zeekctl/blob/master/doc/main.rst).
Active-file incremental tailing remains future work. Do not add a close marker
to a file Zeek is still writing.

Large completed files can first be prepared with `threatfusion-ai prepare-logs`
into private validated shards. Missing DNS query/type remains strict by default;
explicit quarantine preserves raw rows privately and discloses counts in the
dashboard. See [preparation, conservation and coverage limits](LOG_PREPARATION.md).
Preparation does not enlarge the retained analysis window. Rejected, quarantined
or pending prepared input disables expected declarations for one ingestion
window after the cause disappears; original findings remain visible.

## Standalone and limits

For a source checkout, use its environment:

```bash
python -m threatfusion.telemetry_collector \
  --input-dir /absolute/path/to/zeek/logs \
  --state-dir /absolute/private/path/collector \
  --db /absolute/private/path/threatfusion.sqlite
```

The installed Python package also exposes `threatfusion-collect`. Omit `--db`
for behavior only. For a standalone local UI, set
`THREATFUSION_COLLECTOR_STATE_DIR` to that state directory, use the CTI-only
profile and bind Streamlit to `127.0.0.1`. Public profiles ignore this setting
and hide the page. The managed loopback profile uses its installation's state,
even though its session/history privacy flag is enabled. Demo mode has no page.

| Limit | Default / bound |
| --- | --- |
| Poll | 10 seconds; configurable 1–3,600 |
| Evidence window | 24 hours; configurable 1–168 hours |
| Records | 100,000 shared connection/DNS maximum; `--max-records` may lower it |
| DNS query names / exported groups | 25,000 normalized names / first 1,000 prioritized groups; omitted count disclosed |
| Connection destination diversity | Collector IP analysis is separate from DNS-name bounds; shared 100k retained-record limit remains |
| File / expanded gzip | 16 MiB each |
| Scan | 8,192 directory entries; up to 64 changed-file attempts per tick |
| Checkpoint ledger | Up to 10,000 paths/hashes; missing paths expire after seven days |
| Snapshot | 64 MiB / 1,000 connection groups; table shows first 500 filtered groups; JSON omissions disclosed |
| Full connection export | Private JSON.gz contains every retained connection group; 256 MiB expanded / 64 MiB compressed; other section bounds remain |

The full-connection export remains complete within retained evidence; DNS exports
are bounded separately as above. The watermark/window is shared across log kinds.

Records expire relative to the latest observed event **and** their ingestion
time. Historical offline logs can therefore be examined for one ingestion
window. Unchanged files still present in the source retain checkpoints; expired
evidence does not reappear on the next scan. Deleted/renamed files outside ledger
retention or more than 10,000 paths are outside permanent duplicate guarantees.
Directory scan overflow or unreadable subdirectories fail before import; use a
smaller readable archive root. An unreadable source never becomes an empty clean
snapshot; the previous snapshot remains available and grows stale.
A persisted rotating cursor prevents rejected/open files starving later files.

Capacity pruning is reported as coverage loss. It disables expected-activity
declarations for an ingestion window, so missing volume cannot create an
expected classification. Original findings remain. UID conflict detection is
limited to retained evidence. Invalid metadata/future clocks, links/special
files, corrupt/oversized archives and changing files are rejected. Rejected
inputs are retried; a zero-rejection scan is not proof of complete capture.

## State and privacy

State is owned by the current user: directory 0700, files 0600, a single-writer
lock, private SQLite typed records/checkpoints and atomic JSON snapshots.
Source and retention settings are bound to this state; select a fresh separate
state directory for another sensor or changed limits. A crash after checkpoint
commit regenerates reports on restart without counting evidence again.

The dashboard reads the snapshot, never the raw collector database. Endpoints
use report-local aliases; raw UIDs, input paths and declaration IDs/configuration
are not exported. Aliases are not anonymization: timing, port/byte evidence and
CTI remain sensitive. Keep the entire state, original logs and exports outside
GitHub, CI, public hosting and shared directories. No developer data or keys are
bundled. The collector makes no compromise, download-content or analyst-time
claim. Independent checks are recorded in [network evaluation](NETWORK_EVALUATION.md).

## Connection investigation

The local collected view now offers bounded connection-start timelines, states
and known/unknown bytes for selected groups. Reports extend schema 2 additively;
old snapshots still render. Current snapshots retain selections while ordered
group mappings match; mapping changes reset the selected report-local group.
See [workflow, bounds and live controls](CONNECTION_INVESTIGATION.md). No SQLite
migration, raw-row web access, external requests or public listener is added.

## TCP attempt review

Snapshots also include a separate bounded S0/REJ failure-diversity/retry queue
and Attempt review patterns metric. Original connection reviews retain their
meaning; expected filters do not hide attempt patterns. Old snapshots are still
readable; that increment retained state schema 1 and added no raw DB web access. See
[TCP attempt workflow and limits](TCP_ATTEMPT_REVIEW.md).

## Automatic DNS collection (current policy v2)

Completed TCP/UDP `dns.log` files now enter an independent client/domain queue
under **Collected DNS observations** on the same page. Identity uses connection
UID + transaction ID + timestamp, with exact-copy dedup and explicit conflict
exclusions. CTI/behavior policy is unchanged; there is no hostname/flow join or
DNS tunneling claim. Current private state upgrades to schema 3 after an owner-only
schema-1/2 backup; the earlier TCP-attempt increment required no migration itself.
Old v1 snapshots stay readable. See [identity, migration, live evidence and
DNS limits](DNS_COLLECTION.md). No API keys, sensor or new listener are added.

Current correctness/privacy repairs retain every bounded valid DNS answer IP,
disclose legacy first-answer coverage and enable an explicit local endpoint
view through a private generation-bound mapping. Collector downloads keep
aliases. CTI records are reused between polls until cache files change; failed
analysis preserves the published snapshot and retries committed evidence.
See [repair contracts](SOURCE_REVIEW_REPAIRS.md).

## DNS investigation and operational status

Select a device/domain for bounded UTC query/response charts. Current snapshots
also expose scan budget/categorized rejection metadata and reuse unchanged
analysis while reevaluating declaration expiry. See
[DNS investigation, rotation/recovery protocol and resource evidence](DNS_INVESTIGATION.md).
Scan timing excludes report publication; remaining candidates are not a count of
ready files. Active logs still wait for closure.
