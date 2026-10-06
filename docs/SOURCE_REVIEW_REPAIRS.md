# Source review repairs before manual testing

Reviewed baseline: `4b371234b0f43a766fcead85d8005b71099b86de` (2026-10-06).
The nine findings and reproduction receipts remain in the private lab workspace.
Only source, documentation and small reserved synthetic regression tests belong
in Git. No real telemetry, third-party feed rows, credentials or model artifacts
are included. This work repairs correctness and privacy; it does not measure
RITA parity or detection accuracy.

| Finding | Result |
| --- | --- |
| R01 PCAP responses attributed to resolver / counted twice | Use QR direction and reconcile the latest eligible query/reply with identical endpoints, ports, ID, normalized name and type, within 120 seconds. Queries without replies have no response code. Orphan replies and retransmitted queries remain separate observations with diagnostics. |
| R02 Only first DNS IP answer matched | Preserve up to 1,024 source answer entries and all valid unique IPs; one query remains one event. Match evidence carries the particular additional IP; IP counts/context use the whole set. Runtime total answer budget is one million. |
| R03 IP-valued targets exported despite false privacy flags | Aggregate and device reports alias literal IP targets by default. Aggregate JSON adds `unique_targets` and `ip_targets`; `unique_domains` counts domains only. JSON/CSV findings add `target_type`. Explicit local IP export opt-in sets truthful flags. New analyst-history rows alias IP targets. |
| R04 Managed local mode hid endpoint controls | Separate `THREATFUSION_HISTORY_ENABLED=0` from the public/demo profile. Local CTI mode enables endpoint controls while keeping history disabled. Collector host/device identity can be displayed explicitly via a separate generation-bound private mapping; downloads keep aliases. |
| R05 SQLite cleanup exceeded variable limit | Stream/batch old inactive row deletion within SQLite's variable limit and one transaction; preserve active/recent/malformed-date rows. Maintenance failure has its own outcome after source refresh commits. |
| R06 CTI match fanout could exhaust memory | Hard fail above 250,000 match objects or one million lookup operations per matching call; indexed IPv6 prefix lookup avoids scanning every network for every event. Idle collector polls reuse CTI rows until DB/WAL/journal signature changes. Failed analysis preserves published reports and invalidates its cache so committed rows retry. |
| R07 Quick lookup omitted IPv6 networks | Indexed candidate prefix lookup supports all 129 IPv6 prefix lengths. Prefix membership is contextual Review evidence, never an exact Known Threat match by itself. |
| R08 IDNA detail omitted evidence | Detail filtering uses the same domain normalization as matching. |
| R09 AdGuard scalar/deep JSON crashed validation | Return bounded actionable `ValueError` validation errors handled by the UI. Non-finite configured refresh/staleness values are also rejected. |

## Data and migration contracts

- Collector database `user_version=3` rejects accidental use by older versions
  that only understand schemas 1/2. Before upgrading an existing schema, create
  an owner-only `collector.schema1-*.sqlite` or `collector.schema2-*.sqlite`
  backup. Keep these backups private. New installations need no migration.
- Old retained DNS rows/checkpoints are preserved. They cannot recover discarded
  answers without the original logs. `legacy_first_answer_events` and a UI
  warning disclose this. If original logs are still available, collect them in a
  new private state for complete reconstruction; do not delete the old state.
- Reimporting a byte-identical source row in an old/new representation does not
  double the query count or create a fictitious conflict. Coverage reports
  `superseded_representations`; real different source rows with the same
  transaction identity still conflict and are excluded.
- `collector-identities.json` is an ignored 0600 local-only sidecar. Directory,
  file permissions/type/size, mapping fields and selection generation are
  checked before display. Missing/stale mappings fall back to aliases with a
  visible warning. No SQLite read or private mapping download is added to UI.
- Existing saved history/previously exported reports are preserved; these
  fixes cannot retract files already exported. Regenerate reports with this
  version for default target aliases. Aliases do not anonymize domains, times,
  ports or traffic statistics; all telemetry exports remain sensitive.
  New saved-history IP aliases include the run number so different IP targets
  from separate runs cannot be mistaken for a stable shared asset identity.
- Aggregate export opt-in: UI **Include literal IP targets in aggregate
  exports**, or CLI `--include-target-ips` with `--json-output`/`--csv-output`.
  Device export opt-in includes client and literal target addresses; connection
  export retains its separate endpoint opt-in. Aggregate CLI files become 0600
  through atomic replacement; device/connection exports still refuse overwrite.
- Suricata single-question detailed/grouped formats accept `queries` (v3),
  `query` and `rrname` (legacy). Multi-question records fail explicitly. DNS-port
  direction identifies observed clients; ambiguous replies remain unattributed.
  EVE records remain log observations, with no cross-record transaction pairing
  claim. See the [official EVE DNS examples](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html#event-type-dns).
- PCAP import rejects non-Ethernet link types, caps packets/events/pairing work
  and preserves query timestamps. Reply-only observations do not prove a query
  was captured. Encrypted DNS and DNS-over-TCP reconstruction remain outside
  the import contract.

## Verification and next work

Regression coverage uses reserved domains and documentation IP ranges only:
PCAP/PCAPNG query/reply, unanswered/orphan/ID reuse, all-answer order invariance,
modern Suricata, legacy upgrade/reimport/deduplication/restart/gzip, explicit IP
export/private history, local identity UI/stale mapping, match/work budgets,
failed-analysis retry, cache refresh and variable-limit maintenance. Full tests,
Ruff, Bash syntax, diff checks, public source/history audit and original-data
hash checks are required before main publication.

The original fresh-disjoint/strict-temporal limitations, frozen ML identities
and deferred augmented runtime promotion stand. Earlier performance receipts
remain attributed to their frozen source versions. Broad cache/web memory,
wall-clock soak, real permitted traffic efficacy, filesystem corruption,
tunneling controls, SIEM contracts and an analyst pilot still need work.

Local verification: **1,321 tests passed, approximately 91% coverage**, including
45 new regression cases. Ruff, 12 Bash syntax checks and diff validation pass;
all 34 original local data hashes are unchanged. The original cleanup probe now
deletes all 32,767 old rows above SQLite's actual 32,766 variable limit. A real
production-budget synthetic call with 1,000 queries and 1,000 same-host URL IOCs
fails explicitly at the match bound. Whole managed UI and local identity toggle
checks run without exceptions. Private receipts include failed intermediate
test expectations and an external probe import-path error, corrected without
changing acceptance; no failed method result is presented as a runtime defect.

Start manual testing after these repairs: managed Linux open/stop/reopen,
own-key CTI refresh/offline failure, rotate completed conn/DNS logs, compare
local IP identity with input, and inspect/download reports with opt-ins off/on.
No public site is necessary or authorized.
