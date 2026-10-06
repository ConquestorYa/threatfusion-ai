# Diverse connections and bounded local reports

The completed-log **collector** analyzes up to 100,000 retained mixed records
without applying the DNS 25,000-name bound to connection destination IPs. Global
UID/conflict handling, IP CTI, connection detectors, timelines and attempt review
are unchanged. IP targets do not receive invented DNS/domain ML assessments.
DNS names remain bounded; upload/legacy connection analysis still uses its
existing 25,000-target bound. This change is scoped to collection.

## Local workflow

Use the existing installed commands with completed logs or a privately prepared
bundle. No new API key, database migration or command is required:

```bash
threatfusion-ai collect --input-dir /absolute/private/completed-logs --once
threatfusion-ai
```

Open the collected-telemetry view in the local dashboard. For at most 1,000
connection groups, the JSON snapshot contains every retained connection group.
For larger reports:

- The snapshot contains 1,000 groups, prioritizing CTI, then original reviews,
  then unexplained groups. Original order is preserved within the selection.
- Counts above the filters cover **all retained groups**. Exact omitted-group,
  review and CTI counts are disclosed. Filtering cannot search omitted groups.
- Each visible row has a `Full report group` reference. Local selections and
  timeline references use the visible numbering; the full archive uses original
  numbering. A changed mapping resets stale selections.
- The JSON button explicitly downloads the bounded snapshot. The separate
  **full JSON.gz** button downloads every connection group in retained evidence,
  including original findings, CTI, expected context and existing bounded
  timeline/attempt/DNS sections. It does not contain every raw source record.

The archive represents its displayed generation time. Heartbeats may be newer:
idle scans reuse the archive, while CTI, coverage, retention or declaration
activation/expiry/completion changes rebuild it. Downloads verify the referenced
generation on demand. If it has been replaced or altered, refresh the dashboard
instead of receiving a different or unverified report.

## Privacy, publication and recovery

The private collector state holds two alternating managed archives:
`connections.full-a.json.gz` and `connections.full-b.json.gz`. The writer streams
JSON into a private temporary gzip, synchronizes it, atomically publishes it,
then publishes the snapshot pointer. Exact digest ownership protects unrelated
or edited files from replacement. Interrupted ownership finalization accepts
only the registered old/new digests. Previous published evidence remains usable
if encoding, budgets or snapshot publication fail.

Directories are 0700 and files 0600, with owner/regular-file/link/size/hash checks.
When reports shrink to 1,000 groups or expire, intact owned archives and cached
full payloads are released; changed user files remain. A SIGKILL can leave a
private unpublished `.collector-archive-*` temporary file. It is never imported,
referenced by the snapshot or served by the dashboard; inspect it privately
before manual removal. Two published generations do not bound such orphaned
temporaries. These checks do not establish power-loss durability or a full
security audit.

Never commit, send to CI, host or redistribute archives, snapshots, logs,
quarantine, SQLite state or receipts. Public-mode UI exits before collector I/O.
User API keys and provider redistribution constraints remain unchanged.

## Remaining bounds

| Resource | Limit / meaning |
| --- | --- |
| Retained observations | 100,000 shared connection/DNS records; event/ingestion window also applies |
| DNS names / exported groups | 25,000 / 1,000, with separate omission counts |
| Connection snapshot | 1,000 groups; JSON at most 64 MiB |
| Full connection report | All retained connection groups; expanded JSON at most 256 MiB, gzip at most 64 MiB |
| Connection timelines | Existing 200-group / 48-bucket bounds remain |
| Attempt groups | Existing 500-group bound remains |

Budget failure stops publication with an explicit error and preserves the prior
report. Full retained export is different from full source retention. Capacity
and incomplete-input loss remain visible and disable expected declarations.
For large completed files, use [bounded preparation](LOG_PREPARATION.md).

## Frozen engineering replay

`connection-capacity-v1` freezes main `4b7adcd`, source hashes, permitted runtime
paths and contracts before implementation. Candidate/method/tests/oracle and
evaluation declaration are sealed before replay. Independent SQL-window payload
reconciliation complements offline/report/restart/gzip comparisons. All private
plans and outcomes stay outside Git; with those inputs, reproduce using:

```bash
python -m scripts.lab.verify_connection_capacity \
  --root /absolute/private/new-experiment \
  --baseline-root /absolute/private/independent-replay-v1
```

The first capacity verifier failed because Python timeline bucket tuples were
compared directly with JSON arrays. Its freeze and failure remain intact. A
separate replay amendment normalizes the oracle through JSON, without changing
product code, inputs, policies or thresholds. Earlier preparation strict/default
failures also remain historical receipts, never overwritten as successful.

| Known case | Eligible / quarantined | Retained records | Full / snapshot connection groups | First / idle seconds |
| --- | --- | --- | --- | --- |
| CTU-Normal-20 | 33,981 / 0 | 33,981 | 818 / 818 | 3.791 / 0.136 |
| CTU-Normal-21 | 19,360 / 49 | 19,360 | 1,350 / 1,000 | 2.620 / 0.140 |
| IoT-23 3-1 | 156,462 / 6 | 100,000 | 40,706 / 1,000 | 17.495 / 0.165 |
| Known IoT-23 8-1 | 10,403 / 0 | 10,403 | 9 / 9 | 1.229 / 0.065 |
| Synthetic reserved IPv6 targets | 100,000 / 0 | 100,000 | 100,000 / 1,000 | 14.735 / 0.190 |

IoT-3 now completes with the default 100k window, pruning **56,462** records,
including its older DNS observations. It retains two attempt reviews, no TCP
reviews: this is not a fresh malware-detection success. All arms have zero
rejected/pending files, zero new records on restart and unchanged retained
offline/full-report evidence. Gzip copies are duplicates. Windows and known
IoT-8 original findings/timelines/DNS remain identical.

The synthetic full JSON is 74,132,073 bytes (gzip 1,359,100 bytes), above the old
snapshot budget. Its 99,000 omitted snapshot groups remain in the full archive.
An actual SIGKILL of only the spawned writer during encoding leaves the previous
snapshot/archive byte-identical; restart recovers all 100k groups without new
records. One unpublished private stage remains as disclosed above. Large idle
arms reuse the full archive. Evaluation-process peak RSS is **1,092.3 MiB**;
this includes source, offline oracle and report copies, not collector-only RSS.
Times are one local engineering run, not throughput guarantees.

Validation: **1,264 tests, approximately 91% coverage**, including 31 new capacity,
budget, priority, expiry, download, race and recovery controls. The clean Linux
installation check additionally creates and downloads a 1,002-group full archive.
Seven existing runtime modules change, 75 of the previous 82 remain byte-identical,
and one archive module is added. All 34 original local data files are preserved.

This uses inspected sources and synthetic traffic, not new independent detection
evidence, RITA parity, human effectiveness or enterprise readiness. Frozen ML
identities, fresh-disjoint/strict-temporal distinctions and deferred promotion
remain. Next: predeclare representative multi-day load/resource/security/recovery
checks; then untouched timing/sparse/tunneling evidence, SIEM contracts and an
analyst pilot. Reserved independent sources remain unacquired. No public site.

The subsequent [multi-day protocol](MULTIDAY_COLLECTION.md) records accelerated
rotation, retention, collector-only resource and recovery checks separately from
this capacity run. Original receipts and resource measurement scopes remain.
