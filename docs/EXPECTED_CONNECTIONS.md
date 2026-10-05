# Expected connection declarations

ThreatFusion can separate analyst-declared expected activity from unexplained
connection reviews. This is optional local context, not an allowlist, verified
process identity or a change to malware verdicts. Every original connection
priority, statistic and reason stays in the report.

Use this after independently checking what a device should contact. Zeek
connection records alone cannot identify the originating application. A service
using the same endpoints and traffic limits can match the same declaration.
Neither a match nor the absence of CTI proves safety.

## Local workflow

Connection policy v2 can review bidirectional reset/partial-close sessions, but
expected declarations still require original SF/S1 confirmed evidence. Such
partial/reset groups remain visible and cannot match an expected declaration.
See [termination coverage](TCP_TERMINATION.md).

1. Keep an `expected-connections.json` outside the repository, with owner-only
   permissions (`chmod 600 expected-connections.json`). Actual addresses and rule
   references describe your topology; do not publish the file.
2. In **Connection activity**, upload the JSON using the optional local uploader.
   It applies to that rendering session, is not stored in analysis history and
   is not available in public mode. Clear the upload to remove the declarations.
3. The default review view separates matching expected activity. Use **Include
   declared expected activity** to inspect it again. CTI conflicts stay visible
   even when the original connection priority is Observe.
4. The upload connection download contains **all** groups, including declared
   expected ones. Endpoint addresses remain aliased by default; rule IDs and
   configuration are omitted even from the explicit IP export.

For collection above 1,000 connection groups, the visible JSON is a bounded
snapshot with omissions disclosed. Use its separate verified full JSON.gz
download for all retained groups, including expected activity. Summary counts
still cover all retained groups. See [collector capacity](CONNECTION_CAPACITY.md).

Summary counts preserve original, declared and unexplained/CTI work before
filters. Selected-group guidance covers evidence, limits and service verification.
See [analyst tasks and measurements](ANALYST_REVIEW.md).

For automation:

```bash
threatfusion /path/to/conn.log --format zeek-conn --cti-only \
  --db /path/to/your/cache.sqlite \
  --expected-connections /private/expected-connections.json \
  --connection-json-output /private/new-review.json
```

The CLI requires the explicit separate connection report and refuses existing
output files. Invalid declarations abort before analysis/export, with no private
configuration echoed. An invalid UI upload applies no declarations and leaves
the original reviews visible. No credentials, network lookup or feed update are
involved in context matching. Use your own updated CTI cache for CTI coverage.

## Schema and boundaries

This example uses reserved documentation addresses. Replace them with exact
observed addresses, justified limits and a current validity window before use.
The dates below are illustrative, not an automatically renewed policy.

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "checked-updater",
      "originator_ip": "192.0.2.1",
      "responder_ip": "198.51.100.1",
      "responder_port": 443,
      "protocol": "tcp",
      "valid_from": "2026-10-04T00:00:00Z",
      "valid_until": "2026-10-05T00:00:00Z",
      "max_connections": 100,
      "max_duration_seconds": 60,
      "max_originator_bytes": 100000,
      "max_responder_bytes": 1000000
    }
  ]
}
```

- At most 64 KiB and 128 rules. All documented fields are required; unknown and
  duplicate JSON fields are rejected. IDs must be unique ASCII letters/digits,
  `_` or `-`, with at most 64 characters. IDs are local references only.
- Exact IPv4/IPv6 originator, responder and responder port are mandatory. No
  CIDR, wildcard, hostname resolution, inferred domain association or UDP policy.
- Validity must use aware ISO timestamps, last at most 30 days and be active at
  evaluation time. Expired declarations do not apply even to older observations.
- The entire group's observed sessions must fit the validity window and have
  finished by evaluation time. Latest start plus maximum duration is used as a
  conservative upper bound; a legitimate group can fail this bound.
- All sessions must have nonconflicting UID, known originator port, complete
  aware timestamps/duration/bytes, successful bidirectional TCP and zero missed
  bytes. Sparse timing alone does not invalidate an otherwise complete long
  session, but missing metadata, capture gaps or failed sessions do.
- Connection count, maximum individual duration and summed originator/responder
  payload bytes must stay within the declared limits. These are **whole-upload
  group limits**, not rolling rates. A longer upload may exceed an expectation.
- Any existing CTI response-IP/network match for that observed client/destination
  overrides a declaration, regardless of port. This does not introduce an
  originator-IP CTI lookup or inherit another client's DNS/domain evidence.

The separate connection export now uses **schema version 2**. Its detection
policy remains `zeek-connection-context-v2`; `expected-connection-context-v1`
adds `Analyst context`, `CTI match`, `Declared expected` and `Context reason`,
plus evaluation time and declaration count. Existing aggregate/domain and device
reports retain their contracts. Keep all telemetry exports local.

## Evidence and next gate

`scripts/lab/evaluate_expected_controls.py` freezes logs, declarations, hashes
and expected context outcomes before evaluating 11 constructed scenarios. It
checks expiry, wrong device/port, byte deviation, capture gaps and synthetic CTI.
Both the declared updater and an identical harmless heartbeat on its endpoint
match: this explicitly records the inability to verify software identity.
It measures policy behavior, not improved recall, false-positive rate or real
analyst time saved. It does not tune detector or ML thresholds.

```bash
.venv/bin/python scripts/lab/evaluate_expected_controls.py \
  --output-dir /path/outside/repo/new-expected-controls
```

The next evidence gate remains longer independent permitted captures and actual
analyst workflow validation. Automatic suppression, rolling ingestion and a
deployable RITA alternative are not established by these controls.
