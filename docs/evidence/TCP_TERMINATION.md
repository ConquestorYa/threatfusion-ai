# TCP termination coverage and independent evaluation

Connection policy `zeek-connection-context-v2` retains bidirectional payload
evidence when an established TCP session ends with an incomplete close or reset.
Zeek's S2/S3 states describe incomplete closes; RSTO/RSTR describe reset endings.
Payload-byte counts and capture gaps are separate observations. See the
[official Zeek connection script](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/conn/main.zeek).
These states can occur during normal operations.

## Product behavior

| Evidence | Behavior |
| --- | --- |
| SF/S1, positive bytes both ways, zero missed bytes | Existing confirmed-session count and rules |
| S2/S3/RSTO/RSTR, positive bytes both ways, zero missed bytes | Additional eligible payload-session evidence; termination counts/notes remain visible |
| S0/REJ/RSTOS0/RSTRH/SH/SHR | Count failed/half-open attempts; no payload-based Review inferred |
| OTH, UDP or ICMP | Outside established TCP payload rules |
| Missing bytes, one-way bytes or capture gaps | Does not qualify for the new payload rules |

Long-session Review still requires at least 3,600 seconds, observed source and
destination port, a unique nonconflicting UID and eligible bidirectional payload.
New termination states additionally require the originator port. Sustained
periodic Review still requires 20 distinct aware timestamps, 1,800-second span,
score >= 0.85 and complete metadata across the group. Mixed SF/S1/new eligible
states may qualify. Missing/conflicting UIDs, missing time/duration/endpoints or
any ineligible session prevent this timing reason. No thresholds were optimized.

The existing **Confirmed sessions** field retains its SF/S1 meaning. Four
additional fields expose **Bidirectional payload sessions**, **Reset endings**,
**Incomplete closes**, and **Failed or half-open attempts** in connection views
and aliased JSON reports. Termination/attempt counts include unique valid-UID
records even when their bytes/timing are insufficient for Review; payload counts
require the conditions above. Counts do not establish software identity or
malware. Report schema remains v2 with additive columns and a new policy ID.

Expiring expected-connection declarations remain conservative: reset/partial
groups cannot be declared expected or hidden by that filter. Original SF/S1
requirements and CTI overrides remain. Private collector state stores unchanged
typed records; restarting/upgrading recomputes snapshots with the new policy.
Old retained records need no migration. Raw UIDs and endpoints remain private.

## Predeclared controls

`tcp-termination-coverage-v1` wrote its plan/hash and constructed inputs before
detector changes. A development seed and separate reserved seed each contain
32 cases: long/periodic/short sessions for all four new states, incomplete
metadata/gaps/one-way payload, unconfirmed states, irregular/short windows,
duplicate/conflicting UIDs, benign periodic updates, matching heartbeat and
mixed established states. **32/32 development and 32/32 reserved checks pass.**
Benign periodic updates still Review, exactly like their timing-identical
heartbeat control. Those declared priorities verify contracts, not malware
labels or operational false-positive rates. Candidate/parser/report fingerprints
and declared control manifests were frozen before fresh source acquisition.
The inspected earlier four IoT-23 captures were not rescored or used for tuning.

## Reserved official captures

Three different official source files were selected before acquisition. Only
file locations/HEAD sizes were checked before freezing; no traffic bodies were
read. Each label-free log was evaluated by v2 and an isolated trusted archive of
baseline commit `bf5155c3d4378f5d5280c8b422ef379da99eeb80`. Baseline fingerprints
were verified in that process. CTI, ML and analyst declarations were disabled.
Provider labels were kept outside product input. Source attribution, license
references and distribution boundaries are in [the earlier evaluation](NETWORK_EVALUATION.md).

| Capture | Rows | Start-time span | Groups | v1 reviews | v2 reviews |
| --- | ---: | ---: | ---: | ---: | ---: |
| Honeypot-7-1 / Somfy-01 | 130 | 1.38 h | 20 | 1 | 1 |
| IoT-Malware-34-1 | 23,145 | 24.00 h | 52 | 1 | 1 |
| IoT-Malware-21-1 | 3,286 | 23.90 h | 51 | 0 | 0 |

All **26,561 rows** were accepted without invalid/skipped metadata. Separate
domain/IP verdict counts also match baseline. Somfy's reviewed group contains
one benign-labeled flow; capture 34's reviewed group contains 6,706 malicious-
labeled flows. These counts describe provider labels in groups, not verified
C2 detection or comparable group/flow recall. No new Review group was produced.

A post-evaluation coverage diagnostic found capture 34 now has **1,642 eligible
payload sessions**, versus five original SF/S1 confirmed sessions: 1,584
incomplete closes and 53 reset endings supply 1,637 additional payload sessions.
The dashboard therefore exposes much more observed connection evidence, while
the frozen long/timing Review criteria still produce the same queue.

Capture 21 still has zero eligible payload sessions. Its 14 malicious-labeled
flows include ten S0 attempts, one REJ and one each SF/S2/S1; none satisfies
bidirectional-payload requirements. Its eleven failed/half-open attempts and
one incomplete close are visible as counts. The remaining detection gap is
recorded explicitly. This is input/coverage evidence, not permission to classify
failed attempts as malware or tune these now-inspected records.

| Source | Acquired SHA-256 |
| --- | --- |
| CTU-Honeypot-Capture-7-1 / Somfy-01 | `fb37fb38393c48b064d3afd373b075ffe31063d4924a2df1c5d13fc490b830cc` |
| CTU-IoT-Malware-Capture-34-1 | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` |
| CTU-IoT-Malware-Capture-21-1 | `b63db259aead078f50fc150aa97ace4d1f69576e1245334962759d978ce437eb` |

## Reproduction

Use a new private directory outside the checkout and a trusted baseline archive:

```bash
mkdir -m 700 /absolute/private/path/baseline
git archive bf5155c3d4378f5d5280c8b422ef379da99eeb80 | tar -x -C /absolute/private/path/baseline
python -m scripts.lab.evaluate_session_coverage --directory /absolute/private/path/run prepare
python -m scripts.lab.evaluate_session_coverage --directory /absolute/private/path/run development
python -m scripts.lab.evaluate_session_coverage --directory /absolute/private/path/run freeze
python -m scripts.lab.evaluate_session_coverage --directory /absolute/private/path/run evaluate \
  --baseline-source /absolute/private/path/baseline
```

Only the three declared connection logs are downloaded, at most 4 MiB each;
observed destinations are never contacted and malware/PCAP files are not acquired.
Existing artifacts cannot be overwritten. Source content/availability is external;
different hashes identify another acquisition. Future policy changes require this
increment's Git revision to reproduce its freeze. Raw logs, reports, labels and
state remain outside GitHub, CI and hosting.

The next evidence gate is representative real reset/close workloads, missing/
one-way capture behavior, and analyst review workload. Failed-attempt/scan and
UDP/DNS coverage need their own predeclared controls and new reserved inputs.
No production accuracy, RITA parity or ML promotion follows from this increment.
