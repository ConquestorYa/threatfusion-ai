# Detection development and comparison gates

## Goal

Build a useful local Zeek/CTI investigation option with competitive core
coverage, and seek a measured advantage in explainable client-level DNS triage.
The web interface remains the analyst workspace; the CLI remains the automation
interface. RITA stays an optional external comparison baseline.

RITA's documented core capabilities are beaconing, long connections, DNS
tunneling and threat-intelligence checks:
[official RITA README](https://github.com/activecm/rita#rita-real-intelligence-threat-analytics).
ThreatFusion does not yet have measured equivalent coverage. Its existing
`conn.log` importer now preserves typed connection metadata for conservative
long-session/regularity review, alongside destination-IP CTI. This initial
context is not measured equivalent C2 detection.

| Capability | Current evidence | Next acceptance gate |
| --- | --- | --- |
| Client-level DNS review | Independent client/target assessments, sustained-periodic review, CTI evidence scope; synthetic checks and existing Zeek replay | Realistic DNS caching/update controls, several independent windows, alert burden and analyst usefulness |
| Connection behavior | Typed UID/direction/ports/duration/bytes; long bidirectional TCP review; isolated cache/persistence capture | Independent longer captures, partial-session coverage and operational alert burden |
| TCP attempt behavior | S0/REJ sliding-window failed port/host diversity and dense retry review; constructed/live controls; one new official capture produces none | New independent benign/sparse-failure controls and reserved inputs; operational review burden |
| Beaconing | Sustained successful TCP timing review plus DNS regularity; no C2 accuracy claim | Robust timing/size analysis and jitter/retry/idle controls on independent permitted windows |
| DNS tunneling | Hostname shape context only | Registrable-domain aggregation with proper suffix handling, unique-label/size/type evidence, benign CDN/telemetry controls and independent recordings |
| Continuous collection | Completed TSV/gzip mixed-log collector, transaction-aware private state, scan health, idle cache and declared rotation/recovery/capacity checks | Active-file tailing decision, representative multi-day load/recovery/security checks |
| Analyst operations | Local web investigation, bounded connection-start and device/domain DNS timelines, feedback, reports and expiring exact-endpoint declarations with CTI override | Independent analyst task validation and documented SIEM export contracts |
| Operational readiness | Local test suite and bounded synthetic workload | Security review, installation/recovery checks and representative throughput/resource measurements |

## Current increment: normal review workload and source integrity

`review-workload-v1` freezes unchanged runtime policies before two new seeded
two-hour packet replays and three newly selected official PCAPs. Both synthetic
windows yield 5/7 normal TCP reviews and 3/5 simulated reviews; cache-limited DNS,
shared resolver origins, wide jitter and sparse failures expose explicit gaps.
One intact provider-described normal capture yields one TCP and one DNS review;
two sources fail structural/Zeek checks and remain excluded. All three successful
inputs reconcile complete offline/collector/timeline/restart/gzip outputs.
Optional native RITA receives identical logs; its row/severity units are separate.
See [protocol, aggregate results and reproduction](REVIEW_WORKLOAD.md).

The independent real-source gate is partial, not completed representative
validation. Next: predeclare analyst tasks/normal context with preserved original
evidence, obtain several new intact permitted windows, then reserve inputs for
any timing/sparse-failure change. No tuning, ML promotion, accuracy/parity or
human efficacy claim follows from this measurement.

## Previous increment: DNS investigation and collector reliability

Device/domain selectors now offer bounded UTC query counts and response-code
timelines for uploads and collection. Existing detector/ML thresholds remain.
Scan/rejection categories and idle-cache reuse improve operational visibility;
rule expiry and CTI changes still apply. The declared private protocol includes
20-minute real synthetic mixed-log rotation, owned-process shutdown/kill/restart
and pause, exact offline reconciliation and a 120k-record capacity workload.
See [workflow, protocol, aggregate receipts and limits](DNS_INVESTIGATION.md).
Closed-file latency includes rotation and delivery; active tailing is deferred.
The next acceptance gate is independent permitted benign/update/resolver controls
and realistic analyst tasks. DNS tunneling/general UDP and sparse-failure changes
require separately declared controls and new reserved recordings. These checks
do not establish accuracy, enterprise FPR, RITA parity or production readiness.

## Previous increment: automatic DNS collection

Completed TCP/UDP DNS transactions now populate the existing client/domain
triage alongside independent original connection reports. Private schema-1 state
is backed up before schema-2 upgrade; copies/conflicts and shared capacity/window
limits are explicit. Both 11-case identifier sets pass. Two new isolated live
captures each reconcile 24 DNS transactions on two UIDs plus two connection rows;
no reviews, restart adds zero and gzip copies count as two duplicates. These are
short synthetic plumbing controls, not real benign FPR or tunneling detection.
See [workflow, limits and receipts](DNS_COLLECTION.md). Next operational gate:
the subsequent rotating-log/recovery and device DNS investigation increment
documented above; representative multi-day operation remains open.
DNS tunneling/general UDP behavior need separately predeclared new evidence;
sparse TCP failures and independent benign/analyst efficacy remain open.

## Previous increment: TCP attempt review

A separate bounded queue groups S0/REJ failures across ports/responders and dense
retries in sliding five-minute windows. All 64 predeclared controls pass, including
benign inventory/outage review burden. A new 120-record live control produces
three patterns; a new official 10,403-record capture produces none. Its maximum
16 same-endpoint failures per five minutes remains outside the declared gate.
Original connection/domain verdicts match the trusted baseline. See
[workflow, scope and coverage gap](TCP_ATTEMPT_REVIEW.md). Next: UDP/DNS controls,
new independent benign/sparse-failure evidence, longer rotation and analyst study.

## Previous increment: connection investigation and real termination controls

Uploaded/collected groups now have bounded connection-start UTC charts and
state/known-byte/missing-byte summaries; all findings remain exported with
report-local identifiers. Two predeclared isolated live captures each produce
72 records (12 each SF/RSTO/RSTR/S2/S3/REJ), zero short-window reviews and exact
offline/collector/restart/gzip reconciliation. Human analyst efficacy remains
unmeasured. See [workflow and protocol](CONNECTION_INVESTIGATION.md).

## Previous increment: TCP termination coverage

Policy v2 retains bidirectional payload from S2/S3/RSTO/RSTR endings under the
existing long/timing gates and exposes failed/half-open attempts separately.
Expected declarations cannot hide these partial/reset groups. All 64 predeclared
development/reserved contract checks pass. Three new official captures have the
same Review counts as v1; one has 1,637 additional eligible payload sessions.
Another malicious capture still has no eligible bidirectional sessions.
See [protocol, counts and limits](TCP_TERMINATION.md). These are coverage gains,
not increased malware recall or parity. New untouched inputs are required for
further failure/scan or UDP/DNS detector development.

## Previous increment: independent coverage and completed-log collection

Four predeclared official IoT-23 inputs now provide independent 1.91–23.98-hour
connection coverage observations. One malicious capture yields a long-session
review; another yields none. Benign captures yield no connection reviews but
one has two separate fallback verdict reviews. This is not an accuracy or parity
claim. Labels/CTI/ML/context were excluded and frozen thresholds unchanged. See
[results and protocol](NETWORK_EVALUATION.md).

Linux completed-file collection now has bounded evidence/checkpoints, content
deduplication, restart recovery, fair bounded scans and a local refreshing
snapshot view. All four isolated imports matched offline results after restart
and gzip duplication. Active files wait for rotation; no sensor/system service
or production throughput guarantee is installed. See [operation](TELEMETRY_COLLECTOR.md).

Next: declare partial/reset/retry timing controls and reserve new independent
evaluation inputs before changing detection; validate actual analyst workload
and longer live rotation/resource behavior. These v1 captures are inspected
evidence and cannot become an untouched holdout for the next tuned increment.

## Previous increment: expected-connection-context-v1

Optional local declarations separate expected operational activity without
changing original connection priorities or DNS/domain/device verdicts. Exact
endpoints, upload-wide volume/count/duration bounds and <= 30-day expiry are
required. Incomplete data cannot qualify. Existing client/destination CTI
matches override declarations, including for Observe connections. Reports keep
all groups; the UI filter is reversible and declarations are not persisted.
See [schema, workflow and evidence limits](EXPECTED_CONNECTIONS.md).

Eleven predeclared synthetic context controls pass, including a same-endpoint
heartbeat that also matches the declaration. This is an explicit software
identity limitation, not improved detection or measured false-positive reduction.
Longer independent permitted capture and analyst workload evaluation remain open.

## Previous increment: dns-device-triage-v1

The existing domain-wide verdict and original `periodic-controls-v1` comparison
remain unchanged. A separate queue evaluates each observed client and target
independently. IP infrastructure evidence from one client's answer is not
inherited by another client querying the same domain. ML inference is reused;
neither model identities nor frozen thresholds are changed or promoted.

Queue priorities are `investigate` (existing exact-domain/high-risk evidence),
`review` (existing review evidence or sustained DNS regularity), and `observe`.
They describe investigation order, not confirmed compromise. Regularity alone
can move a Low verdict into the Review **queue**, while its threat verdict
stays Low. Legitimate updates and the matching heartbeat simulation both qualify.

Sustained-periodic review requires a valid observed client IP, fully specified
timezone-aware timestamps, at least **20 distinct timestamps**, at least
**1,800 seconds** of observed span and the existing periodicity rule. These are
declared engineering coverage gates, not optimized detection thresholds or
malware accuracy claims. Duplicate answer rows do not count as additional
timestamps. Missing/invalid client identities remain unattributed; IP targets
from `conn.log`/flow fallbacks cannot receive the DNS periodic-review reason.
Coverage limits do not suppress direct CTI evidence.

The Device triage tab hides IP identities by default using report-local aliases.
Explicit local viewing/export may include observed client IPs; public-mode
rendering never offers this option. Aliases are not anonymization: targets,
timestamps and CTI evidence remain telemetry. Existing aggregate exports and
history remain unchanged; the device queue is session-local and unpersisted.
An observed client may be a resolver/NAT, and is not a verified endpoint asset.

## Evidence discipline

`scripts/lab/evaluate_device_controls.py` writes immutable external inputs and
manifest hashes before evaluating 12 control types at two fixed seeds. Controls
cover irregular browsing, benign polling/update schedules, matching simulated
heartbeat timing, sparse cached DNS, short captures, duplicate answer rows,
missing metadata, pooled clients and synthetic exact/infrastructure CTI.
Detector input excludes intent labels and expected queue values. Synthetic CTI
fixtures are reserved domains/addresses; no feed/cache/credential is used.

**24/24 passing policy checks establish engineering behavior only.** Expected
queue labels are not malware truth. This suite is neither realistic production
traffic nor independent proof of false-positive rate, recall or RITA superiority.
The original shared Zeek replay yields two device reviews and three observations;
its original five Low domain verdicts and RITA findings remain unchanged.

For every next detector increment:

1. Declare scope, input requirements and benign/suspicious controls before
   collecting results. Keep development and evaluation windows separate.
2. Use harmless isolated simulation and permitted independent recordings.
   Preserve immutable shared inputs and record each tool's data/configuration.
3. Measure missed scenarios, benign review/alert burden, missing-data behavior,
   latency and resource use. Report review queue load separately from malware
   verdict accuracy; native severity labels are not comparable probabilities.
4. Implement the smallest justified change, run regressions and evaluate on a
   new reserved window. Do not select thresholds on the frozen v1 observations.
5. Publish method, code and aggregate limitations. Keep traffic, evaluation
   outputs, private history, CTI datasets and model artifacts local.

Real-traffic evidence, security review and operational checks are required before
claiming a deployable RITA alternative. Stronger untouched strict-temporal ML
evidence is still required for the deferred runtime promotion decision.
