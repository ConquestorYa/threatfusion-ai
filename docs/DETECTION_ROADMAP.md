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
`conn.log` importer maps destination-IP observations for CTI; it discards
duration/connection statistics and is not long-connection detection.

| Capability | Current evidence | Next acceptance gate |
| --- | --- | --- |
| Client-level DNS review | Independent client/target assessments, sustained-periodic review, CTI evidence scope; synthetic checks and existing Zeek replay | Realistic DNS caching/update controls, several independent windows, alert burden and analyst usefulness |
| Connection behavior | Destination-IP CTI ingestion exists | Preserve UID, duration, direction, ports and bytes; verify long sessions and noisy benign controls |
| Beaconing | DNS regularity heuristic and review queue; no network beacon-detection accuracy claim | Connection timing and size analysis on declared jitter/retry/idle controls; compare native RITA outputs on shared logs |
| DNS tunneling | Hostname shape context only | Registrable-domain aggregation with proper suffix handling, unique-label/size/type evidence, benign CDN/telemetry controls and independent recordings |
| Continuous collection | Manual local upload/CLI | Rotation-aware, bounded, restart-safe ingestion with checkpoints and duplicate protection |
| Analyst operations | Local web investigation, feedback, aggregate exports and explicit device export | Device investigation/timelines, bounded retention and documented SIEM export contracts |
| Operational readiness | Local test suite and bounded synthetic workload | Security review, installation/recovery checks and representative throughput/resource measurements |

## Current increment: dns-device-triage-v1

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
