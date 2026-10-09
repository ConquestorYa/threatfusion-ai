# Documentation

## Using ThreatFusion

| Document | Contents |
| --- | --- |
| [Linux installation](INSTALL_LINUX.md) | One-command install, start/stop, upgrades, keys |
| [Zeek sensor setup](ZEEK_SETUP.md) | Producing logs: sensor placement, Docker recipe, privacy |
| [User guide](USER_GUIDE.md) | Pages, collector, what gets flagged, investigation, limits |
| [Architecture](ARCHITECTURE.md) | Data flow, evidence model, storage and privacy |
| [Data sources](DATA_SOURCES.md) | CTI sources, licences and attribution |

## Evidence

What has been measured, how, and what failed. Each record names the exact
commit and protocol it belongs to; later code needs new measurements.

| Record | Question |
| --- | --- |
| [Real-traffic evaluation design](evidence/REAL_TRAFFIC_EVALUATION.md) | How usefulness on real traffic and on labeled malware will be measured (in progress) |
| [Review workload](evidence/REVIEW_WORKLOAD.md) | How much normal synthetic traffic enters Review; comparison with RITA |
| [Network evaluation](evidence/NETWORK_EVALUATION.md) | Independent IoT-23 captures: what was found and missed |
| [Independent replay](evidence/INDEPENDENT_REPLAY.md) | Replays of independent captures through the collector |
| [TCP termination](evidence/TCP_TERMINATION.md) / [TCP attempts](evidence/TCP_ATTEMPT_REVIEW.md) | Connection-state and failed-attempt rules on live controls |
| [Connection investigation](evidence/CONNECTION_INVESTIGATION.md) / [DNS investigation](evidence/DNS_INVESTIGATION.md) / [DNS collection](evidence/DNS_COLLECTION.md) | Timeline, DNS identity and migration contracts with live controls |
| [Expected connections](evidence/EXPECTED_CONNECTIONS.md) | Declaration rules and their constructed controls |
| [Collector](evidence/TELEMETRY_COLLECTOR.md) / [capacity](evidence/CONNECTION_CAPACITY.md) / [log preparation](evidence/LOG_PREPARATION.md) | Collector contracts, capacity and large-file preparation |
| [Multi-day collection](evidence/MULTIDAY_COLLECTION.md) / [operational confidence](evidence/OPERATIONAL_CONFIDENCE.md) | Rotation, retention, fault matrix, wall-clock soak, security reviews |
| [Analyst review](evidence/ANALYST_REVIEW.md) | Review guidance and synthetic analyst tasks |
| [ML dataset and evaluation](evidence/ML_DATASET.md) | The experimental domain model and why it is off |
| [Local lab](evidence/LOCAL_LAB.md) | Isolated lab used for controls and RITA comparison |
| [Manual acceptance](evidence/MANUAL_ACCEPTANCE_TR.md) | The developer's manual acceptance checklist (Turkish) |

Not yet measured: detection rate on real malware, false alarms on real traffic,
usefulness for other users.

## Development

| Document | Contents |
| --- | --- |
| [Product plan](dev/PRODUCT_PLAN.md) | Goal, status and the ordered work queue |
| [Decisions](dev/DECISIONS.md) | Numbered design decisions with reasons |
| [Project context](dev/PROJECT_CONTEXT.md) | Current checkpoint and dated history |
| [Release handoff](dev/RELEASE_HANDOFF.md) | Latest completed work, checks and limitations |
