# ThreatFusion AI Documentation

This directory contains the technical documentation behind the portfolio-facing README.

> Language note: the repository README is available in **[English](../README.md)** and **[Türkçe](../README.tr.md)**. Technical reference documents are kept in English to avoid maintaining two diverging specifications.

## Start here

| Document | Use it for |
| --- | --- |
| [INSTALL_LINUX.md](INSTALL_LINUX.md) | One-command private Python/dependency install and localhost demo/CTI-only start |
| [TELEMETRY_COLLECTOR.md](TELEMETRY_COLLECTOR.md) | Private automatic completed Zeek logs, restart/rotation, limits and local UI |
| [DNS_COLLECTION.md](DNS_COLLECTION.md) | Automatic TCP/UDP DNS transaction collection, private state migration and live controls |
| [LOG_PREPARATION.md](LOG_PREPARATION.md) | Bounded completed-log preparation, explicit private DNS quarantine and coverage accounting |
| [CONNECTION_CAPACITY.md](CONNECTION_CAPACITY.md) | Diverse collector targets, bounded snapshots, verified private full exports and recovery evidence |
| [MULTIDAY_COLLECTION.md](MULTIDAY_COLLECTION.md) | Accelerated multi-day rotation, independent retention, own-process resources and recovery protocol |
| [DNS_INVESTIGATION.md](DNS_INVESTIGATION.md) | Device/domain query timelines, scan health and private rotation/recovery/resource protocol |
| [NETWORK_EVALUATION.md](NETWORK_EVALUATION.md) | Independent official IoT-23 protocol, aggregate observations and detection gaps |
| [REVIEW_WORKLOAD.md](REVIEW_WORKLOAD.md) | Normal review burden, caching/shared resolvers, same-source native RITA and excluded corrupt inputs |
| [CONNECTION_INVESTIGATION.md](CONNECTION_INVESTIGATION.md) | Bounded connection timelines, analyst workflow and two isolated live termination controls |
| [TCP_ATTEMPT_REVIEW.md](TCP_ATTEMPT_REVIEW.md) | Sliding-window TCP failure diversity/retry review, private workflow and reserved evidence |
| [TCP_TERMINATION.md](TCP_TERMINATION.md) | Partial/reset TCP payload coverage, failed-attempt counts and reserved comparison |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Current data flow, trust boundaries, runtime components and design principles |
| [DATA_SOURCES.md](DATA_SOURCES.md) | CTI sources, attribution, redistribution boundaries and telemetry privacy |
| [ML_DATASET.md](ML_DATASET.md) | Dataset construction, evaluation methodology, holdouts and model limitations |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Docker, public mode, sanitized runtime bundles and scheduled CTI refresh |
| [RELEASE_NOTES_v0.1.0.md](RELEASE_NOTES_v0.1.0.md) | v0.1.0 release-candidate scope and limitations |
| [RELEASE_CHECKLIST_v0.1.0.md](RELEASE_CHECKLIST_v0.1.0.md) | Final publication checklist |
| [RELEASE_HANDOFF.md](RELEASE_HANDOFF.md) | Current release status, blockers and exact next steps |
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Problem statement, goals, implemented scope and intended users |
| [DECISIONS.md](DECISIONS.md) | Important technical and product decisions |
| [UI_REVIEW.md](UI_REVIEW.md) | Manual Streamlit presentation/regression review flow |

## Current product boundaries

ThreatFusion AI is an educational and portfolio security-analysis prototype.

It currently demonstrates:

- multi-source CTI ingestion and normalization;
- indexed passive URL/domain/IP lookup;
- automatic network/DNS telemetry ingestion;
- deterministic IOC correlation;
- ML-assisted domain scoring;
- DNS behavior context;
- explainable hybrid verdicts;
- analyst feedback, suppression and history;
- privacy-safe exports;
- scheduled CTI refresh support;
- Docker/public-mode packaging;
- cross-platform CI and dependency auditing.

It is not positioned as a production SIEM, EDR, IDS/IPS replacement, automated incident-response platform, or guaranteed malware detector.

## Documentation principles

The documentation follows four rules:

1. **Implemented behavior is separated from future work.**
2. **Known IOC evidence is distinguished from contextual evidence and ML signals.**
3. **ML scores are not described as calibrated malware probabilities.**
4. **Privacy and third-party data boundaries are documented alongside functionality.**
