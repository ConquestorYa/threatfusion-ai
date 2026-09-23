# ThreatFusion AI

## Problem

Simply displaying public USOM or threat-feed data would provide limited value because users can already access those sources directly. ThreatFusion AI is intended to combine multiple threat-intelligence sources with organization or user DNS telemetry so an analyst can ask:

- Which known threats appeared in my network?
- Which domains are not in known threat feeds but look suspicious?
- Which indicators may belong to the same emerging campaign?

## Core Goal

ThreatFusion AI is an AI-assisted multi-source cyber threat intelligence and early-warning platform. It is an educational prototype, not a production security product. Its value is intended to come from combining external intelligence with local observations and producing understandable, measurable findings.

## Intended Users

Potential users include:

- Small SOC or security teams.
- Cybersecurity students and researchers.
- Small organizations without a full SIEM or CTI platform.

These users are a realistic target for an educational prototype that demonstrates data integration, detection, and explainability without claiming production-grade coverage or response capability.

## Implemented So Far

The repository currently implements:

- `IOCType`, an enum for domains, URLs, IPv4, IPv6, common hashes, and unknown values.
- `IOCRecord`, the common dataclass used to represent an indicator.
- IOC value normalization for domains, hashes, IP addresses, URLs, and unknown values.
- IOC correlation and deduplication through `IOCGroup` and `correlate_iocs()`.
- A ThreatFox collector for recent API IOC data, including conservative type mapping and timestamp/tag parsing.
- A URLhaus collector for the recent CSV export, including named-column discovery and malformed-row handling.
- Automated pytest tests for the model, normalization, correlation, and collectors.
- Ruff checks for code quality.
- Real live-data validation for the ThreatFox and URLhaus collectors in addition to network-free automated tests.

Threat URLs, domains, IP addresses, and hashes are treated strictly as data. The collectors do not visit, resolve, open, or follow IOC URLs returned by feeds. Authenticated feed requests are limited to their official collection endpoints, and collector tests use injected fake sessions.

## Planned Core Features

The following capabilities are planned and are not implemented in the current repository:

- USOM integration.
- Broader multi-source correlation workflows.
- DNS telemetry CSV upload.
- Matching known IOCs against DNS telemetry.
- ML-based detection of previously unseen suspicious domains.
- Explainable domain-risk output.
- Campaign clustering.
- A model evaluation dashboard.
- A Streamlit dashboard.
- An optional threat relationship graph.
- Optional analyst feedback.
- Optional LLM-generated analyst reports.

## ML / LLM Principle

Machine Learning is intended to perform detection and classification, including malicious-domain classification and clustering or campaign discovery. These capabilities should be measurable with precision, recall, F1 score, and false-positive rate.

An LLM may be used later as an optional explanation and analyst-reporting layer. It must not act as the primary malicious-domain detector.

**ML detects.  LLM explains.**