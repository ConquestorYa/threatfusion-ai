# ThreatFusion AI — Project Context

## Problem

Public threat feeds answer **what is known to be malicious**, but they do not directly answer **what appeared in a user's environment** or **what should be reviewed first**.

ThreatFusion AI connects external intelligence with local telemetry so an analyst can ask:

- Which known indicators appeared in my telemetry?
- Which unseen domains deserve review?
- What evidence produced this verdict?
- Are multiple suspicious observations related by local infrastructure?
- Is the threat-intelligence cache fresh enough to trust for triage?

## Core goal

ThreatFusion AI is an AI-assisted, multi-source cyber threat-intelligence and telemetry-triage platform.

Its portfolio value comes from combining:

- CTI engineering;
- safe local telemetry ingestion;
- deterministic IOC matching;
- measured ML experimentation;
- explainable hybrid decisions;
- privacy-conscious persistence;
- analyst workflow design;
- deployment and CI practices.

It is an educational prototype, not a production security product.

## Intended users

The prototype is most relevant to:

- cybersecurity students and researchers;
- small SOC/security teams evaluating a lightweight workflow;
- small organizations learning how CTI and local telemetry can be combined.

## v0.1.0 implemented scope

### Threat intelligence

Implemented sources:

- ThreatFox;
- URLhaus;
- PhishTank verified-online public feed;
- T.C. Siber Güvenlik Başkanlığı (SGB).

The local SQLite CTI cache supports:

- normalized values;
- active/inactive lifecycle state;
- refresh metadata;
- indexed Quick Lookup keys;
- URL hostname indexing;
- stale-source visibility;
- independent source refresh with previous-snapshot preservation on failure.

### Passive Quick Lookup

A user can submit one:

- URL;
- domain;
- IPv4/IPv6 address.

ThreatFusion checks the local CTI cache without visiting the destination. Domain ML is only used for eligible domain targets.

### Telemetry ingestion

Auto-detect currently supports:

- CSV / TSV / TXT;
- XLSX / XLS;
- Zeek <code>dns.log</code>;
- Zeek <code>conn.log</code>;
- PCAP / PCAPNG / CAP classic UDP DNS;
- Suricata EVE JSON / JSONL;
- Pi-hole FTL SQLite;
- AdGuard Home query logs;
- dnstop-style domain rows.

<code>.capinfos</code> is recognized as metadata and is not analyzed as packet telemetry.

### Analysis

Runtime analysis combines:

- known IOC matching;
- domain ML scoring;
- DNS behavior aggregation;
- explainable hybrid assessment;
- related-activity context.

The hybrid model distinguishes exact known-domain evidence from weaker hostname/infrastructure context.

### Machine learning

The ML component uses character n-gram TF-IDF + balanced Logistic Regression.

The development workflow includes:

- reproducible snapshots;
- train/validation/test separation;
- validation-selected thresholds;
- explicit FPR budgets;
- source-aware diagnostics;
- frozen artifacts;
- fresh/disjoint holdout evaluation support;
- temporal first-seen filtering support.

ML scores are uncalibrated and are not presented as malware probabilities.

The current C=4 candidate is frozen for one final post-freeze temporal measurement before the v0.1.0 release is finalized.

### Analyst workflow

The Streamlit application includes:

- system health and CTI freshness;
- Quick Lookup;
- telemetry analysis;
- priority triage;
- evidence-first investigation;
- source corroboration;
- related-activity graph/context;
- optional local analyst feedback;
- optional local suppression;
- aggregate analysis history in local mode;
- privacy-safe JSON/CSV export;
- model-evaluation views.

### Privacy / release engineering

Implemented safeguards include:

- raw uploaded telemetry not persisted by default;
- raw client/response IPs excluded from portable reports;
- public mode disabling shared history;
- sanitized public-demo/runtime generation;
- non-root Docker packaging;
- secret/local-path release auditing;
- Linux + Windows CI;
- Docker build/health validation;
- dependency auditing.

## Resource boundaries

The Streamlit upload limit is 100 MB.

Runtime analysis is separately bounded to:

- 100,000 events;
- 25,000 unique analysis targets.

The system is intentionally bounded rather than attempting unlimited packet-processing workloads in the browser-driven Streamlit application.

## Release position

Feature development for v0.1.0 is considered complete.

Remaining release tasks are:

- final post-freeze temporal ML evaluation;
- sanitized portfolio screenshots;
- hosted public-mode demo;
- final release checklist;
- GitHub tag/release.

These are release/presentation tasks rather than new core product features.

## Explicit non-goals for v0.1.0

ThreatFusion AI is not intended to be:

- a production SIEM;
- an EDR;
- a full IDS/IPS replacement;
- a packet-forensics suite;
- an automatic incident-response platform;
- a guarantee of maliciousness/benignness;
- an autonomous analyst.

## ML / LLM principle

The current v0.1.0 project does not depend on an LLM for detection.

If an LLM is added in a future version, its role should be explanation/reporting rather than primary detection.

> **ML assists detection. Deterministic CTI remains stronger evidence. An LLM, if added later, explains rather than decides.**
