# ThreatFusion AI v0.1.0 — Release Notes Draft

> **Status: release candidate.** Core feature development is complete. Do not publish these notes as the final GitHub release until the remaining temporal ML measurement, sanitized screenshots, hosted demo, and manual release checks are complete.

## Overview

ThreatFusion AI is an educational / portfolio cyber threat-intelligence and network-telemetry analysis platform.

It combines:

- deterministic multi-source CTI evidence;
- passive URL/domain/IP lookup;
- automatic telemetry ingestion;
- an auxiliary lexical ML signal for unseen domains;
- DNS behavior indicators;
- analyst-focused investigation views;
- privacy-conscious local persistence and export.

The project is intentionally positioned as a security-analysis prototype rather than a production SIEM, EDR, or guaranteed malware detector.

## Highlights

### Multi-source CTI

- ThreatFox current/full IOC collection
- URLhaus full malware-URL collection
- PhishTank verified-online public phishing feed
- T.C. Siber Güvenlik Başkanlığı (SGB)
- local SQLite lifecycle/cache layer
- indexed URL/domain/IP Quick Lookup
- stale-source visibility and scheduled refresh support
- previous healthy snapshot preserved when refresh fails

### Passive Quick Lookup

Single-target lookup supports:

- URL;
- domain;
- IPv4/IPv6 address.

The workflow does not visit the URL, resolve the hostname, or download remote content.

### Automatic telemetry ingestion

The Streamlit dashboard can auto-detect:

- CSV / TSV / TXT;
- XLSX / XLS;
- Zeek <code>dns.log</code>;
- Zeek <code>conn.log</code>;
- PCAP / PCAPNG / CAP classic UDP DNS;
- Suricata EVE JSON / JSONL;
- Pi-hole FTL SQLite;
- AdGuard Home query logs;
- dnstop domain summaries.

The upload limit is 100 MB. Runtime analysis remains bounded to 100,000 events and 25,000 unique targets.

### Explainable analysis

ThreatFusion combines:

- exact/contextual CTI evidence;
- domain ML score/tier;
- DNS behavior context;
- analyst review state.

Hybrid verdicts remain explainable:

- <code>known_threat</code>
- <code>high_risk</code>
- <code>review</code>
- <code>low</code>

Exact known-domain evidence is intentionally stronger than URL-hostname/response-IP context, ML, or behavior heuristics.

### Analyst workflow

The dashboard includes:

- priority triage;
- evidence-first investigation;
- multi-source corroboration;
- related-activity context;
- local analyst feedback;
- local suppression with optional expiry;
- saved aggregate analysis history in local mode;
- model-evaluation view;
- privacy-safe JSON/CSV export.

### Release engineering

- Python 3.12 package layout
- Windows + Ubuntu pytest coverage
- Ruff
- <code>pip-audit</code>
- Docker build + Streamlit health check
- non-root container
- public mode
- sanitized demo/runtime generation
- public-release secret/local-path audit

## ML evaluation position

Known IOC evidence remains stronger than the lexical ML signal.

The original model exposed excessive false positives on long-tail benign CESNET data. A CESNET-augmented v2 candidate substantially reduced false positives, but fresh-holdout malicious recall fell too far to justify promotion.

A bounded regularization experiment kept the same character 2–6 TF-IDF + balanced Logistic Regression family and compared only <code>C=0.5, 1, 2, 4</code>.

The C=4 candidate improved the development medium operating-point recall from 20.22% to 25.52% while development-test FPR moved from 0.52% to 0.60%.

The C=4 artifact is frozen for one final untouched post-freeze temporal holdout.

The final protocol now requires post-freeze ThreatFox / URLhaus / SGB cache
refreshes and a separate untouched confirmed-benign CESNET sampling window.
Exact development-domain overlap is removed again before scoring. This keeps
the malicious temporal-recall question and real-traffic benign-FPR question
inside one frozen-threshold evaluation without reusing the CESNET development
sample.

**Final temporal measurement: pending before release.**

No additional v1 model family or threshold tuning is planned after that measurement.

## Security and privacy

- uploaded telemetry is processed locally / in memory by default;
- raw uploaded telemetry rows are not persisted in saved analysis history;
- portable reports exclude raw client/response IP values;
- threat indicators are treated as inert data and are not visited or resolved;
- public mode disables shared history saving/browsing;
- public deployment uses sanitized runtime assets;
- feed credentials belong in maintenance jobs / secret managers;
- third-party live feed dumps are not committed to the repository.

## Known limitations

- ML scores are uncalibrated scores, not literal malware probabilities;
- model performance depends on source mix, time and base rates;
- temporal first-seen filtering reduces one leakage risk but does not prove campaign/family independence;
- behavior heuristics provide context, not malware proof;
- PCAP support extracts classic UDP/53 DNS and does not claim DoH/DoT decryption;
- Zeek conn.log analysis is destination-IP CTI context, not domain reconstruction;
- the project is an educational / portfolio prototype, not a production SOC platform.

## Deferred beyond v1

The following remain intentionally outside v0.1.0:

- full API service;
- watch-folder / continuous streaming ingestion;
- STIX/MISP/webhook SOC integrations;
- LLM analyst reporting;
- neural-network / transformer detection models;
- autonomous incident response.

Suricata file ingestion is **already implemented** in v0.1.0 and is no longer a deferred item.
