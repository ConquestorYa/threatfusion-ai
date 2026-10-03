# ThreatFusion AI v0.1.0 — Release Notes Draft

> **Status: development / security review.** Completed features remain under
> local verification and security review. Public hosting requires a new explicit
> user request. Publishing verified source changes to GitHub does not authorize
> deploying a site or finalizing this draft as a release.

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

The private/local upload limit is 100 MB; the synthetic public-demo image uses
20 MB. Runtime analysis remains bounded to 100,000 events and 25,000 unique targets.

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

An explicit CTI-only dashboard/CLI mode supports matching and DNS behavior when
the trusted original artifact is unavailable. It skips ML loading and scoring,
labels the mode clearly, and disables model-dependent history. Experimental
artifacts are never selected as an automatic fallback.

The dedicated synthetic public-demo image and free Render Blueprint add request,
connection and upload limits, an independent read-only model pin, and real
Streamlit-session CI verification without uploading local feed data or models.

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

The C=4 artifact was frozen before the final untouched post-freeze temporal holdout.

The final protocol required post-freeze ThreatFox / URLhaus / SGB cache
refreshes and a separate untouched confirmed-benign CESNET sampling window.
Exact development-domain overlap was removed again before scoring. This kept
the malicious temporal-recall question and real-traffic benign-FPR question
inside one frozen-threshold evaluation without reusing the CESNET development
sample.

The final retained holdout contained 240 post-freeze malicious domains and
19,912 confirmed-benign CESNET domains. Frozen-threshold results were:

- High: 26.67% recall, 0.56% FPR, 36.57% holdout precision
- Medium: 50.42% recall, 2.35% FPR, 20.54% holdout precision
- Low: 55.42% recall, 4.08% FPR, 14.07% holdout precision

Source recall showed materially stronger performance on the retained SGB
samples than on the much smaller retained URLhaus subset. ThreatFox contributed
no eligible retained domain/URL sample to this temporal holdout, so a ThreatFox
source-recall value is not reported.

The final result supports keeping lexical ML as an auxiliary signal. Medium and
Low false-positive rates on untouched CESNET remain too high for the
character-only C=4 model to be described as a standalone malicious-domain
detector, while High is more conservative but still misses most post-freeze
malicious domains.

After this historical holdout, a bounded lexical-feature extension was
selected as `lr_char_2_6_plus_lexical_c4`. A separately reconstructed artifact
was evaluated on a new untouched post-freeze holdout, but its false-positive
rate was too high for promotion. The runtime default remains unchanged, and
the result must not be presented as a standalone malicious-domain detector.

A follow-up hard-negative development iteration added a separate CESNET
window and produced an augmented lexical C=4 artifact. Its fresh-collection
disjoint evaluation measured 60.62%/78.75%/81.87% recall at
0.85%/1.95%/2.62% FPR for the high/medium/low tiers. This is a meaningful
improvement, but it is not strict first-seen temporal evidence, so the
artifact remains an auxiliary candidate and is not the runtime default.

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

- Augmented lexical runtime promotion is deferred pending stronger untouched
  temporal evidence. The initial cache retained zero post-cutoff malicious
  domains; a subsequent independent SGB refresh found five development-disjoint
  domains, kept unscored. This small single-source collection is insufficient
  promotion evidence.
- The original default artifact is absent from the current checkout. The
  generated synthetic demo artifact does not supply final ML evidence.
- Aggregate reports display their actual protocol and, for new schema-v4
  reports, exact artifact identity; loading a report does not promote a model.

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
