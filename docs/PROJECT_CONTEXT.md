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
- IOC correlation through `IOCGroup` and `correlate_iocs()`, which groups equivalent IOCs while preserving all original source records.
- A ThreatFox collector for recent API IOC data, including conservative type mapping and timestamp/tag parsing.
- A URLhaus collector for the recent CSV export, including named-column discovery and malformed-row handling.
- An SGB collector using the official T.C. Siber Guvenlik Baskanligi malicious-address API, with domain, URL, IPv4, and IPv6 mapping into `IOCRecord`. IPv6 network/CIDR records that do not fit the current IOC model are preserved as `IOCType.UNKNOWN`, and retrieval is safe and bounded through page-based requests.
- DNS telemetry ingestion via `DNSEvent` and `parse_dns_csv()`, with evidence-preserving field parsing and local-only CSV handling.
- Known IOC matching through `DNSIOCMatch` and `match_dns_events()`, which compares DNS queries and responses against IOC records while preserving the original evidence objects.
- Reproducible malicious-domain ML dataset preparation, stratified development splitting, local snapshot persistence, and pinned Tranco acquisition.
- A baseline malicious-domain classifier using character n-gram TF-IDF with Logistic Regression, evaluated with precision, recall, F1, false-positive rate, and confusion-matrix counts.
- A high-recall development evaluation using balanced Logistic Regression plus validation-only threshold selection.
- A small classical-model comparison that selects thresholds under explicit validation false-positive-rate budgets before measuring the shared development test split.
- Source-wise malicious recall diagnostics that show how ThreatFox, URLhaus, SGB, or other retained malicious sources behave under the same validation-selected thresholds.
- A frozen-model fresh holdout evaluator that removes all development-snapshot domain overlap, measures the unchanged artifact thresholds on a separately collected later snapshot, and can persist an aggregate JSON evaluation report.
- DNS behavior aggregation for query volume, client spread, response-IP diversity, query-type diversity, and observation span.
- An explainable hybrid domain assessment that combines known IOC evidence, ML probability tiers, and local DNS behavior into known_threat / high_risk / review / low verdicts.
- Local persistence and trusted loading of the selected development ML pipeline together with validation-selected high / medium / low thresholds, plus normalized runtime probability inference.
- A reusable runtime analysis pipeline that connects DNS CSV / DNSEvent input, known IOC matching, persisted ML inference, DNS behavior aggregation, and explainable hybrid verdicts in one local workflow.
- Privacy-conscious SQLite analysis history that stores run summaries and per-domain findings without retaining raw uploaded DNS rows or client IP values by default, plus local analyst feedback labels/notes for saved findings.
- A local SQLite CTI cache plus explicit refresh CLI, allowing ThreatFox, URLhaus, and SGB data to be refreshed separately from user analysis and then loaded locally by the runtime pipeline.
- A Streamlit MVP with DNS CSV upload, separate event/domain metrics, domain-level verdict distribution, human-readable evidence labels, per-domain detail inspection, known IOC evidence, possible related-activity groups, a privacy-preserving relationship graph, model-evaluation reporting, CTI cache status, and opt-in aggregate analysis history.
- Explainable related-activity clustering that groups suspicious domains only when local DNS telemetry shows a shared client or shared response IP; time proximity is supporting context rather than proof.
- Public-deployment preparation with environment-configurable runtime paths, a public mode that disables shared analysis history, non-root Docker packaging, and a sanitized deployment-bundle builder that copies only the CTI cache plus trusted ML artifact.
- Privacy-safe JSON and CSV report export for the current in-memory analysis, containing aggregate/per-domain findings without raw DNS rows or client/response IP values.
- Automated pytest tests for the model, normalization, correlation, collectors, DNS ingestion, matching, ML dataset, snapshot, split, and baseline evaluation behavior.
- Ruff checks for code quality.
- Analyst-feedback regression tests covering saved-run/domain isolation,
  legacy SQLite history migration, bounded notes, unchanged detector output,
  and the local/public Streamlit workflow.
- Real live-data validation for the ThreatFox, URLhaus, and SGB collectors in addition to network-free automated tests.

DNS telemetry ingestion includes:

- `DNSEvent` model
- CSV parsing for `timestamp`, `client_ip`, `query_name`, `query_type`, and `response_ip`
- `query_name` evidence preserved verbatim from the CSV input
- optional timestamp/client IP/query type/response IP handling
- local-only parsing with no DNS or network requests performed

Known IOC matching includes:

- `DNSEvent` matched against `IOCRecord`
- DOMAIN IOC matching by normalized DNS query
- URL IOC hostname matching using local `urllib.parse` logic only
- IPv4 / IPv6 IOC matching against `response_ip`
- multiple CTI source records preserved as separate evidence matches
- malformed IOC values ignored safely without breaking the batch

Threat URLs, domains, IP addresses, and hashes are treated strictly as data. The collectors and DNS parser do not visit, resolve, open, or follow IOC URLs returned by feeds or query values from telemetry. Authenticated feed requests are limited to their official collection endpoints, and collector tests use injected fake sessions.

## Planned Core Features

The following capabilities are planned and are not implemented in the current repository:

- Broader multi-source correlation workflows.
- Collection and one-time measurement of a fresh final holdout snapshot using the implemented frozen-model evaluator.
- Optional LLM-generated analyst reports.

## ML / LLM Principle

Machine Learning is intended to perform detection and classification, including malicious-domain classification and clustering or campaign discovery. These capabilities should be measurable with precision, recall, F1 score, and false-positive rate.

An LLM may be used later as an optional explanation and analyst-reporting layer. It must not act as the primary malicious-domain detector.

**ML detects.  LLM explains.**
