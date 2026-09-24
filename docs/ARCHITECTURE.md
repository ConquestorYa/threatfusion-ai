# Architecture

This document distinguishes the current implementation from the planned system. The current architecture includes IOC collection, correlation, DNS telemetry ingestion, in-memory known-IOC matching, reproducible ML dataset snapshots, persisted development-model inference, DNS behavior aggregation, and explainable hybrid runtime assessment. Campaign clustering, SQLite application persistence, final holdout evaluation, and the Streamlit dashboard remain planned.

## Current Data Flow

```mermaid
flowchart LR
    ThreatFox[ThreatFox collector] --> Record[IOCRecord]
    URLhaus[URLhaus collector] --> Record
    SGB[SGB collector] --> Record
    Record --> Correlate[correlate_iocs]
    Correlate -. uses internally .-> Normalize[normalize_ioc_value]
    DNSCSV[DNS CSV telemetry] --> DNS[DNSEvent]
    DNS --> Match[match_dns_events]
    Record --> Match
    Match --> MatchResult[DNSIOCMatch evidence]
```

ThreatFox, URLhaus, and SGB are implemented external sources that produce `IOCRecord` objects. `correlate_iocs()` performs grouping and internally uses `normalize_ioc_value()` to compute canonical comparison values. It groups equivalent records while retaining all original evidence records; it does not rewrite all `IOCRecord` objects through a separate normalization pipeline.

The DNS ingestion layer parses CSV telemetry into `DNSEvent` objects without performing any network lookup or resolution. The matching layer then compares normalized DNS queries and response IPs against known IOC records while preserving the original `DNSEvent` and `IOCRecord` evidence objects.

The matcher currently supports:

- DOMAIN -> DNS query_name
- URL hostname -> DNS query_name
- IPv4 / IPv6 -> DNS response_ip

Normalization is used for comparison only. URL IOC values are parsed locally with `urllib.parse` and are never visited or resolved. Matching is in-memory and performs no network activity.

## Current ML Development Flow

```mermaid
flowchart LR
    CTI[Collected IOC records] --> Samples[DomainSample dataset]
    Tranco[Pinned Tranco domains] --> Samples
    Samples --> Snapshot[Persisted snapshot]
    Snapshot --> Split[80/20 stratified split]
    Split --> TFIDF[Character n-gram TF-IDF]
    TFIDF --> LR[Logistic Regression]
    LR --> Metrics[Precision / Recall / F1 / FPR]
```

The baseline vectorizer and classifier are fitted after splitting, so held-out
test domains do not influence TF-IDF fitting. The current random stratified
split is explicitly a development baseline rather than the final evaluation
protocol.

## Current Hybrid Analysis Flow

```mermaid
flowchart TD
    CSV[DNS CSV] --> DNS[DNSEvent]
    DNS --> Runtime[Runtime analysis]
    IOC[Already-loaded IOCRecord values] --> Runtime
    Artifact[Trusted local ML artifact] --> Runtime
    Runtime --> Match[Known IOC matching]
    Runtime --> ML[Domain probability inference]
    Runtime --> Behavior[DNS behavior aggregation]
    Match --> Hybrid[Hybrid assessment]
    ML --> Hybrid
    Behavior --> Hybrid
    Hybrid --> Verdict[known_threat / high_risk / review / low]
```

The hybrid assessment is an explainable educational risk layer, not a
calibrated malware probability. Known IOC evidence takes precedence. DNS
behavior can strengthen an assessment or trigger review, but it is not treated
as proof of malware.

## Current Presentation Flow

```mermaid
flowchart TD
    Upload[DNS CSV upload] --> Runtime[Runtime analysis]
    Cache[SQLite CTI cache] --> Runtime
    Model[Trusted local ML artifact] --> Runtime
    Runtime --> Findings[Domain findings]
    Runtime --> Evidence[Known IOC evidence]
    Runtime --> Chart[Verdict chart]
    Runtime -. explicit save .-> History[SQLite analysis history]
    History --> Dashboard[Streamlit history view]
```

## Current Related-Activity Flow

```mermaid
flowchart TD
    Runtime[Runtime analysis] --> Suspicious[Known Threat / High Risk / Review domains]
    Suspicious --> Evidence[Shared client / shared response IP evidence]
    Evidence --> Cluster[Possible related-activity groups]
    Cluster --> Dashboard[Streamlit related-activity view]
```

The related-activity layer is an explainable baseline. A relationship requires
shared local DNS evidence; time proximity is supporting context only. Groups
are presented as possible related activity and do not prove one malware
campaign.

## Planned Analysis Extensions

```mermaid
flowchart TD
    Dashboard[Streamlit dashboard] --> Hosted[Hosted demo packaging planned]
    Eval[Fresh final holdout planned] --> Hosted
```

Fresh source-aware or time-aware final evaluation and hosted deployment
packaging remain planned. Local model artifact persistence,
domain-probability inference, privacy-conscious SQLite analysis history, a
local SQLite CTI cache, and a Streamlit MVP are implemented.

## Current Modules

### `src/threatfusion/models.py`

- Defines `IOCType` for supported indicator categories.
- Defines the `IOCRecord` dataclass and its optional timestamps, threat type, confidence, and tags.

### `src/threatfusion/normalization.py`

- Provides canonical IOC value normalization.
- Lowercases and removes one trailing dot from domains.
- Lowercases hashes.
- Uses Python's `ipaddress` module for IPv4 and IPv6 values.
- Strips surrounding whitespace from URLs and unknown values without making network requests.

### `src/threatfusion/correlation.py`

- Defines `IOCGroup` for a correlated canonical value and its original records.
- Provides `correlate_iocs()`.
- Groups records only when both normalized value and `IOCType` match.
- Preserves every original `IOCRecord`, including duplicate evidence from one source.

### `src/threatfusion/dns.py`

- Defines `DNSEvent` for a DNS observation with optional timestamp, client IP, query type, and response IP.
- Provides `parse_dns_csv()` for safe CSV ingestion using the Python standard library.
- Accepts the project CSV schema: `timestamp,client_ip,query_name,query_type,response_ip`.
- Preserves `query_name` evidence exactly as observed, while trimming surrounding whitespace.
- Validates canonical response IP values with Python's `ipaddress` module and keeps malformed values as `None`.
- Performs no network operations, DNS lookups, or external requests while parsing telemetry.

### `src/threatfusion/matching.py`

- Defines `DNSIOCMatch` for a matched DNS event and IOC record with a simple match type.
- Provides `match_dns_events()` for local in-memory matching.
- Builds lightweight lookup indexes instead of performing a naive full nested scan.
- Matches DOMAIN IOC values against normalized DNS query names.
- Matches URL IOC hostnames against DNS query names using local parsing only.
- Matches IPv4 and IPv6 IOC values against `DNSEvent.response_ip` values.
- Preserves original `DNSEvent` and `IOCRecord` objects as evidence.
- Ignores malformed IOC values without breaking the whole batch.
- Ignores unsupported hash and `UNKNOWN` IOC types for DNS matching.

### `src/threatfusion/dns_behavior.py`

- Aggregates local DNS events by normalized query domain.
- Reports query volume, unique clients, unique response IPs, query types, and
  comparable observation span.
- Preserves the original `DNSEvent` ingestion model and performs no network
  requests or DNS resolution.

### `src/threatfusion/hybrid_assessment.py`

- Combines known IOC match evidence, caller-supplied ML probability tiers, and
  local DNS behavior signals.
- Produces explainable `known_threat`, `high_risk`, `review`, or `low`
  verdicts.
- Requires ML thresholds to be supplied by the caller rather than hardcoding
  snapshot-specific operating points.
- Treats behavior rules as heuristic context, not malware proof.

### `src/threatfusion/ml_dataset.py`

- Extracts normalized malicious domain samples from DOMAIN and URL IOC records.
- Builds benign samples from caller-supplied domain strings.
- Deduplicates at normalized-domain level and gives malicious labels precedence on overlap.

### `src/threatfusion/ml_split.py`

- Provides the deterministic 80/20-style stratified development split.
- Rejects duplicate/conflicting normalized domains and preserves original sample objects.
- Uses a fixed default `random_state=42`.

### `src/threatfusion/ml_snapshot.py` and `ml_snapshot_io.py`

- Assemble reproducible in-memory dataset snapshots with aggregate statistics.
- Persist exact local `dataset.csv` and `metadata.json` experiment snapshots.
- Keep local snapshot data outside Git through `data/snapshots/`.

### `src/threatfusion/ml_baseline.py`

- Builds character 3-5 gram TF-IDF features and a Logistic Regression classifier.
- Fits only on the training side of the existing stratified split.
- Reports precision, recall, F1, false-positive rate, and TN/FP/FN/TP counts.
- Performs no networking and does not depend on live CTI collection during training.

### `src/threatfusion/ml_high_recall.py`

- Uses the same character TF-IDF representation with `class_weight="balanced"`.
- Creates deterministic train, validation, and development-test partitions.
- Fits the representation and classifier on train only.
- Selects operating thresholds on validation only for requested recall targets.
- Measures the selected thresholds on the development-test partition.
- Reports the precision/recall/F1/false-positive tradeoff instead of claiming guaranteed perfect detection.

### `src/threatfusion/ml_fpr_comparison.py`

- Compares three predefined classical text-classification candidates.
- Reuses one shared deterministic train/validation/development-test split.
- Selects candidate thresholds on validation only under explicit false-positive-rate budgets.
- Maximizes recall subject to each validation false-positive-rate limit.
- Applies each selected threshold to the shared development-test split.
- Uses no networking and adds no third-party dependency beyond the existing scikit-learn stack.

### `src/threatfusion/ml_artifact.py`

- Trains the selected development candidate from an existing `DomainSample`
  snapshot using the deterministic train/validation/development-test split.
- Selects high / medium / low operating thresholds on validation only at 1%,
  5%, and 10% FPR budgets.
- Persists the fitted sklearn pipeline to a local joblib file and aggregate
  configuration to JSON metadata.
- Loads only explicitly trusted local artifacts; joblib/pickle files must
  never be accepted from untrusted sources.
- Normalizes runtime domain strings and returns malicious-domain probabilities
  without networking.

### `src/threatfusion/runtime_analysis.py`

- Provides the reusable local orchestration layer for the implemented analysis path.
- Accepts already-loaded DNS events, IOC records, and a trusted local ML artifact.
- Runs known IOC matching, normalized ML probability inference, DNS behavior aggregation, and hybrid assessment without networking.
- Preserves original DNS/IOC evidence and returns matches, probabilities, and per-domain assessments together.
- Provides a convenience helper that starts directly from DNS CSV text.

### `src/threatfusion/cti_cache.py`

- Stores IOCRecord values from ThreatFox, URLhaus, and SGB in a local SQLite cache.
- Replaces one source atomically only after that source's caller-supplied fetch has succeeded.
- Stores source refresh time and aggregate record count.
- Loads cached IOC records deterministically for runtime matching.
- Performs no network activity itself; explicit collector orchestration lives in the refresh CLI.

### `src/threatfusion/persistence.py`

- Stores completed analysis summaries and per-domain hybrid assessment results in SQLite.
- Persists verdict counts, ML output, aggregate DNS behavior, CTI source names, and reason codes.
- Does not persist raw uploaded DNS rows or client IP values by default.
- Uses parameterized SQL, foreign-key constraints, and deterministic read ordering.
- Provides run-history and per-run assessment read helpers for the future dashboard.

### `src/threatfusion/campaign.py`

- Builds local-only relationships among Known Threat / High Risk / Review domains.
- Requires at least one shared client observation or shared response IP to create a relationship.
- Uses time proximity only as supporting context, never as the sole edge condition.
- Builds deterministic connected components and omits singleton groups.
- Returns aggregate relationship counts/reason codes without exposing raw client IP values.

### `src/threatfusion/dashboard.py` and `streamlit_app.py`

- Convert runtime results into deterministic presentation rows and summary counts.
- Provide separate DNS-event and unique-domain metrics so domain-level verdict counts are unambiguous.
- Provide DNS CSV upload, a domain-level Plotly verdict chart, human-readable evidence labels, per-domain detail inspection, domain findings, and known-IOC evidence views.
- Display local CTI cache status and saved analysis history.
- Keep raw uploaded DNS telemetry in memory and make aggregate history saving explicit.
- Do not refresh external CTI sources during interactive user analysis.

### `src/threatfusion/ml_source_diagnostics.py`

- Breaks development-test malicious recall down by retained CTI source.
- Reuses validation-selected thresholds from the FPR-budget comparison.
- Reports total, detected, missed, and recall per source.
- Does not use source-wise development-test results to retune thresholds.

### `src/threatfusion/collectors/threatfox.py`

- Integrates with the ThreatFox Community API for recent IOCs.
- Uses an injected or real `requests.Session` and an Auth-Key header.
- Maps supported domains, URLs, hashes, and valid IPv4/IPv6 `ip:port` values into `IOCRecord` objects.
- Parses optional timestamps and tags conservatively.

### `src/threatfusion/collectors/urlhaus.py`

- Downloads the URLhaus recent CSV export from the official export endpoint.
- Detects named CSV headers, including comment-prefixed headers, and ignores metadata comments.
- Maps valid URL rows into `IOCRecord` objects with timestamps, threat fields, and tags.
- Treats dataset URLs as text only; it does not follow them and sanitizes authenticated request errors.

### `src/threatfusion/collectors/sgb.py`

- Integrates with the official T.C. Siber Guvenlik Baskanligi malicious-address API.
- Performs single-page bounded fetching through a one-based public `page` argument.
- Maps domains, URLs, IPv4, and IPv6 indicators into `IOCRecord` objects.
- Handles IPv6 networks conservatively as `IOCType.UNKNOWN` because the current model represents host IPs, not networks.
- Treats returned IOC values only as data and never requests them.

## Tests and Tooling

The repository uses `pytest.ini` to expose the `src` layout to pytest. The test suite covers the implemented model, normalization, correlation, collectors, DNS ingestion, matching, ML dataset preparation, splitting, snapshot persistence, and baseline model evaluation. Ruff is used for lint checks. Collector tests inject fake sessions and do not make real feed requests. GitHub Actions runs Ruff and pytest automatically on pull requests and pushes to `main`.

## Planned Stack

The planned technology stack is:

- Python 3.12.
- pandas.
- scikit-learn.
- Streamlit.
- Plotly.
- SQLite.
- pytest.
- Ruff.

The stack describes project direction; it does not mean that every planned component is currently implemented or wired into the application.