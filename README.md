# ThreatFusion AI

AI-assisted multi-source cyber threat intelligence and DNS threat-analysis platform.

ThreatFusion AI combines public threat intelligence, local DNS telemetry,
machine-learning domain scoring, and explainable DNS behavior signals. It is
designed as a portfolio-quality educational security prototype rather than a
replacement for a production SIEM or EDR.

## What it does

The current runtime flow is:

```text
ThreatFox / URLhaus / SGB
          |
          v
   Local CTI cache
          |
DNS CSV / Zeek dns.log / Pi-hole FTL DB
          -> IOC matching
          + ML domain scoring
          + DNS behavior analysis
          |
          v
  Explainable hybrid verdict
          |
          v
known_threat / high_risk / review / low
```

Exact known-domain IOC matches take precedence and produce the Known Threat
verdict. URL-hostname and response-IP IOC matches remain deterministic CTI
context but do not, by themselves, prove that the queried domain is malicious.
ML is used as an additional signal for previously unseen domains, and DNS
behavior can strengthen an assessment or trigger review. Behavioral signals are
not treated as proof of malware.

## Implemented

- ThreatFox, URLhaus, and SGB collectors
- common IOC model, normalization, and correlation
- DNS CSV, Zeek `dns.log`, and in-memory Pi-hole FTL database ingestion with aggregate input-quality diagnostics
- known domain / URL-hostname / response-IP / IPv6-network matching with evidence-scope metadata
- reproducible ML dataset snapshots
- character n-gram TF-IDF + Logistic Regression development model
- validation-only threshold selection under explicit false-positive budgets
- source-wise ML diagnostics
- frozen-model fresh holdout evaluation workflow and aggregate JSON reporting
- trusted local model artifact persistence
- DNS behavior aggregation
- explainable hybrid verdicts
- reusable runtime analysis pipeline
- SQLite CTI cache
- privacy-conscious SQLite analysis history with local analyst feedback, prior-review context, and expiring local triage suppression
- analyst-focused Streamlit dashboard with priority triage, evidence-first domain investigation, multi-source CTI corroboration, filtered history, and a dedicated model-evaluation view
- explainable related-activity clustering
- privacy-preserving relationship graph
- public-mode privacy controls and non-root Docker packaging
- privacy-safe JSON/CSV analysis report export with spreadsheet-safe CSV cells
- bounded runtime analysis, IDNA/punycode canonicalization, and strict ML eligibility filtering for valid public-domain candidates, with explicit Not-scored presentation
- CTI freshness/staleness visibility
- sparse evidence-driven related-activity pair generation with bounded and optimized timestamp comparison
- pytest + Ruff CI

## Local dashboard

The dashboard expects:

- a trusted local model artifact at `data/models/development-001`
- a local SQLite database at `data/threatfusion.sqlite`

Refresh the CTI cache (the refresh is rejected before cache replacement if an expected source unexpectedly returns zero records):

```powershell
$env:THREATFOX_AUTH_KEY="..."
$env:URLHAUS_AUTH_KEY="..."
python scripts\refresh_cti_cache.py
```

Generate a safe local demo DNS CSV:

```powershell
python scripts\generate_demo_dns_csv.py
```

This creates `data/demo/demo_dns.csv`. If the local CTI cache contains at
least one domain IOC, the demo includes one cached IOC value as inert text so
the known-threat matching path can be exercised. The generator does not print,
visit, or resolve that IOC.

Run the dashboard:

```powershell
streamlit run streamlit_app.py
```

Run the same local detector from the CLI:

```powershell
python scripts\analyze_dns.py data\demo\demo_dns.csv --format dns-csv --json-output data\demo\analysis.json
```

The CLI also accepts `--format zeek` and `--format pihole`. It reads the
existing local CTI cache and trusted model artifact; it does not refresh feeds
or require API credentials.

Supported telemetry formats are generic DNS CSV, Zeek `dns.log`, and an
uploaded Pi-hole FTL SQLite query database.

The generic DNS CSV schema is:

```text
timestamp,client_ip,query_name,query_type,response_ip
```

Only `query_name` is required for generic CSV. Zeek imports use the standard
`#fields` header and map `query`, `ts`, `id.orig_h`, `qtype_name`, and
`answers` when available. Pi-hole imports read the standard `queries` view
from an uploaded FTL SQLite database entirely in memory; the upstream
`forward` value is not treated as a DNS response IP. The Streamlit uploader is
configured with a 10 MB maximum file size.

## Privacy defaults

Uploaded DNS telemetry is analyzed in memory. The current dashboard does not
persist raw uploaded DNS rows or client IP values. Saving analysis history is
explicit and stores aggregate/per-domain findings only. In local mode, an
analyst can add a Confirmed Threat / Benign / Uncertain label and an optional
short note to a saved finding. Later analyses can surface the most recent
local review for the same domain. Local mode can also suppress a domain from
the priority queue with a reason and optional expiry. Feedback and suppression
do not alter the original ThreatFusion verdict, ML score, or model training.

Threat URLs and domains received from CTI feeds are treated as inert data; the
analysis pipeline does not visit or resolve them.

## ML status

The selected development candidate is character 2-6 TF-IDF with sublinear term
frequency plus balanced Logistic Regression.

The current local artifact uses validation-selected score thresholds at 1%,
5%, and 10% false-positive-rate budgets. These scores are model decision
outputs, not literal probabilities that a domain is malware.

The current model artifact remains development-only until a separately
collected disjoint holdout is measured. When that evaluation is run with
`--json-output data/evaluation/final_holdout.json`, the Streamlit
`Model evaluation` tab displays the frozen operating-point metrics and
source-wise malicious recall.

## Project direction

Remaining planned work includes:

- collect and run the fresh final holdout dataset
- deploy the prepared container to a hosted environment/domain
- optional LLM-generated explanations and reports

Principle:

**ML detects. LLM explains.**


## Hosted demo preparation

The repository includes a non-root Dockerfile and an explicit public mode:

```text
THREATFUSION_PUBLIC_MODE=1
```

Public mode disables shared analysis-history saving/browsing so anonymous
visitors cannot inspect another visitor's persisted domain findings.

Runtime paths can be configured with:

```text
THREATFUSION_DB_PATH
THREATFUSION_MODEL_DIR
THREATFUSION_EVALUATION_REPORT
```

Before hosting, create a sanitized runtime bundle instead of mounting the
developer data directory:

```powershell
python scripts\prepare_deployment_bundle.py \
  --evaluation-report data\evaluation\final_holdout.json
```

This copies only the CTI cache and trusted ML artifact into
`data/deployment/runtime`; saved local analysis history and dataset snapshots
are not included.

See `docs/DEPLOYMENT.md` for container and hosting guidance.
