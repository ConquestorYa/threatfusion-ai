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
DNS CSV -> IOC matching
          + ML domain scoring
          + DNS behavior analysis
          |
          v
  Explainable hybrid verdict
          |
          v
known_threat / high_risk / review / low
```

Known IOC matches take precedence. ML is used as an additional signal for
previously unseen domains, and DNS behavior can strengthen an assessment or
trigger review. Behavioral signals are not treated as proof of malware.

## Implemented

- ThreatFox, URLhaus, and SGB collectors
- common IOC model, normalization, and correlation
- DNS CSV ingestion
- known domain / URL-hostname / response-IP matching
- reproducible ML dataset snapshots
- character n-gram TF-IDF + Logistic Regression development model
- validation-only threshold selection under explicit false-positive budgets
- source-wise ML diagnostics
- frozen-model fresh holdout evaluation workflow and aggregate JSON reporting
- trusted local model artifact persistence
- DNS behavior aggregation
- explainable hybrid verdicts
- reusable runtime analysis pipeline with bounded input processing
- runtime ML eligibility gate for non-public DNS namespaces
- SQLite CTI cache
- privacy-conscious SQLite analysis history with local analyst feedback
- Streamlit analysis dashboard with a dedicated model-evaluation view
- explainable related-activity clustering
- privacy-preserving, bounded relationship graph
- public-mode privacy controls and non-root Docker packaging
- privacy-safe JSON and spreadsheet-safe CSV analysis report export
- CTI cache freshness visibility
- pytest + Ruff CI

## Local dashboard

The dashboard expects:

- a trusted local model artifact at `data/models/development-001`
- a local SQLite database at `data/threatfusion.sqlite`

Refresh the CTI cache:

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

The DNS CSV schema is:

```text
timestamp,client_ip,query_name,query_type,response_ip
```

Only `query_name` is required. The Streamlit uploader is configured with a 10 MB maximum file size.

## Privacy defaults

Uploaded DNS telemetry is analyzed in memory. The current dashboard does not
persist raw uploaded DNS rows or client IP values. Saving analysis history is
explicit and stores aggregate/per-domain findings only. In local mode, an
analyst can add a Confirmed Threat / Benign / Uncertain label and an optional
short note to a saved finding. This feedback does not alter the original
ThreatFusion verdict or retrain the model.

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
