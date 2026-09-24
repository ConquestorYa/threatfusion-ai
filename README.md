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
- trusted local model artifact persistence
- DNS behavior aggregation
- explainable hybrid verdicts
- reusable runtime analysis pipeline
- SQLite CTI cache
- privacy-conscious SQLite analysis history
- Streamlit analysis dashboard
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

Run the dashboard:

```powershell
streamlit run streamlit_app.py
```

The DNS CSV schema is:

```text
timestamp,client_ip,query_name,query_type,response_ip
```

Only `query_name` is required.

## Privacy defaults

Uploaded DNS telemetry is analyzed in memory. The current dashboard does not
persist raw uploaded DNS rows or client IP values. Saving analysis history is
explicit and stores aggregate/per-domain findings only.

Threat URLs and domains received from CTI feeds are treated as inert data; the
analysis pipeline does not visit or resolve them.

## ML status

The selected development candidate is character 2-6 TF-IDF with sublinear term
frequency plus balanced Logistic Regression.

The current local artifact uses validation-selected score thresholds at 1%,
5%, and 10% false-positive-rate budgets. These scores are model decision
outputs, not literal probabilities that a domain is malware.

The current evaluation is development-only. Final performance claims require a
fresh source-aware or time-aware holdout.

## Project direction

Remaining planned work includes:

- stronger final holdout evaluation
- campaign clustering / relationship analysis
- deployment packaging for a hosted demo
- optional analyst feedback
- optional LLM-generated explanations and reports

Principle:

**ML detects. LLM explains.**
