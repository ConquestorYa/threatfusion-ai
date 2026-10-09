# ThreatFusion AI - Copilot Instructions

## Project Goal

ThreatFusion AI is a local-first network investigation and triage tool (early prototype; see docs/PRODUCT_PLAN.md) that combines multiple public cyber threat intelligence sources with user-provided network/DNS telemetry.

The system should:

- Normalize threat intelligence from multiple sources.
- Match known indicators of compromise against DNS telemetry.
- Use machine learning to identify previously unseen suspicious domains.
- Group related indicators into possible threat campaigns.
- Produce explainable risk scores.
- Evaluate ML models using appropriate metrics.
- Present findings through a web dashboard.

## Planned Stack

- Python 3.12
- pandas
- scikit-learn
- Streamlit
- Plotly
- SQLite
- pytest
- Ruff

## Development Rules

- Prefer simple and understandable implementations.
- Do not introduce frameworks or dependencies unless necessary.
- Do not execute or visit malicious URLs.
- Treat threat URLs, domains, IP addresses, and hashes as data only.
- Never hardcode API keys, passwords, tokens, or secrets.
- Add type hints to new Python functions where practical.
- Add tests for data-processing and ML-related logic.
- Keep modules focused and reasonably small.
- Do not silently change the project architecture.
- Explain significant architectural changes before implementing them.
- Prefer reproducible ML experiments.
- Avoid data leakage when creating ML train/test datasets.
- Security detections must not rely on an LLM as the sole decision maker.

## AI Architecture Principle

Machine learning performs detection and classification.

LLMs may be used later for explanation and analyst-facing report generation, but not as the primary malicious-domain detection engine.