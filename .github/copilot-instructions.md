# ThreatFusion AI - Copilot Instructions

## Project Goal

ThreatFusion AI is a local network investigation tool for Zeek users (early
prototype; see docs/dev/PRODUCT_PLAN.md). It reads completed Zeek connection and
DNS logs, matches destinations against public CTI sources and flags device →
destination groups with explainable behavior checks.

The system should:

- Normalize threat intelligence from multiple sources (SGB, ThreatFox, URLhaus).
- Import completed Zeek logs safely and within explicit bounds.
- Flag connection and DNS groups with reasons and coverage limits, never verdicts
  presented as proof.
- Keep all telemetry local; suspicious destinations are data, never visited.
- Measure usefulness on predeclared, untouched evidence (see AGENTS.md).
- Present findings in the local Streamlit workspace.

ML (a lexical domain score) is experimental and off by default.

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