# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The current unreleased state is the v0.1.0 portfolio-release candidate. The
release date is added only when the final tag/release is created.

### Added

- Multi-source IOC collection and normalization for ThreatFox, URLhaus, and SGB.
- DNS telemetry ingestion for generic CSV, Zeek `dns.log`, Pi-hole FTL, and
  AdGuard Home.
- Deterministic domain, URL-hostname, response-IP, and IPv6-network IOC
  matching with evidence-scope metadata.
- Explainable hybrid assessment combining CTI evidence, ML domain scoring, and
  DNS behavior signals.
- Character n-gram TF-IDF + Logistic Regression development-model workflow,
  trusted local artifact persistence, explicit FPR-budget threshold selection,
  and source-aware evaluation.
- Fresh/disjoint frozen-model holdout evaluation, long-tail benign evaluation,
  confidence intervals, base-rate caveats, malicious IOC timing preservation,
  and explicit post-freeze first-seen filtering support.
- Streamlit analyst dashboard, privacy-safe JSON/CSV report export, and local
  SQLite CTI/history persistence.
- Analyst feedback, prior-review context, expiring local suppression, and
  explainable related-activity analysis.
- Public-mode privacy controls, sanitized deployment bundles, non-root Docker
  packaging, and scheduled CTI refresh guidance.
- Ubuntu Ruff/pytest/coverage/pip-audit CI, Windows pytest CI, Docker
  build/health checks, and public-release tracked-tree/Git-history auditing.
- `SECURITY.md`, MIT `LICENSE`, data-source attribution notes, and release
  readiness documentation.

### Changed

- ML terminology uses `ml_score` rather than implying calibrated malware
  probability.
- The v1 scope is frozen around final evaluation, portfolio presentation,
  hosted demo, and release instead of expanding into API/streaming/Suricata,
  SOC integrations, LLM features, or neural-network model families.
- The runtime default remains the earlier trusted artifact while experimental
  candidates are evaluated separately and never auto-promoted.
- Documentation now distinguishes the completed historical character-only C=4
  holdout, the rejected reconstructed lexical candidate, and the improved
  augmented lexical candidate measured with a fresh-disjoint protocol.

### Release gates still open

- Decide whether the improved augmented lexical candidate should receive a
  stronger temporal collection before any runtime promotion.
- Capture sanitized screenshots from a real application run.
- Publish and verify the hosted public-mode demo.
- Complete final manual release verification, then create the `v0.1.0` tag
  and GitHub release.
