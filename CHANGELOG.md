# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SECURITY.md with responsible vulnerability reporting guidance.
- MIT LICENSE for the project source code.
- release-readiness documentation for v0.1.0.
- public-release audit tooling for known secret formats, local user paths, and reachable Git history.
- malicious IOC timing persistence and first-seen-filtered temporal holdout evaluation support.
- long-tail benign development/evaluation workflow and lower operational FPR experiments.

### Changed

- README and architecture documentation now reflect completed holdout work, the non-promoted v2 model result, and the frozen v1 scope.
- ML terminology uses score rather than calibrated malware probability semantics.
- CI covers Ubuntu quality/security checks, Windows pytest, Docker health, and public-release history auditing.

## [0.1.0] - 2026-09-25

### Added

- Initial educational ThreatFusion AI release structure.
- Multi-source IOC collection and normalization (ThreatFox, URLhaus, SGB).
- DNS telemetry ingestion (generic CSV, Zeek dns.log, Pi-hole FTL, AdGuard Home).
- Deterministic IOC matching and explainable hybrid assessment workflow.
- Development ML pipeline, artifact persistence, and evaluation/reporting workflows.
- Streamlit dashboard, privacy-safe report export, and local SQLite persistence layers.
- Non-root Docker packaging and public-mode privacy controls.

### Notes

- License selection is pending repository-owner decision before any public release.
- Fresh/disjoint holdout measurement has been completed; a timing-preserving
  first-seen-filtered measurement remains before any strict temporal claim.
