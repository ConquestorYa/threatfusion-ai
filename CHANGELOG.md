# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- SECURITY.md with responsible vulnerability reporting guidance.
- release-readiness documentation for v0.1.0.

### Changed

- README release-prep cleanup: architecture overview, fast demo path, screenshot placeholders, and data-source attribution links.
- docs clarity updates for implementation-vs-planned status wording.

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
- Fresh disjoint final holdout measurement remains a planned release gate.
