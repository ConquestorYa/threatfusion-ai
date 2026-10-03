# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The current unreleased state is the v0.1.0 portfolio-release candidate. The
release date is added only when the final tag/release is created.

### Added

- Explicit CTI-only dashboard/CLI operation when a trusted ML artifact is
  unavailable, with disabled ML scoring and provenance-dependent history.
- Synthetic-only public-demo Docker image and free Render Blueprint, independent
  read-only model pin, Nginx request/connection/upload limits and supervised
  shutdown. CI checks the generated runtime and proxy behavior without private
  data or feed credentials.
- Artifact SHA-256 identity in schema-v4 aggregate ML reports, with legacy
  schema-v1/v2/v3 report support and collection-provenance validation.
- Fresh-disjoint builder regression coverage for domain separation, empty
  classes, post-cutoff refreshes, existing-output preservation and inert output.
- Release audit rejection of local dataset/cache/model paths, including binary
  artifacts in the tracked tree and reachable history; SQLite sidecar ignores.

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

- Development remains local; public hosting requires a new explicit user
  request. Verified source updates can still be published to GitHub. The
  retained Render Blueprint disables automatic deploy and previews; CI also
  supports separate `local-development/` branches to avoid an active main-branch
  hosting integration. Existing service suspension and Blueprint Auto Sync
  must be handled and verified separately.
- Fresh-disjoint snapshots now remove malicious and benign development overlap
  before persistence and use the canonical protocol identifier.
- The evaluation dashboard describes each report's actual temporal protocol,
  cutoff and artifact identity. Loading a report never promotes its artifact.
- Final evaluation rejects synthetic demo artifacts, mismatched recorded
  artifact/development provenance and missing/changed recorded temporal cutoffs.
- Augmented runtime promotion is deferred pending stronger untouched temporal
  evidence; the missing original default artifact is distinguished from the
  separately generated synthetic demo runtime.
- Independent follow-up CTI collection found five unscored post-cutoff SGB
  domains. Original local data remains unchanged; this readiness count does not
  replace the fresh-disjoint result or justify promotion.

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

- Collect stronger untouched temporal evidence before reconsidering augmented
  runtime promotion; the current decision is to retain it experimentally.
- Complete local security review and remediation. Public hosting is deferred
  unless the user explicitly requests it again.
- Complete final manual release verification, then create the `v0.1.0` tag
  and GitHub release.
