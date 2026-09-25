# Release Checklist — v0.1.0

Use this checklist before creating the `v0.1.0` portfolio release.

## 1) Repository and legal readiness

- [ ] **License decision confirmed by repository owner** and `LICENSE` file added.
- [ ] README and docs reflect current implementation accurately (no contradictory status notes).
- [ ] Third-party data-source attribution and redistribution notes reviewed in `docs/DATA_SOURCES.md`.

## 2) Security and privacy readiness

- [ ] `SECURITY.md` present and reviewed.
- [ ] Secret scan completed on tracked files (including docs/config changes).
- [ ] Git history reviewed for accidental committed secrets/private telemetry.
- [ ] Public release content excludes local paths, analyst history, and private telemetry.

## 3) Quality gates

- [ ] Ruff passes.
- [ ] Pytest passes.
- [ ] Docker build/health workflow remains passing in CI.

## 4) Release notes and versioning

- [ ] `CHANGELOG.md` updated for `0.1.0`.
- [ ] Release notes drafted from changelog highlights.
- [ ] Tag plan confirmed (`v0.1.0`).

## 5) Portfolio presentation assets

- [ ] Sanitized screenshots captured and saved under `docs/images/`.
- [ ] README screenshot links resolved (no broken image references).
- [ ] Fast demo path validated with inert demo data only.

## 6) Final manual verification

- [ ] Threat IOC values are handled as inert data only (no IOC browsing/resolution behavior introduced).
- [ ] Public-mode behavior verified (`THREATFUSION_PUBLIC_MODE=1`).
- [ ] Remaining known TODOs are explicitly documented (no invented permissions/claims).
