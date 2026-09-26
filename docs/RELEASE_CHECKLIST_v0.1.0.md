# Release Checklist — v0.1.0

Use this checklist before creating the `v0.1.0` portfolio release.

## 1) Repository and legal readiness

- [x] **License decision confirmed** and MIT `LICENSE` file added.
- [x] README and docs reflect the current implementation/evaluation status.
- [ ] Third-party data-source attribution and redistribution notes reviewed in `docs/DATA_SOURCES.md`.

## 2) Security and privacy readiness

- [x] `SECURITY.md` present and reviewed.
- [x] Public-release audit passes on tracked files.
- [x] Full reachable Git-history audit passes for known secret/privacy patterns.
- [ ] Public release content excludes local paths, analyst history, and private telemetry.

## 3) Quality gates

- [x] Ruff passes.
- [x] Pytest passes.
- [x] Docker build/health workflow remains passing in CI.

## 4) Release notes and versioning

- [x] `CHANGELOG.md` updated for `0.1.0`.
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
