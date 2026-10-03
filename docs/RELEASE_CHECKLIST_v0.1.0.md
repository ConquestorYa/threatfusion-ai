# Release Checklist — v0.1.0

Use this checklist before creating the `v0.1.0` portfolio release.

## 1) Repository and legal readiness

- [x] **License decision confirmed** and MIT `LICENSE` file added.
- [x] README and docs reflect the current implementation/evaluation status.
- [x] Third-party data-source attribution and redistribution notes reviewed in `docs/DATA_SOURCES.md`.

## 2) Security and privacy readiness

- [x] `SECURITY.md` present and reviewed.
- [x] Public-release audit passes on tracked files.
- [x] Full reachable Git-history audit passes for known secret/privacy patterns.
- [x] Public release content excludes local paths, analyst history, and private telemetry.

## 3) Quality gates

- [x] Ruff passes.
- [x] Pytest passes.
- [x] Docker build/health workflow remains passing in CI.
- [x] Synthetic demo image, rate/body limits and real WebSocket UI session
  verified locally; new CI job added for this boundary.
- [x] Render Blueprint validated against the official JSON Schema.
- [x] Implementation commit `dc03e36` passed Linux/Windows and both container
  jobs on GitHub (CI run `37159279681`).

## 4) Release notes and versioning

- [x] `CHANGELOG.md` updated for `0.1.0`.
- [x] Release notes drafted from changelog highlights.
- [ ] Reconfirm final release timing after local security review; earlier
  portfolio/hosting plans do not authorize deployment during development.

## 5) Portfolio presentation assets

- [x] Sanitized screenshots captured and saved under `docs/screenshots/`.
- [x] README screenshot links resolved (no broken image references).
- [x] Fast demo path validated with inert demo data only.

## 6) Final manual verification

- [x] Threat IOC values are handled as inert data only (no IOC browsing/resolution behavior introduced).
- [x] Public-mode behavior verified (`THREATFUSION_PUBLIC_MODE=1`).
- [x] Explicit CTI-only CLI/dashboard operation verified with absent model.
- [ ] Local security review and remediation completed.
- [ ] Any later hosted verification explicitly requested by the user.
- [x] Remaining known TODOs are explicitly documented (no invented permissions/claims).

## 7) Current ML release gate

- [x] Reconstructed lexical C=4 artifact evaluated on a new untouched
	post-freeze holdout; result retained as aggregate-only evidence.
- [x] Reconstructed development snapshot and lexical C=4 artifact generated
	from the refreshed CTI cache; kept explicitly development-only.
- [x] Untouched CESNET benign window generated with deterministic offset
	`80,000` and retained size `20,000`.
- [x] ThreatFox, URLhaus and SGB caches refreshed after the reconstructed
	lexical artifact freeze cutoff (`2026-10-02T21:55:51Z`).
- [x] Indexed CTI lookup coverage audited without contacting IOC destinations.
- [x] Earlier character-only C=4 temporal holdout retained as historical
	evidence only.
- [x] Reconstructed temporal lexical C=4 candidate remains separate from the
	runtime default because its holdout false-positive rate was operationally
	unusable.
- [x] Augmented lexical C=4 fresh-disjoint evaluation completed with aggregate
	metrics and its non-temporal limitation documented.
- [x] Promotion decision recorded: keep the augmented candidate experimental
  and require stronger untouched temporal evidence before runtime promotion
  (DEC-082).
- [x] Original configured runtime artifact absence and synthetic demo distinction
  documented in the handoff.
- [x] Fresh-disjoint persistence, report provenance and binary/local-artifact
  release safeguards covered by regression tests.
- [x] Independent follow-up collection checked temporal readiness: five
  development-disjoint SGB domains, kept unscored; original data preserved.
- [ ] Collect enough untouched temporal evidence with broader source coverage
  before revisiting promotion; do not reuse inspected holdouts for selection.
