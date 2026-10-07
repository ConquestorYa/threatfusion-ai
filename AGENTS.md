# Project working instructions

## Product direction and continuation

- Start new development sessions with `docs/PRODUCT_PLAN.md`, then
  `docs/PROJECT_CONTEXT.md`, the newest `docs/RELEASE_HANDOFF.md` section and
  the relevant feature/ML/data contracts. The product plan is the current
  ordered work queue; older experiment "Next" notes are historical.
- Keep the local web analyst workspace and Linux automation interface. Focus
  on useful explainable Zeek/CTI client-level triage; Quick Lookup is supporting.
  RITA is an external comparison baseline, not an integrated runtime dependency.
- Preserve user changes and check actual source/local assets before resuming.
  Update plan/checkpoint/context/handoff/changelog after completed increments.
  Do not mark manual acceptance, detection efficacy or a planned integration
  complete from synthetic/unit checks alone.

## Local development and publication

- Develop and test locally. Bind development servers and previews to loopback
  (`127.0.0.1`); do not create public sites, public tunnels, hosted previews or
  deployments unless the user explicitly requests that action.
- Earlier portfolio/release plans do not authorize public deployment. Security
  review and fixes take priority over presentation and hosting.
- The user authorizes publishing completed, working changes to this GitHub
  repository after appropriate verification. Preserve unrelated user changes
  and record results and limitations in the handoff/changelog.
- Before updating a branch connected to hosting, confirm that automatic deploy,
  Blueprint auto-sync and hosted previews cannot trigger publication. If this
  cannot be established, use a separate `local-development/` branch and do not
  merge it into the hosting-connected branch. CI runs on those branches without
  deploying a service.
- The user explicitly requested integration into `main`. A confirmed
  user-suspended service with previews disabled, no new Blueprint resources and
  a `[skip render]` integration commit permits that source-only merge without
  resuming hosting. Recheck service suspension and deployment history after CI.
  Do not treat the merge request as permission to resume or publish a site.
- The Render Blueprint (`render.yaml`) was removed at the user's request
  (DEC-086); do not re-add hosting configuration without a new explicit request.
  On 2026-10-07 the user reported deleting the `threatfusion-ai-demo` web
  service. Until the user confirms the Render Blueprint is deleted too, keep
  `[skip render]` on commits. Never claim external settings changed without
  verifying them.

## Local data and ML evidence

- Keep CTI SQLite caches, database sidecars, domain datasets, CESNET files,
  evaluation files, model binaries, private telemetry and analyst history local
  and ignored. Do not upload them to GitHub, Git LFS, CI or hosting.
- Preserve frozen model identities and thresholds. Do not tune on inspected
  holdouts, present fresh-disjoint results as strict temporal evidence, or
  promote the augmented candidate without the required new untouched evidence.
- Synthetic demo models are presentation assets, not measured runtime models.
  See `docs/ML_DATASET.md`, `docs/PROJECT_CONTEXT.md` and
  `docs/RELEASE_HANDOFF.md` for the current experiment and missing original
  runtime artifact.
