# Project working instructions

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
- `render.yaml` is retained for possible future use. Its manual-deploy setting
  does not suspend an existing service or disable dashboard Blueprint auto-sync.
  Never claim those external settings changed without verifying them.

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
