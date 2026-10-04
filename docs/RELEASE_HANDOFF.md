# v0.1.0 Release Handoff

Status date: 2026-10-04

## Current user instructions — local development only

This policy supersedes the earlier hosted-demo/release plan below. Continue
development and security checks locally. Do not create or resume a public site,
tunnel or hosted preview unless the user explicitly asks. Completed and verified
code/configuration/documentation may still be published to GitHub, keeping all
private/third-party data local and ignored. See the root `AGENTS.md`.

A new read-only Render check for the user's explicit `main` integration request
confirmed `threatfusion-ai-demo` is **user-suspended**, with service previews
disabled; no other services/previews exist in the confirmed workspace. The
latest deployment record still refers to `8966620` and is not evidence that the
suspended service is running. Auto-Deploy still reports `yes` / `checksPass`;
Blueprint Auto Sync is not verified. Neither setting is claimed to be disabled.

The source integration uses `[skip render]`, adds no Blueprint resources and
retains the manual-deploy/preview-disabled Blueprint. Suspension and deployment
history are rechecked after merge/CI. Do not resume hosting; the merge request
authorizes source integration only. See `AGENTS.md` and Render's documented
[auto-deploy skip phrase](https://render.com/docs/deploys#skipping-an-auto-deploy).

The retained Blueprint now requests manual deployment and disables previews;
GitHub CI also runs on `local-development/` branches. YAML/schema/lint/privacy
checks validate this configuration change. These file changes alone do not
close an existing public service or turn off dashboard Auto Sync.

## Main integration (2026-10-04)

- The user requested including the verified `local-development/linux-first-run`
  work in `main`. Preserve its commits and all private/ignored local data.
- Both README download commands and `scripts/install_linux.sh` now select
  `main`; each install still resolves one immutable source SHA before download.
- Source work had 818 local tests and all six CI jobs passing before integration.
  Integration uses a `[skip render]` commit and a confirmed user-suspended
  service, with no preview creation or service resume. Verify main CI and the
  exact main download command before reporting completion.

## Linux first-run delivery (2026-10-04)

- `scripts/install_linux.sh` is the normal-user, one-command entry point. It
  installs pinned uv 0.12.23, private Python 3.12.14 and 49 hashed binary-wheel
  dependencies from `requirements-linux.lock`; Python/Git/sudo are not needed.
- Immutable source downloads and private environment identities are managed by
  `scripts/bootstrap_linux.py`. The saved `start` launcher supports offline
  restart; setup refuses unrecognized directories and preserves existing data.
- First launch is a clearly synthetic demo. Explicit `--mode cti-only
  --refresh-cti` collects separate real CTI; keys are not saved or passed to the
  Streamlit child, refresh output omits upstream URL/error details, and ML stays
  disabled. No experimental artifact is selected or promoted.
- `scripts/start_local.py` / `local_setup.py` bind only 127.0.0.1, open a browser
  after health readiness, choose a free port and supervise shutdown. Shared
  persistent analyst history is disabled in this first-run profile. The UI calls
  this a session-only workspace, avoiding a misleading public-hosting label.
- Fresh Debian 12 and Ubuntu 24.04 containers, running as a normal user with no
  Python/Git, passed full installation and repeat installation. Black-box checks
  exercised actual Streamlit WebSocket UI rendering in demo and CTI-only modes,
  loopback binding, occupied-port handling, duplicate-launch exclusion, both
  Ctrl+C/SIGTERM shutdown and preserved synthetic/CTI fixture data. A path with
  spaces was covered. No real feed credentials or developer data entered tests.
- Local regression: **805 passed**, **90%** coverage; Ruff and ShellCheck passed,
  and pip-audit found no known dependency vulnerabilities.
- Published implementation `633323be61cde41edb296f827471489bea1203b4` passed all
  six [GitHub CI jobs](https://github.com/ConquestorYa/threatfusion-ai/actions/runs/37164159694),
  including Windows and both clean Linux installations. The exact README
  copy-paste command also passed in a third clean Ubuntu environment with no
  mounted checkout: immutable GitHub source retrieval, real foreground UI,
  Ctrl+C shutdown and temporary-file cleanup were verified.
- CI adds the same two clean-install jobs alongside Ubuntu quality, Windows
  pytest and both existing Docker jobs. Ruff, Bash syntax, ShellCheck,
  dependency auditing and tracked-tree/history privacy auditing are part of the
  verification. Original 32 local data files retain their recorded checksums.
- See `INSTALL_LINUX.md` and both READMEs for the copy-paste command, supported
  baseline, optional credentials, restart and recovery. The work was initially
  published on `local-development/linux-first-run`; the user now requested its
  guarded integration into `main`.
- This flow does not change the fresh-disjoint metrics, five unscored eligible
  temporal samples, missing original runtime artifact or deferred promotion.

## Credential privacy follow-up (2026-10-04)

- Rechecked the first-run flow: credentials come exclusively from the caller's
  environment; no developer/shared fallback exists. Missing ThreatFox/URLhaus
  keys skip those collectors. Demo needs no key or upstream CTI collection.
- Closed a legacy refresh diagnostic exposure: raw collector exceptions could
  reach progress callbacks, returned outcome details and CLI logs. Failures now
  use fixed safe messages while preserving the actionable SGB page-bound hint;
  neither authenticated URLs nor private payload text is forwarded.
- Ignored `.env`/Streamlit secrets/private-key files are also rejected by path
  in the tracked-tree and Git-history release audit, including short keys and
  binary containers not covered by recognizable token patterns.
- Regression tests cover callback/result/CLI redaction, absent-key collector
  exclusion, secret-file paths and removed secrets retained in history. No live
  keys are used in tests. The credential/privacy follow-up does not complete
  the broader local security review or authorize public hosting.
- Follow-up validation: **818 local tests passed**, **90%** coverage; Ruff and
  tracked-tree/history secret audit passed. All 32 recorded original local data
  files retain their checksums. No known secret-file/token finding was detected.

## Current position

- The earlier character-only C=4 model has a completed historical post-freeze
  holdout. Its metrics are documented in `ML_DATASET.md` and
  `RELEASE_NOTES_v0.1.0.md`.
- The improved candidate is an augmented
  `lr_char_2_6_plus_lexical_c4` artifact trained with a separate CESNET
  hard-negative development window.
- Its fresh-disjoint evaluation completed with High/medium/low recall of
  60.62%/78.75%/81.87% and FPR of 0.85%/1.95%/2.62%.
- It is not the runtime default because fresh-disjoint evidence is not strict
  first-seen temporal evidence.
- Runtime promotion is deferred until stronger untouched post-freeze temporal
  evidence is available. The augmented artifact stays an experimental candidate.
- The default configuration still points to `data/models/development-001`, but
  that original artifact is **absent in this checkout**. The available synthetic
  demo runtime has a separate `development-001` directory and
  `demo_only_synthetic` status; it is not the original measured artifact.
- Explicit CTI-only operation is now available when the original artifact is
  unavailable. It does not change the default or promote either candidate.

## Completed in this checkout

- Documentation was synchronized across the README files, architecture,
  project context, decision log, deployment guide, release notes, checklist,
  and changelog.
- The synthetic public-mode demo starts successfully and its Streamlit health
  endpoint returns `ok`.
- A sanitized local deployment bundle was generated at
  `data/deployment/runtime/`. It contains only the synthetic CTI cache and
  demo model artifact; analysis history and evaluation reports are absent.
- The Docker image was built successfully and the sanitized runtime passed the
  public-mode Streamlit health check. The test used a refreshed `docker`
  group shell; the temporary container has since been removed.
- A forced CTI refresh without credentials successfully refreshed SGB with
  488,361 active records, ThreatFox with 110,075 active records, and URLhaus
  with 16,072 active records. PhishTank was rejected by its access/security
  redirect and its previous cache was preserved.
- The indexed URLhaus lookup audit covered 1,000 active URL records with 100%
  exact and hostname-index coverage. No IOC destination was opened or
  resolved.
- A reconstructed development-only snapshot was generated at
  `data/snapshots/reconstructed-development/` from the refreshed local CTI
  cache and Tranco `L5PV4` (50,000 rows). It contains 523,114 final samples.
- A corresponding development-only lexical C=4 artifact was generated at
  `data/models/reconstructed-development-lexical-c4/`. Its thresholds are
  validation-selected at FPR budgets of 0.1%, 0.5% and 1.0%. This artifact is
  not the previously documented frozen candidate and has no final holdout
  claim.
- A new CESNET benign window was streamed into
  `data/evaluation/cesnet-benign-lexical-final-20k.csv`: 20,000 unique domains
  after an 80,000-domain offset, with SHA-256
  `6ffc45cca5e089ad648f54e2d05f5d42bf4fc2bd6514ff2aa8e484af497da287`.
- The reconstructed artifact identity is
  `8b207dc363edde3544a8dcd447b80968c433b1d2b929616d492d40d5204ef356`,
  frozen at approximately `2026-10-02T21:55:51Z`.
- The reconstructed artifact was evaluated once on the post-freeze holdout.
  High/medium/low operating points measured 69.68%/82.58%/86.45% recall with
  14.09%/25.60%/33.99% FPR. It was not promoted because the false-positive
  rates are operationally unusable.
- A follow-up bounded feature comparison on the development snapshot did not
  justify promotion. Lexical C=4 was the more conservative candidate at the
  0.5% and 1.0% development FPR budgets, but the comparison remains
  development-only and requires a new untouched holdout for any future
  selection.
- The next final-holdout build was attempted with the augmented artifact and
  a post-freeze CTI refresh, but no malicious domain had a usable
  `first_seen` strictly after the new artifact cutoff. The evaluator correctly
  refused to create an empty temporal holdout. A later collection with new
  eligible IOC timing, or a separately documented fresh-disjoint non-temporal
  protocol, is required before promotion.
- A separately documented fresh-disjoint evaluation was completed for the
  augmented artifact after removing all development-domain overlap. It measured
  High/medium/low recall of 60.62%/78.75%/81.87% at FPRs of
  0.85%/1.95%/2.62%. This is a meaningful improvement over the earlier
  reconstructed temporal result, but it is not strict temporal evidence and
  the artifact remains unpromoted.
- The fresh-disjoint builder is implemented at
  `scripts/build_ml_fresh_disjoint_holdout.py`; it preserves the temporal
  builder’s stricter behavior and labels the alternative protocol explicitly.
- The initial verification passed all 709 pre-existing tests.

## Continuation audit — 2026-10-04

- GitHub's three context documents matched the local pre-edit versions. The
  initial worktree had only the user's untracked `komutlar.txt`; it was preserved.
- The augmented artifact checksum is
  `643b5adc1cf4bc4cb9c677df88aa4797dcbd6ae1be8ff0d0c0f4ee7d7f3e4cd9`.
  Its bytes match the recorded collection identity, and all three frozen
  thresholds match the existing aggregate report. No holdout rescoring or
  threshold tuning was performed.
- A read-only audit against the recorded `2026-10-03T20:41:49Z` cutoff retained
  **zero** strict-temporal malicious domains: all 473,323 unique candidates had
  usable earliest timing at or before the cutoff. The required sources were
  refreshed at `2026-10-03T21:20:55.415866Z`. No feed refresh was performed in
  this continuation.
- The existing fresh-disjoint snapshot is a legacy pre-filter collection:
  the evaluator removed 473,163 development overlaps, leaving 160 malicious
  and 19,936 benign domains. Its report remains unchanged. New builder outputs
  remove both classes' development overlap **before persistence**, require both
  retained classes, and use the canonical `fresh_collection_disjoint` identifier.
- New schema-v4 aggregate reports carry the evaluated artifact SHA-256.
  Evaluation checks recorded artifact/development provenance and refuses to
  drop or alter a temporal snapshot's recorded cutoff. Synthetic demo artifacts
  are refused as final ML evidence. Schema-v1/v2/v3 reports remain readable.
- The evaluation page describes the actual first-seen protocol, cutoff and
  removal counts, distinguishes legacy reports without artifact identity, and
  explains that loading a report does not promote its candidate.
- SQLite sidecars are ignored. The release audit checks local data/model paths
  in the tracked tree and history even when file contents are binary.
- CTI caches, datasets, models and existing evaluation files remain local and
  ignored. Neither Git LFS nor publishing these files is part of this release.

The augmented High tier still has 0.85% measured FPR against a 0.1% validation
budget, and source coverage is uneven: SGB contributes 138 malicious domains
with 69.57% High recall; URLhaus contributes 22 with 4.55%; ThreatFox contributes
none after overlap removal. These inspected aggregates strengthen the decision
to defer promotion; they are not new tuning data. See DEC-082.

## Validation after continuation

- Full pytest suite with coverage: **742 passed**, **88%** total coverage.
- Ruff and `git diff --check`: passed.
- Public-release tracked-tree and full reachable-history audit: zero findings;
  newly added task files were also scanned explicitly before any staging.
- Historical artifact path aliases are checked even if a binary blob also
  appeared under a permitted path and the artifact was later removed.
- Isolated synthetic runtime: Streamlit localhost health returned `200 / ok`;
  the application loaded its checksum-verified demo model without UI errors,
  and public mode hid shared history. The temporary server was stopped.
- Checksums verified all 32 existing local data files unchanged at the end of
  that audit. The initial untracked note was not modified by the agent; it was
  no longer present when the subsequently authorized implementation started.
  No commit, push, hosted deployment or release tag was created in that audit.

## Authorized release implementation — 2026-10-04

- A local backup search did not find the trusted original runtime artifact.
  The CTI-only dashboard and CLI paths skip model loading/scoring, preserve
  exact CTI and behavior evidence, and label exports without fabricated ML
  values. Model-dependent history is disabled in this mode (DEC-083).
- `Dockerfile.public-demo` generates only synthetic assets, keeps code/model
  and the independent checksum pin read-only, and supervises loopback Streamlit
  behind Nginx. Request, WebSocket connection and upload limits are applied;
  access logs and request buffering are disabled (DEC-084).
- The Docker context is an allowlist of application/configuration files. Private
  CTI, datasets, model binaries, telemetry, secrets, tests and Git metadata do
  not enter either image. No live-feed credentials are needed for the demo.
- `render.yaml` targets the free Frankfurt plan, Docker runtime and health
  endpoint. Official Render JSON Schema validation passed. A dedicated CI job
  builds the synthetic image and checks proxy limits and a real Streamlit session.
- Full verification: **763 tests passed**, **90%** coverage; Ruff and
  tracked-tree/reachable-history release auditing passed. The standard and demo
  Docker images both built successfully. Local proxy checks verified HTTP 200,
  security headers, oversized-body HTTP 413 and burst HTTP 429; health remained
  HTTP 200. A real WebSocket session rendered the UI without exceptions.
- A separate ignored CTI cache copy was refreshed: SGB retained 488,504 active
  records and five development-disjoint post-cutoff domains. All five come from
  SGB and remain unscored. ThreatFox/URLhaus retained the earlier post-cutoff
  cache snapshots because new keyed credentials were unavailable; PhishTank
  refresh failed at its access/security redirect and preserved previous data.
  The original cache and all 32 existing local data files retained their
  checksums. No inspected holdout was rescored and no threshold was tuned.
- Hosted deployment is still pending: the Render connection requires user
  workspace confirmation, its service-creation tool cannot configure the custom
  Dockerfile, and this session has no controllable browser. The ready Blueprint
  can be applied from the Render dashboard after publication to `main`.
- The final `v0.1.0` tag/release remains gated on actual hosted HTTPS and ingress
  verification; local Docker success is not claimed as a hosted deployment.
- Source implementation was published to GitHub `main` as
  `dc03e368308e91c14b74ff389b269c594e926f9d`. Its reachable-history audit passed
  again after publication. CI run `37159279681` verifies this implementation;
  deployment assets still contain no private data.
- That CI run completed successfully: Ubuntu Ruff/pytest/coverage/pip-audit,
  Windows pytest, standard Docker build/health, and synthetic-demo privacy,
  proxy limits and real WebSocket-session checks all passed.
- The three existing portfolio screenshots were reviewed visually: they use
  inert `.example` synthetic findings and show no private telemetry or secrets.
  PNG metadata and EXIF were empty. This historical review is superseded by
  the current interface captures recorded below.

## Remaining release gates

1. Collect stronger untouched post-freeze temporal evidence before reconsidering
   augmented runtime promotion. This is a future ML gate; v0.1.0 can retain the
   documented auxiliary/default policy without promoting the candidate.
2. Complete local security review and fix confirmed issues.
3. Revisit final release timing after those checks. Public hosting requires a
   new explicit user request and is not an active development task.

## Current blockers

- The follow-up collection has only five unscored post-freeze malicious domains,
  all SGB, after the initial zero-eligible result. This is insufficient stronger
  temporal evidence. The available augmented performance report remains
  fresh-disjoint, not strict temporal; promotion stays deferred.
- The original configured runtime artifact is absent locally. Use the synthetic
  demo generator for presentation, or restore the trusted original artifact from
  its private/local source. Retraining produces a new identity and requires new
  evaluation; it cannot restore the historical model claim.
- CTI-only operation is available now without that model. For full historical
  ML operation, restore the trusted backup privately if one exists elsewhere.
- Keep the Render demo user-suspended. Auto-Deploy still reports enabled and
  Blueprint Auto Sync is not verified; disable them when dashboard access is
  available. The guarded, explicitly requested source integration above does
  not authorize resuming the service or bypassing its deployment safeguards.
- The normal pre-existing terminal may still lack the refreshed `docker` group
  membership. Open a new terminal or run `newgrp docker` before using Docker.

Do not create final ML metrics from the synthetic demo artifact or substitute
an older holdout for the lexical candidate.

## Current interface screenshots (2026-10-04)

- Replaced Quick Lookup, telemetry overview and domain investigation PNGs used
  by both README languages with actual current Streamlit UI captures.
- Captured with isolated Chromium on 127.0.0.1, English/Mid theme and a separate
  temporary synthetic-only runtime. The input contains 24 events across five
  reserved example domains; no upstream feeds, private data or API keys used.
- Browser verification exercised lookup, CSV upload, analysis and investigation.
  Screenshots were reviewed visually and checked for empty PNG/EXIF metadata.
  The 48 targeted UI/theme/release-audit tests passed; all 32 previously recorded
  local data files retain their original checksums.
  Source model policy, private artifacts and runtime promotion are unchanged.
- Source-only main update uses [skip render]; the Render service was confirmed
  user-suspended with previews disabled before publication. No public site
  deployment is authorized.
