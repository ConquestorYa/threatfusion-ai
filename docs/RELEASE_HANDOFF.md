# v0.1.0 Release Handoff

Status date: 2026-10-04

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
- The runtime/default and synthetic demo continue to use the trusted
  `development-001` artifact.

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
- Ruff, the full pytest suite, public-release audit, and `git diff --check`
  pass. The current suite has 709 passing tests.

## Remaining release gates

1. Decide whether the augmented candidate’s fresh-disjoint evidence is enough
  for an explicitly documented auxiliary runtime promotion, or collect a
  stronger post-freeze temporal sample.
2. Publish the public-mode demo behind HTTPS and hosting-layer rate limits.
3. Confirm the `v0.1.0` tag/release after the model decision and deployment
  checks.

## Current blockers

- The strict temporal protocol still has no eligible post-freeze malicious
  `first_seen` samples. The available augmented evidence is fresh-disjoint,
  not strict temporal.
- The normal pre-existing terminal may still lack the refreshed `docker` group
  membership. Open a new terminal or run `newgrp docker` before using Docker.

Do not create final ML metrics from the synthetic demo artifact or substitute
an older holdout for the lexical candidate.
