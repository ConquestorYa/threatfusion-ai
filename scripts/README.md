# Scripts

What each script is for. End users only need the installer; everything else
supports development, CI or the [evidence records](../docs/README.md#evidence).

## Install and run

| Script | Purpose |
| --- | --- |
| `install_linux.sh`, `bootstrap_linux.py` | The one-command Linux installer and its standard-library bootstrap |
| `check_linux_installation.py` | Black-box checks of a disposable installation (used by CI) |
| `start_local.py`, `manage_local.py` | Start the app and the small installed command interface |
| `check_public_demo_session.py` | Check a real Streamlit session on the synthetic demo |

## CTI and repository maintenance

| Script | Purpose |
| --- | --- |
| `refresh_cti_cache.py` | Refresh the local CTI cache from the command line |
| `audit_cti_lookup_coverage.py` | Audit CTI lookup coverage |
| `audit_public_release.py` | Secret and local-path audit of the repository (run in CI) |

## Demo and analysis helpers

| Script | Purpose |
| --- | --- |
| `generate_demo_dns_csv.py` | Generate a safe local DNS CSV from the CTI cache for UI testing |
| `analyze_dns.py` | Run the `threatfusion` command-line analysis from a source checkout |

## Retired lexical domain-name model (research record)

The lexical domain-name classifier failed its evaluations and is switched off
in the app. These scripts are **kept on purpose**: they reproduce the results
recorded in [ML evaluation](../docs/evidence/ML_DATASET.md), and some of them
are exercised by the test suite or referenced by the *Model evaluation* page.
They are not needed to use ThreatFusion.

- `build_ml_augmented_snapshot.py`, `build_ml_final_holdout.py`,
  `build_ml_fresh_disjoint_holdout.py`, `inspect_live_ml_snapshot.py`,
  `sample_cesnet_benign_domains.py`: build the pinned datasets and holdouts
- `train_ml_artifact.py`: train the development artifact
- `evaluate_ml_*.py`: the baseline, high-recall, FPR-budget, source-diagnostic,
  feature/recall iteration, benign-telemetry and final-holdout evaluations

## Lab (`lab/`)

Workloads, controls and measurements run in the isolated local lab described in
[Local lab](../docs/evidence/LOCAL_LAB.md). Each produces data for one evidence
record; none of them is part of the installed app.
