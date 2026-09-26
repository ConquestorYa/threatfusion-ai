# ThreatFusion AI v0.1.0 — Release Notes Draft

> Status: release candidate. Do not publish these notes as a final GitHub
> release until the remaining temporal evaluation, screenshots, hosted demo,
> and manual release checks are complete.

## Overview

ThreatFusion AI is an educational/portfolio cyber threat intelligence and DNS
analysis platform. It combines deterministic public CTI evidence, local DNS
telemetry, an explainable lexical ML signal for previously unseen domains, DNS
behavior indicators, and analyst-focused investigation views.

The project is intentionally positioned as a security-analysis prototype rather
than a production SIEM, EDR, or guaranteed malware detector.

## Highlights

- Multi-source CTI ingestion from ThreatFox, URLhaus, and SGB.
- DNS ingestion for generic CSV, Zeek, Pi-hole, and AdGuard Home.
- Exact/domain-context IOC matching with source/evidence details.
- Character n-gram TF-IDF + Logistic Regression ML scoring with explicit
  false-positive budgets and frozen artifacts.
- Explainable hybrid verdicts: `known_threat`, `high_risk`, `review`,
  and `low`.
- DNS behavior features including NXDOMAIN, lexical signals, response-IP churn,
  and periodicity.
- Streamlit investigation dashboard, analyst feedback/suppression, history,
  related-activity analysis, and privacy-safe exports.
- Public-mode privacy controls, sanitized deployment packaging, CLI support,
  and non-root Docker execution.
- Cross-platform CI, dependency auditing, coverage reporting, Docker health
  checks, and public-release secret/history auditing.

## ML evaluation position

Known IOC evidence remains stronger than the lexical ML signal. ML is used as
an auxiliary early-warning score for domains that are not already identified by
CTI.

The original model exposed excessive false positives on long-tail benign CESNET
data. A CESNET-augmented v2 candidate substantially reduced false positives but
its fresh-holdout malicious recall was too low, so it was not promoted.

A final bounded experiment kept the same TF-IDF + balanced Logistic Regression
family and changed only regularization strength. The C=4 candidate improved the
development medium operating-point recall from 20.22% to 25.52% while test FPR
moved from 0.52% to 0.60%. It has been frozen for one final untouched
post-freeze temporal holdout.

**Final temporal measurement: pending before release.**

No additional v1 model family or threshold tuning will be performed after that
measurement.

## Security and privacy

- Uploaded DNS telemetry is processed in memory by default.
- Public mode disables shared history saving/browsing.
- Threat indicators are treated as inert data and are not visited or resolved.
- Public deployment uses a sanitized runtime bundle rather than the developer
  data tree.
- Feed credentials belong only in maintenance jobs/secret managers, not in the
  interactive web process or repository.
- The repository includes an automated scan for common secret formats, local
  user paths, and reachable Git-history blobs.

## Known limitations

- ML scores are uncalibrated model scores, not literal malware probabilities.
- Final performance depends on data source mix and base rates.
- Temporal first-seen filtering reduces one leakage risk but does not prove
  campaign/family independence.
- DNS behavior heuristics provide context and review signals, not proof of
  malware.
- The project is an educational/portfolio prototype, not a production SOC
  platform.

## Deferred beyond v1

API service, watch-folder/streaming ingestion, Suricata support, STIX/MISP or
webhook SOC integrations, LLM analyst reporting, and neural-network/transformer
models are intentionally outside the v0.1.0 scope.
