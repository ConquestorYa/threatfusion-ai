# ML Dataset Preparation

This document describes the local, deterministic dataset construction layer used before any model training begins.

## Scope

The dataset builder is intentionally limited to:

- parsing already-supplied malicious IOC records into normalized domain samples
- accepting caller-provided benign domains
- deduplicating by normalized domain
- resolving overlaps so malicious labels win over benign labels
- keeping all behavior locally and deterministic

It does not perform:

- network downloads
- DNS lookups
- requests to public services
- feature extraction
- model training
- train/test splitting

## Malicious class

Planned real-data sources are:

- ThreatFox `DOMAIN` IOCs
- SGB `DOMAIN` IOCs
- hostnames extracted locally from URLhaus URL IOCs

URL hostnames that are IPv4 or IPv6 literals are excluded. They are IP
indicators, not domain samples for the malicious-domain classifier.

## Benign class

The planned benign source is a reproducible Tranco popular-domain snapshot.
The current code does **not** download Tranco; benign domains must be supplied
by the caller. When real collection is added, the Tranco list identifier,
version, and collection date should be recorded with the dataset metadata.

## Data model

Each dataset entry is represented as a `DomainSample` with:

- `domain`: normalized domain string, lower-case and without a trailing dot
- `label`: 1 for malicious, 0 for benign
- `source`: origin of the sample for traceability

## Normalization and deduplication rules

1. Domain strings are normalized using the project `normalize_ioc_value()` logic.
2. Malware entries may originate from `IOCRecord` objects of type `DOMAIN` or from the hostname extracted from `URL` records.
3. Benign inputs are accepted as strings already supplied by the caller.
4. Duplicate domains are removed using the normalized domain value.
5. If the same domain appears in both malicious and benign inputs, the malicious label wins.
6. The output ordering is deterministic and preserves first-seen order for each domain.

## Dataset safeguards

- Normalize before comparison.
- Deduplicate at the normalized-domain level.
- Malicious samples win on overlap.
- Never allow one normalized domain under both labels.
- Record source, version, and date when real data is collected.
- Use fixed random seeds later if sampling is introduced.
- A balanced training dataset does not represent real-world malicious prevalence.
- Prevent train/test leakage by keeping equivalent normalized domains in one split.
- Later evaluation should consider time-aware and source-aware splitting.

## Why this is separate from training

Dataset construction is intentionally a separate concern from model training. This keeps the data pipeline explainable and prevents accidental leakage from the preparation stage into later modeling steps.

The project intentionally keeps this layer simple: it is a static data contract, not a machine-learning pipeline.

## Planned baseline model

**Not implemented yet.** The planned first baseline is character n-gram TF-IDF
features followed by Logistic Regression. This is intended to be an
explainable and reproducible starting point, not the final model.

No model training or evaluation currently exists in this layer.
