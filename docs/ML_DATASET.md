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
- final evaluation or model selection

## Malicious class

Planned real-data sources are:

- ThreatFox `DOMAIN` IOCs
- SGB `DOMAIN` IOCs
- hostnames extracted locally from URLhaus URL IOCs

URL hostnames that are IPv4 or IPv6 literals are excluded. They are IP
indicators, not domain samples for the malicious-domain classifier.

## Benign class

The planned benign source is a reproducible Tranco popular-domain snapshot.
`ml_dataset.py` and `ml_snapshot.py` do **not** download Tranco; reusable
dataset construction remains network-free. The explicit `TrancoCollector`
performs pinned-list acquisition, while `parse_tranco_csv()` consumes
caller-supplied CSV text. The live inspection script orchestrates the
collector and parser. When real collection is used, the Tranco list
identifier, version, and collection date should be recorded with the dataset
metadata.

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

## Baseline development split

The project now provides a baseline development split for an already-clean
`DomainSample` dataset:

- 80/20 train/test by default
- stratified by the binary label
- deterministic with `random_state=42` by default
- no pandas, feature extraction, or model training

Domain-level deduplication must happen before splitting. The split validates
that each normalized domain appears only once, and the same normalized domain
cannot appear in both the train and test sets. Both sets must contain benign
and malicious samples.

This random stratified split is for baseline development only. It is not
sufficient as the only final evaluation protocol because source-specific and
time-related patterns may inflate results. Later evaluation should include a
source-aware split that holds out malicious-source data, and time-aware
evaluation should be considered when timestamp metadata is preserved in the
ML dataset. Source-aware and time-aware splitting are not implemented here.

## Reproducible dataset snapshots

The snapshot layer assembles an in-memory labeled dataset from already-
collected `IOCRecord` objects and already-loaded benign domain strings. It
does not download data or contact ThreatFox, URLhaus, SGB, Tranco, DNS, or any
other network service. Real feed acquisition remains outside this module.

The Tranco standard list is rank/domain CSV, such as `1,example.com`. The
parser consumes only caller-supplied CSV text, takes the second column as
inert domain text, preserves valid-row order, and supports an optional row
limit. It does not interpret values as URLs or resolve them. Automated tests
use synthetic inert data rather than live lists or feeds.

A real experiment should record the following snapshot metadata and counts:

- benign dataset source
- Tranco list or snapshot identifier
- snapshot or list date
- malicious counts by retained source
- malicious and benign counts before and after deduplication
- malicious/benign overlap removed
- final dataset size

The snapshot statistics distinguish malicious IOC-derived candidates from
unique retained malicious domains, caller-supplied benign rows from valid
unique benign domains, and the final label counts after malicious overlap
precedence is applied. Malicious source counts describe the final retained
malicious samples, so the first source for a duplicate normalized domain wins
deterministically under the existing dataset rules.

Model training is still not implemented. Snapshot construction also does not
invoke the baseline split, calculate metrics, or write files to disk.

## First pinned live snapshot

The first live snapshot inspection experiment uses these parameters:

- Tranco ID: `L5PV4`
- Tranco list date: `2026-09-23`
- Tranco maximum rows used: `50,000`
- ThreatFox recent window: 7 days
- SGB bounded pages: 10
- URLhaus recent export

These are experiment parameters, not hardcoded behavior in the reusable
collectors. The inspection script accepts overrides, while the Tranco
collector always requires a caller-supplied list ID. Tranco is pinned to a
fixed list ID for reproducibility; the malicious feeds are live, so their
exact CTI contents depend on collection time.

The live inspection script prints aggregate configuration, source record
counts, dataset counts, overlap removal, and malicious source counts only. It
does not print IOC values, domains, URLs, or IP addresses, and it does not
train a model.

Using popular Tranco domains as benign examples may make the first baseline
easier than real-world DNS traffic. Later evaluation should include more
realistic benign DNS observations when they are available.
