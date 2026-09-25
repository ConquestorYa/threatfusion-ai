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

1. Domain strings are canonicalized to lowercase IDNA ASCII form so Unicode
   hostnames and their punycode representations share one normalized value.
2. ML candidates must contain at least two valid DNS labels, respect DNS label
   length/syntax limits, and must not be IP literals.
3. Malware entries may originate from `IOCRecord` objects of type `DOMAIN`
   or from the hostname extracted from `URL` records.
4. Benign inputs are accepted as strings already supplied by the caller.
5. Duplicate domains are removed using the normalized canonical domain value.
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

## Baseline model

The first baseline is implemented as character n-gram TF-IDF features
(`analyzer="char"`, n-grams 3 through 5) followed by Logistic Regression.
The vectorizer and classifier are fitted only after the deterministic
train/test split so the held-out test domains do not influence the learned
vocabulary or IDF statistics.

The baseline reports precision, recall, F1, false-positive rate, and the
TN/FP/FN/TP confusion-matrix counts. Accuracy is intentionally not the primary
metric because the persisted baseline dataset is class-imbalanced.

This is the first explainable and reproducible development baseline, not the
final model or final evaluation protocol.

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

Snapshot construction itself does not train a model, invoke the baseline
split, calculate metrics, or perform collection. The separate snapshot I/O
layer persists completed snapshots locally, and the baseline evaluation layer
loads those saved samples for training and held-out development evaluation.

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

## Persisted experiment snapshots

Live malicious feeds change over time, so an exact experiment dataset must be
persisted locally rather than re-fetched during model training. The snapshot
I/O layer writes two deterministic files under an explicitly supplied output
directory:

- `dataset.csv` stores normalized `domain,label,source` rows in snapshot order.
- `metadata.json` stores snapshot metadata, statistics, and experiment
	parameters.

The default local path `data/snapshots/` is ignored by Git. API keys are never
stored. Future model training should load a saved snapshot instead of
re-fetching live feeds during training.

The first live collection run produced these aggregate results:

- ThreatFox records: `8575`
- URLhaus records: `14381`
- SGB records: `200`
- malicious candidates: `7021`
- unique malicious: `5566`
- Tranco rows: `50000`
- benign after overlap: `49994`
- final total: `55560`

These numbers describe that one live collection run and may differ in later
runs as the live CTI sources change.

## Running the baseline evaluation

The command-line evaluation utility reads an existing local snapshot rather
than re-fetching live feeds:

```text
python scripts/evaluate_ml_baseline.py --snapshot-dir data/snapshots/baseline-001
```

Defaults are an 80/20 stratified development split and `random_state=42`.
Output is aggregate-only: split sizes, confusion-matrix counts, precision,
recall, F1, and false-positive rate. It does not print domain values and does
not perform networking.

The random stratified split remains a development baseline. Source-aware
evaluation and time-aware evaluation are still required as stronger later
checks before treating the measured performance as representative of
real-world DNS traffic.

## High-recall development evaluation

The first saved-snapshot baseline produced very high precision but low recall
on `baseline-001`:

- precision: `0.9865`
- recall: `0.1312`
- F1: `0.2316`
- false-positive rate: `0.0002`
- TN: `9997`
- FP: `2`
- FN: `967`
- TP: `146`

This means the default baseline was extremely conservative: it produced very
few false alarms but missed most malicious test domains.

The high-recall experiment therefore keeps the same character 3-5 gram TF-IDF
representation and compares a Logistic Regression classifier using
`class_weight="balanced"`. It uses a deterministic train/validation/test
split. The model and TF-IDF representation are fitted on TRAIN only.
Decision thresholds are selected on VALIDATION only, and the untouched TEST
set is used only for the final measurement.

The evaluation reports candidate operating points for validation recall
targets of 0.80, 0.90, 0.95, and 0.99. For each target, the validation
threshold with the lowest false-positive rate that still reaches the requested
recall is selected, then that exact threshold is measured on TEST.

This does not guarantee detection of every malicious domain. A detector can
achieve 100% recall trivially by labeling every domain malicious, but that
would also create an unusable false-positive rate. The project therefore
measures the recall/false-positive tradeoff explicitly rather than claiming
perfect detection.

Run the local saved-snapshot experiment with:

```text
python scripts/evaluate_ml_high_recall.py --snapshot-dir data/snapshots/baseline-001
```

The output is aggregate-only and does not print domain values.

## FPR-budget model comparison

The high-recall experiment showed that lowering the decision threshold can
raise recall, but at the cost of an impractically large false-positive rate.
The next development comparison therefore reverses the question: for a fixed
false-positive-rate budget, how much malicious-domain recall can each model
recover?

The comparison uses the same deterministic train/validation/development-test
split and evaluates a deliberately small, explainable candidate set:

- character 3-5 TF-IDF + balanced Logistic Regression
- character 2-6 TF-IDF with sublinear term frequency + balanced Logistic Regression
- character 3-5 TF-IDF + balanced SGDClassifier with logistic loss

For each candidate, thresholds are selected on VALIDATION only at false-positive
rate budgets of 0.1%, 1%, 5%, and 10%. Within each budget, the selected
validation threshold maximizes recall without exceeding the requested
false-positive rate. That exact threshold is then measured on the shared
development TEST split.

Because development test results have already been inspected while iterating on
the model, this split is not treated as a final unbiased benchmark. Final
performance claims require a fresh holdout, preferably with source-aware or
time-aware separation.

Run the comparison locally with:

```text
python scripts/evaluate_ml_fpr_comparison.py --snapshot-dir data/snapshots/baseline-001
```

The script prints aggregate metrics only and never prints domain values.


## Source-wise malicious recall diagnostics

Aggregate recall can hide source-specific weaknesses. The source diagnostic
layer reuses the fitted FPR-budget comparison and breaks malicious recall down
by the retained `DomainSample.source` value on the development test split.

For each candidate and validation-selected FPR budget, it reports:

- malicious sample count per source
- detected count
- missed count
- source-wise recall

This is diagnostic only. It does not change model thresholds or select a model
from development-test source results.

Because duplicate malicious domains keep the first retained source under the
existing dataset rules, source-wise recall reflects that retained source label,
not every original CTI source that may have observed the domain.

Run locally with:

```text
python scripts/evaluate_ml_source_diagnostics.py --snapshot-dir data/snapshots/baseline-001
```

The output is aggregate-only and never prints domain values.


## Development source-diagnostic findings

On `baseline-001`, the wider character 2-6 TF-IDF + sublinear TF + balanced
Logistic Regression candidate had the highest VALIDATION recall at every tested
false-positive-rate budget, so it is the current development candidate rather
than a final production choice.

Its development-test source recall was:

- at about 1% FPR: SGB 0.6364, ThreatFox 0.2691, URLhaus 0.3030
- at about 5% FPR: SGB 0.7045, ThreatFox 0.4763, URLhaus 0.4343
- at about 10% FPR: SGB 0.7955, ThreatFox 0.5876, URLhaus 0.5354

These numbers are diagnostic only. The SGB test subset contains only 44
malicious samples, compared with 970 retained ThreatFox samples and 99
URLhaus samples, so the source percentages should not be treated as equally
precise estimates.

The result supports a hybrid design: known IOC matching remains the strongest
deterministic signal, while domain-string ML is one signal for previously
unseen domains and local DNS behavior provides additional context.

## Hybrid DNS assessment

The first hybrid analysis layer is intentionally explainable and does not claim
to be a calibrated malware probability.

It combines:

- existing known IOC matches
- caller-supplied ML probabilities plus validation-selected thresholds
- local DNS behavior summaries

DNS behavior is aggregated by normalized query domain and includes query count,
unique client count, unique response-IP count, observed query types, and a
comparable observation time span when timestamps permit it.

The hybrid verdicts are:

- `known_threat`: at least one known IOC match exists
- `high_risk`: strong ML evidence, or medium ML evidence strengthened by
  multiple DNS behavior signals
- `review`: weaker ML evidence or multiple behavior signals
- `low`: insufficient evidence for the stronger categories

Behavior-only signals are heuristic context, not proof of malware. Snapshot-
specific ML thresholds are not hardcoded into the reusable module.


## Persisted development ML artifact

The current development candidate can be trained from an existing local
snapshot and persisted for later local inference. The reusable artifact
contains:

- the fitted character 2-6 sublinear TF-IDF + balanced Logistic Regression
  pipeline
- validation-selected high / medium / low probability thresholds
- the corresponding validation false-positive-rate budgets
- split counts, random state, schema version, and scikit-learn version

The default threshold policy for the artifact is:

- high confidence: validation FPR budget 1%
- medium confidence: validation FPR budget 5%
- low confidence: validation FPR budget 10%

The thresholds are selected on VALIDATION only. The fitted artifact keeps the
same train-only model used when those thresholds were selected; it is not
refitted on development-test data.

Train and persist locally with:

```text
python scripts/train_ml_artifact.py --snapshot-dir data/snapshots/baseline-001 --output-dir data/models/development-001
```

`data/models/` is ignored by Git. The JSON metadata contains aggregate model
configuration and counts, not training-domain rows or secrets.

The model file uses joblib/pickle-compatible serialization. Loading such a
file can execute code, so `load_trusted_ml_artifact()` is intentionally
documented for trusted local artifacts generated by this project only. Never
load a model artifact from an untrusted source.

This remains a development artifact rather than a final production model.
Final performance claims still require a fresh holdout and a new final model
selection/evaluation cycle.


## Frozen-model fresh holdout evaluation

The repository now includes a final-evaluation workflow for the already-frozen
development artifact. This workflow is intentionally separate from development
model selection.

The protocol is:

1. keep the existing persisted model artifact unchanged
2. collect a separate later dataset snapshot
3. require the holdout benign snapshot date to be later than the development
   snapshot date
4. remove every normalized domain that appeared anywhere in the development
   snapshot
5. evaluate the frozen high / medium / low thresholds exactly as stored in the
   artifact
6. report aggregate precision, recall, F1, false-positive rate, confusion
   counts, and malicious recall by retained source
7. do not retrain the model or tune thresholds from holdout results

Collect the real holdout snapshot first. Use a **new pinned Tranco list ID**
and the actual date associated with that list; do not reuse `L5PV4` /
`2026-09-23` from the development snapshot.

```powershell
$env:THREATFOX_AUTH_KEY="..."
$env:URLHAUS_AUTH_KEY="..."

python scripts\inspect_live_ml_snapshot.py `
  --final-holdout-against data\snapshots\baseline-001 `
  --artifact-dir data\models\development-001 `
  --tranco-id <NEW_TRANCO_ID> `
  --tranco-date <YYYY-MM-DD> `
  --output-dir data\snapshots\holdout-001
```

Final-holdout mode performs its preflight **before network collection**. It
refuses to proceed when the benign snapshot date is not later than development,
when the Tranco list ID is reused, when the holdout output directory is the
development directory, or when the holdout output directory is already
non-empty. The persisted experiment metadata also records the
`fresh_collection_disjoint` protocol, the development/holdout benign
snapshot identities, frozen model name, and frozen artifact SHA-256 checksum.
The checksum is an identity record; the model and thresholds are not changed.

After collection, run the evaluator once against the saved holdout. The
evaluator itself is local and network-free:

```powershell
python scripts\evaluate_ml_final_holdout.py `
  --artifact-dir data\models\development-001 `
  --development-snapshot-dir data\snapshots\baseline-001 `
  --holdout-snapshot-dir data\snapshots\holdout-001 `
  --json-output data\evaluation\final_holdout.json
```

The optional JSON output contains aggregate metrics/source diagnostics only and
is what the Streamlit Model evaluation tab reads. It does not contain domain
rows. Both `data/snapshots/` and `data/evaluation/` are ignored by Git by
default, so the raw holdout remains local.

This is a **fresh-collection disjoint holdout**, not a strict IOC first-seen
time split. The current `DomainSample` schema does not retain IOC
`first_seen` timestamps, so the project must not describe this protocol as a
strict temporal event split.

The final holdout should be inspected only after the model and thresholds are
frozen. If its results later influence another model change, that holdout
becomes development evidence and a new final holdout would be required.

## Final-holdout uncertainty and operational base rates

Final-holdout reports include 95% Wilson score confidence intervals for
precision, recall, and false-positive rate at every frozen operating point.
Source-aware diagnostics also report malicious recall and benign
false-positive rate per retained dataset source when that class is present.

These intervals describe sampling uncertainty for the evaluated holdout. They
do not correct dataset bias, source leakage, missing long-tail benign traffic,
or the absence of strict IOC first-seen timestamps.

Dataset precision must not be presented as real-world positive predictive
value (PPV). Operational PPV depends on the malicious base rate in the traffic
being analyzed:

`PPV = (TPR × prevalence) / ((TPR × prevalence) + (FPR × (1 - prevalence)))`

In real DNS traffic the malicious prevalence may be far lower than in an
evaluation dataset. As a result, even a seemingly small false-positive rate can
produce more benign alerts than malicious detections at scale. Final reporting
must therefore show the measured FPR, its uncertainty, dataset composition,
and this base-rate limitation alongside precision.

