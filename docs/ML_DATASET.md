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

The CLI also accepts explicit FPR budgets without changing the persisted
artifact policy. After the CESNET long-tail benign evaluation exposed a 3.60%
high-threshold FPR, the next diagnostic step is to quantify recall at much
lower operational budgets:

```powershell
python scripts\evaluate_ml_fpr_comparison.py `
  --snapshot-dir data\snapshots\baseline-001 `
  --fpr-budgets 0.001 0.005 0.01
```

Those rates correspond to 0.1%, 0.5%, and 1% validation FPR budgets. This is
development analysis only: it does not rewrite the frozen artifact or change
runtime thresholds.

To measure the resulting score thresholds directly on the already-collected
confirmed-benign CESNET corpus without changing the artifact, pass them as
diagnostic thresholds:

```powershell
python scripts\evaluate_ml_benign_telemetry.py `
  --artifact-dir data\models\development-001 `
  --development-snapshot-dir data\snapshots\baseline-001 `
  --dns-csv data\evaluation\cesnet-benign-20k.csv `
  --confirm-benign-label `
  --diagnostic-thresholds 0.875784 0.805109 0.757369
```

Diagnostic thresholds are console-only measurements and do not replace the
artifact's frozen high / medium / low thresholds. If later model/threshold
changes are chosen using these results or the CESNET diagnostic, a new
untouched final holdout is required.

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

## Confirmed-benign long-tail DNS telemetry evaluation

Tranco Top 50k is useful for a reproducible benign proxy, but it is not a
representative sample of ordinary long-tail DNS activity. The repository now
includes a second benign-only evaluation path for DNS telemetry that an
operator has independently chosen to treat as benign-labeled data.

This workflow reuses the existing DNS importers for:

- Generic ThreatFusion DNS CSV
- Zeek `dns.log`
- Pi-hole FTL SQLite
- AdGuard Home query-log JSON

The evaluator:

1. requires the explicit `--confirm-benign-label` acknowledgement
2. keeps only valid public-domain ML scoring candidates
3. normalizes and deduplicates domains so repeated queries do not inflate FPR
4. removes every normalized domain that appeared in the development snapshot
5. evaluates the frozen high / medium / low thresholds without retraining or
   threshold tuning
6. reports false-positive counts, empirical FPR, and 95% Wilson intervals
7. can persist an aggregate-only JSON report that contains no domain names,
   DNS rows, or client IP values

Example with a Generic DNS CSV:

```powershell
python scripts\evaluate_ml_benign_telemetry.py `
  --artifact-dir data\models\development-001 `
  --development-snapshot-dir data\snapshots\baseline-001 `
  --dns-csv data\evaluation-input\confirmed-benign.csv `
  --confirm-benign-label `
  --json-output data\evaluation\benign_dns.json
```

Equivalent input switches are `--zeek-dns-log`, `--pihole-db`, and
`--adguard-query-log`. Exactly one telemetry input must be supplied.

The acknowledgement is a scientific guardrail, not a security guarantee.
**Absence from CTI is not proof that a domain is benign.** The measured FPR is
valid only to the extent that the supplied corpus really is benign. A corpus
built by taking arbitrary DNS traffic and merely removing known IOC matches
must not be described as confirmed benign.

The tool intentionally measures unique-domain false-positive behavior rather
than per-query alert volume. Query-frequency-weighted operational alert burden
can be studied separately when realistic production telemetry is available.

Implementing this path does not by itself complete the long-tail benign
evaluation backlog item. A real operator-confirmed benign corpus still needs to
be evaluated and its aggregate result documented before that work is complete.


## CESNET real-traffic benign corpus sampling

For the first realistic long-tail benign-domain measurement, the project uses
the public 2024 DomainRadar dataset's `benign_cesnet.json` subset
(DOI `10.5281/zenodo.14332167`). The published subset contains 461,338
benign domains originating from real CESNET academic-network traffic and was
filtered by the dataset authors to reduce malicious/risky labels.

The enriched source file is about 6.4 GB, so ThreatFusion does not require the
entire file to be saved locally. `scripts/sample_cesnet_benign_domains.py`
streams the JSON array, keeps only normalized unique `domain_name` values,
stops once the requested sample size is reached, and closes the HTTP stream.
The raw enriched source is never written to disk by this script.

Default bounded collection:

```powershell
python scripts\sample_cesnet_benign_domains.py
```

The default target is 20,000 unique domains and writes:

- `data/evaluation/cesnet-benign-20k.csv`
- `data/evaluation/cesnet-benign-20k.metadata.json`

`data/evaluation/` is ignored by Git. The metadata records source DOI,
source file MD5 published by Zenodo, CC BY 4.0 attribution, requested/retained
counts, skip counts, streamed byte count, and the local CSV SHA-256. It does
not contain domain names.

Evaluate the frozen artifact on that locally sampled corpus with:

```powershell
python scripts\evaluate_ml_benign_telemetry.py `
  --artifact-dir data\models\development-001 `
  --development-snapshot-dir data\snapshots\baseline-001 `
  --dns-csv data\evaluation\cesnet-benign-20k.csv `
  --confirm-benign-label `
  --json-output data\evaluation\cesnet-benign-evaluation.json
```

Scientific limitation: the CESNET domain names were derived from real-network
TLS SNI observations rather than a DNS query-frequency sample. This makes them
valuable for evaluating lexical/domain diversity beyond Tranco Top 50k, but
the result must not be presented as a measurement of production DNS query
volume or alert frequency. Query-frequency-weighted behavior remains separate
future work.

## CESNET-augmented development comparison

After the frozen artifact produced a 3.60% high-threshold false-positive rate on
the retained CESNET benign corpus, threshold-only diagnostics showed that a
score threshold near 0.875784 reduced CESNET FPR to about 0.46% but retained
only about 15% malicious recall on the original development test.

The next development-only experiment therefore adds the confirmed-benign
CESNET domains that are not already present in the baseline snapshot to the
development dataset and repeats the low-FPR model comparison.

Run:

```powershell
python scripts\evaluate_ml_augmented_benign.py `
  --snapshot-dir data\snapshots\baseline-001 `
  --benign-dns-csv data\evaluation\cesnet-benign-20k.csv `
  --confirm-benign-label `
  --fpr-budgets 0.001 0.005 0.01
```

The tool:

- normalizes and deduplicates the added benign domains
- removes every domain already present in the baseline snapshot
- labels the retained additions as `CESNET`
- trains the same predefined candidate models in memory only
- selects thresholds on the augmented validation split
- reports overall development-test recall/FPR
- reports benign test FPR separately for Tranco and CESNET sources
- does not overwrite the existing frozen artifact

This corpus has already been inspected, so it is development evidence rather
than an untouched benchmark. Any model or threshold selected using this
experiment requires a new untouched final holdout before new final-performance
claims.

## Freeze the v2 development snapshot and artifact

Once the CESNET-augmented comparison has been reviewed, build a separate
development-v2 snapshot instead of overwriting the original baseline:

```powershell
python scripts\build_ml_augmented_snapshot.py `
  --base-snapshot-dir data\snapshots\baseline-001 `
  --benign-dns-csv data\evaluation\cesnet-benign-20k.csv `
  --output-dir data\snapshots\development-v2 `
  --confirm-benign-label
```

The snapshot metadata records the base benign snapshot, the augmentation
source identifier, the added-corpus SHA-256, overlap removal, and the explicit
benign-label basis.

Then train the selected development model with the lower operational budgets:

```powershell
python scripts\train_ml_artifact.py `
  --snapshot-dir data\snapshots\development-v2 `
  --output-dir data\models\development-v2 `
  --high-fpr-budget 0.001 `
  --medium-fpr-budget 0.005 `
  --low-fpr-budget 0.01
```

These correspond to 0.1%, 0.5%, and 1% validation FPR budgets. The output is a
new development-only artifact; it does not replace `development-001` unless
the operator explicitly chooses the same output path with `--overwrite`.

After the v2 artifact is frozen, collect a new untouched holdout. Do not reuse
the inspected CESNET 20k sample or the earlier final holdout as final evidence
for the v2 artifact.

## One bounded recall iteration

Before adding a more complex model family, ThreatFusion uses one intentionally
small development experiment around the current selected representation:
character 2-6 TF-IDF with sublinear term frequency and balanced Logistic
Regression. Only the Logistic Regression regularization strength changes.

Run it on the local v2 development snapshot:

```powershell
python scripts\evaluate_ml_recall_iteration.py `
  --snapshot-dir data\snapshots\development-v2 `
  --fpr-budgets 0.001 0.005 0.01
```

The comparison checks `C=0.5, 1, 2, 4` on one shared development split and
prints overall recall/FPR plus benign-source FPR and malicious-source recall.
This is development evidence only. If one candidate is selected from this
output, it must be frozen before another untouched final holdout.

## Freeze the bounded C=4 candidate

The bounded recall iteration selected only one candidate for a final holdout
check: the same 2-6 character TF-IDF + balanced Logistic Regression pipeline
with `C=4`. This is not a new model family.

Freeze it as a separate local artifact:

```powershell
python scripts\train_ml_artifact.py `
  --snapshot-dir data\snapshots\development-v2 `
  --output-dir data\models\development-v3-c4 `
  --model-name lr_char_2_6_balanced_c4 `
  --high-fpr-budget 0.001 `
  --medium-fpr-budget 0.005 `
  --low-fpr-budget 0.01
```

The runtime default remains unchanged until a new untouched holdout is
evaluated. Existing C=1 artifacts remain supported by the trusted artifact
loader.

## Post-freeze final temporal protocol

The frozen v1 C=4 artifact has a recorded SHA-256 identity:

```text
d2b6a34710312ecd80340d86b7118e3d2a94bfe258575ad7ccd34c87cf1639c3
```

For the final v1 evaluation, use the conservative protocol boundary
`2026-09-26T12:45:00+03:00`. The artifact had already been frozen before this
boundary; the timestamp is deliberately conservative and is not presented as
the exact byte-creation time.

The final protocol now separates the two evidence needs:

- malicious candidates come from ThreatFox, URLhaus and SGB cache snapshots
  refreshed after the post-freeze cutoff;
- malicious observations are normalized to domains and grouped **before**
  final dataset deduplication; the earliest usable `first_seen` across all
  retained source observations determines temporal eligibility;
- any domain whose earliest usable `first_seen` is on or before the cutoff is
  excluded, so a later observation from another source cannot hide known
  pre-freeze evidence;
- legacy cache timestamps without an explicit offset are interpreted as UTC,
  matching the collectors' UTC normalization for upstream timestamps;
- benign false-positive measurement uses an untouched deterministic window
  from the confirmed-benign CESNET real-traffic corpus;
- every domain already present in `development-v2` is removed again before
  scoring;
- malicious domains must have a usable earliest `first_seen` strictly after
  the cutoff;
- the C=4 model bytes and thresholds remain frozen.

Do not reuse `cesnet-benign-20k.csv`: it is development evidence. Create a
different CESNET window. For example, leave a 20,000-domain gap after the
development sample and retain the following 20,000 unique domains:

```powershell
python scripts\sample_cesnet_benign_domains.py `
  --skip-unique 40000 `
  --limit 20000 `
  --output-csv data\evaluation\cesnet-benign-final-20k.csv `
  --metadata-output data\evaluation\cesnet-benign-final-20k.metadata.json
```

The offset is deterministic. The final holdout builder also removes any
remaining normalized overlap with the full development snapshot, so the
evaluation does not rely on the offset alone.

Refresh the local CTI cache after the cutoff, then build the final snapshot
from that cache plus the untouched benign window:

```powershell
python scripts\build_ml_final_holdout.py `
  --db-path data\threatfusion.sqlite `
  --artifact-dir data\models\development-v3-c4 `
  --expected-artifact-sha256 d2b6a34710312ecd80340d86b7118e3d2a94bfe258575ad7ccd34c87cf1639c3 `
  --development-snapshot-dir data\snapshots\development-v2 `
  --benign-dns-csv data\evaluation\cesnet-benign-final-20k.csv `
  --confirm-benign-label `
  --benign-source-id cesnet-final-window-40k-60k `
  --holdout-snapshot-date YYYY-MM-DD `
  --malicious-first-seen-after 2026-09-26T12:45:00+03:00 `
  --output-dir data\snapshots\holdout-v3-c4-final
```

The builder refuses to proceed unless ThreatFox, URLhaus and SGB all have a
non-empty local cache refresh later than the cutoff. This makes temporary
upstream API failure a collection/refresh concern rather than a reason to
change the frozen evaluation protocol.

Evaluate the resulting snapshot with the exact same cutoff and trusted
artifact identity:

```powershell
python scripts\evaluate_ml_final_holdout.py `
  --artifact-dir data\models\development-v3-c4 `
  --expected-artifact-sha256 d2b6a34710312ecd80340d86b7118e3d2a94bfe258575ad7ccd34c87cf1639c3 `
  --development-snapshot-dir data\snapshots\development-v2 `
  --holdout-snapshot-dir data\snapshots\holdout-v3-c4-final `
  --malicious-first-seen-after 2026-09-26T12:45:00+03:00 `
  --json-output data\evaluation\final_holdout_v3_c4.json
```

This produces frozen high / medium / low threshold metrics, confusion-matrix
counts, 95% confidence intervals in the aggregate JSON report, and malicious
recall by retained source. Because the benign half is now confirmed-benign
CESNET rather than Tranco-only data, the reported FPR directly answers the
long-tail benign lexical false-positive question for this untouched window.

### Final C=4 temporal holdout result

The final frozen C=4 evaluation was completed on 2026-09-28 without retraining
or threshold tuning. After final development-overlap removal, the retained
holdout contained 240 post-freeze malicious domains and 19,912 confirmed-benign
CESNET domains.

Frozen operating-point results:

| Tier | Threshold | Recall | Recall 95% CI | FPR | FPR 95% CI | Precision | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| High | 0.938460 | 26.67% | 21.47–32.60% | 0.56% | 0.46–0.67% | 36.57% | 64 | 111 | 176 | 19,801 |
| Medium | 0.823553 | 50.42% | 44.13–56.69% | 2.35% | 2.15–2.57% | 20.54% | 121 | 468 | 119 | 19,444 |
| Low | 0.754178 | 55.42% | 49.09–61.57% | 4.08% | 3.81–4.36% | 14.07% | 133 | 812 | 107 | 19,100 |

Retained-source malicious recall was:

- SGB: 222 samples; High 27.93%, Medium 52.70%, Low 57.66%
- URLhaus: 18 samples; High 11.11%, Medium 22.22%, Low 27.78%
- ThreatFox: no eligible retained domain/URL samples in this temporal holdout,
  so source recall is unavailable rather than zero

The result demonstrates useful lexical signal on genuinely post-freeze
malicious domains, but the untouched benign CESNET false-positive rate is
materially above the development FPR budgets at the Medium and Low operating
points. The High tier is substantially more conservative, but it still misses
most malicious domains. For v0.1.0, the C=4 output therefore remains an
auxiliary signal inside the hybrid assessment rather than a standalone malware
verdict.

No threshold was changed after seeing these final results. Any future model,
feature, class-weight, sampling, or threshold change informed by this holdout
would make it development evidence and require a new untouched final holdout.

Precision in this report is still conditional on the retained holdout class
mix. It must not be presented as deployed-world PPV without a representative
malicious base rate.

The CESNET final window is untouched relative to model selection but comes
from the same published 2024 source corpus as the earlier development window.
The explicit offset and overlap removal prevent exact-domain reuse; they do
not prove independence of organization, domain family, or traffic-generating
process. Likewise, post-freeze malicious `first_seen` filtering improves
temporal separation but does not by itself eliminate campaign/source-family
leakage. Source-specific recall is only defined for sources that contribute
eligible domain/URL samples to the retained temporal holdout; a source with no
eligible domain-level samples must be reported as unavailable rather than
assigned a synthetic recall value. These limitations remain part of the final
interpretation.

## Post-final lexical feature development iteration

The completed C=4 temporal holdout is now inspected evidence. It must not be
used again to select or tune the next model. The next development iteration
therefore returns to the existing `development-v2` snapshot and compares the
current C=4 character model against a small domain-string-only extension.

The enhanced representation keeps the same character 2-6 sublinear TF-IDF and
adds 14 bounded lexical features:

- normalized domain length
- label count
- maximum and mean label length
- digit ratio
- hyphen ratio
- vowel ratio
- unique-character ratio
- normalized Shannon entropy
- longest digit-run ratio
- longest consonant-run ratio
- longest repeated-character-run ratio
- punycode-label ratio
- numeric-label ratio

These features use only the normalized domain string. They perform no DNS,
WHOIS, network, CTI, reputation, or web lookup. The lexical block is scaled on
the training split inside the scikit-learn pipeline so validation and
development-test rows do not influence feature scaling.

Run the bounded comparison locally:

```powershell
python scripts\evaluate_ml_feature_iteration.py `
  --snapshot-dir data\snapshots\development-v2 `
  --fpr-budgets 0.001 0.005 0.01
```

The shared development split compares:

- the current char 2-6 TF-IDF + balanced Logistic Regression C=4 baseline
- char 2-6 TF-IDF + lexical features with C=1
- char 2-6 TF-IDF + lexical features with C=2
- char 2-6 TF-IDF + lexical features with C=4

Thresholds are selected on VALIDATION only for the requested FPR budgets. The
script then prints development-test recall/FPR/precision, benign-source FPR,
and malicious-source recall. It does not persist or promote a model.

The development comparison selected
`lr_char_2_6_plus_lexical_c4` as the next candidate. At the shared
development-test operating points it improved the current C=4 baseline:

| Validation FPR budget | Baseline recall | Lexical C=4 recall | Baseline test FPR | Lexical C=4 test FPR | Baseline precision | Lexical C=4 precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.1% | 13.03% | 16.17% | 0.04% | 0.07% | 96.67% | 94.74% |
| 0.5% | 25.52% | 27.31% | 0.60% | 0.47% | 77.38% | 82.16% |
| 1.0% | 30.01% | 32.88% | 1.05% | 1.03% | 69.58% | 71.91% |

The 0.5% operating point is the clearest improvement: recall increased while
false-positive rate fell. The 0.1% point trades a small FPR increase for more
recall, so this remains development evidence rather than proof of final
generalization.

Freeze the selected candidate locally without overwriting the prior C=4
artifact:

```powershell
python scripts\train_ml_artifact.py `
  --snapshot-dir data\snapshots\development-v2 `
  --output-dir data\models\development-v4-lexical-c4 `
  --model-name lr_char_2_6_plus_lexical_c4 `
  --high-fpr-budget 0.001 `
  --medium-fpr-budget 0.005 `
  --low-fpr-budget 0.01
```

The resulting artifact remains development-only until a new untouched temporal
holdout is collected after the artifact freeze. The 2026-09-28 C=4 final
holdout cannot be reused as final evidence for this lexical candidate.

### Frozen lexical C=4 identity and next untouched holdout

The selected lexical C=4 artifact was frozen locally on 2026-09-28 with:

```text
model: lr_char_2_6_plus_lexical_c4
artifact SHA-256: 82f07f99820cea4ec2b8c2c07ab3d6a9387c87b17fafe1994d7730cc39386d14
freeze cutoff UTC: 2026-09-28T21:38:37.5577083Z
high threshold: 0.933823
medium threshold: 0.832484
low threshold: 0.760446
```

These bytes and thresholds are now frozen. Any retraining, feature change, or
threshold adjustment requires a different artifact identity and another fresh
holdout.

The previous benign evidence windows must not be reused:

- development: first 20,000 CESNET unique domains
- prior C=4 final holdout: CESNET unique-domain window 40,000–60,000

For the lexical C=4 final evaluation, reserve a new untouched deterministic
CESNET window 80,000–100,000, leaving an additional 20,000-domain gap after
the prior final window:

```powershell
python scripts\sample_cesnet_benign_domains.py `
  --skip-unique 80000 `
  --limit 20000 `
  --output-csv data\evaluation\cesnet-benign-lexical-final-20k.csv `
  --metadata-output data\evaluation\cesnet-benign-lexical-final-20k.metadata.json
```

The malicious half must come only from CTI cache refreshes performed strictly
after `2026-09-28T21:38:37.5577083Z`, and malicious domains must have an
earliest usable `first_seen` strictly after that same cutoff. Refreshing the
cache after the cutoff is necessary but does not by itself make older
indicators eligible.

Once all required CTI sources are refreshed after the cutoff, build the new
holdout with the frozen lexical artifact and the new benign window. Do not use
the prior `holdout-v3-c4-final` snapshot or its 2026-09-28 result to select,
tune, or validate this artifact.

## Reconstructed lexical C=4 holdout result

The originally recorded lexical artifact from the prior development workflow
was not present in this checkout. A separate development-only artifact was
therefore reconstructed from the refreshed local CTI cache and the pinned
Tranco `L5PV4` snapshot. Its identity was:

- model: `lr_char_2_6_plus_lexical_c4`
- artifact SHA-256: `8b207dc363edde3544a8dcd447b80968c433b1d2b929616d492d40d5204ef356`
- freeze cutoff: `2026-10-02T21:55:51Z`
- holdout benign window: CESNET unique-domain offset 80,000, 20,000 retained
  domains
- retained malicious domains: 155
- retained benign domains: 19,929

The frozen reconstructed artifact was evaluated once on the post-freeze
holdout without retraining or threshold tuning:

| Tier | Threshold | Recall | FPR | Precision | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| High | 0.995799 | 69.68% | 14.09% | 3.70% | 108 | 2,807 | 47 | 17,122 |
| Medium | 0.972128 | 82.58% | 25.60% | 2.45% | 128 | 5,102 | 27 | 14,827 |
| Low | 0.923755 | 86.45% | 33.99% | 1.94% | 134 | 6,773 | 21 | 13,156 |

The high recall is not operationally useful at these false-positive rates. The
reconstructed lexical candidate is therefore **not promoted** to the runtime
default. The runtime continues using the trusted existing development artifact
and lexical ML remains auxiliary inside the hybrid assessment. Any new model,
feature, sampling, or threshold change requires a new development iteration and
another untouched holdout.

## Reconstructed-snapshot feature iteration

After the reconstructed lexical C=4 holdout was rejected, a bounded feature
comparison was run on the reconstructed development snapshot only. The
completed post-freeze holdout was not reused for selection.

At the validation FPR budgets, the lexical C=4 candidate measured:

| Validation FPR budget | Development-test recall | Development-test FPR | Precision |
| --- | ---: | ---: | ---: |
| 0.1% | 58.95% | 0.13% | 99.98% |
| 0.5% | 77.50% | 0.47% | 99.94% |
| 1.0% | 84.30% | 1.07% | 99.87% |

Lexical C=2 reached 84.42% recall at the 1.0% budget, but its development
FPR was 1.12%; lexical C=4 remained the more conservative candidate at that
operating point and was stronger at the 0.5% budget. These development results
do not override the rejected post-freeze holdout result. No candidate was
promoted, and any new selection requires a new untouched holdout.

## Augmented lexical C=4 fresh-disjoint evaluation

The hard-negative development snapshot was used to train a new lexical C=4
artifact after adding a separate CESNET development window. A new CESNET
window at unique-domain offset 120,000 with 20,000 retained domains was then
collected for evaluation. The holdout removed every normalized domain present
in the augmented development snapshot before scoring.

The post-freeze temporal protocol could not retain malicious domains because
the refreshed feeds contained no usable `first_seen` values strictly after the
new artifact cutoff. A separate `fresh_collection_disjoint` evaluation was
therefore run without first-seen filtering. This protocol measures a fresh
collection boundary and domain disjointness, but it does not prove strict IOC
temporal separation.

Frozen augmented artifact results:

| Tier | Threshold | Recall | FPR | Precision | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| High | 0.995293 | 60.62% | 0.85% | 36.33% | 97 | 170 | 63 | 19,766 |
| Medium | 0.957530 | 78.75% | 1.95% | 24.51% | 126 | 388 | 34 | 19,548 |
| Low | 0.913834 | 81.87% | 2.62% | 20.03% | 131 | 523 | 29 | 19,413 |

These results are materially better than the earlier reconstructed temporal
experiment, especially at the High tier, and support keeping hard-negative
augmentation in further development. They are not strict temporal evidence and
do not by themselves justify runtime promotion. The artifact remains separate
from the runtime default pending a stronger temporal collection or an explicit
product decision to accept the fresh-disjoint limitation.

### Runtime decision and continuation audit — 2026-10-04

Runtime promotion is **deferred** (DEC-082). The augmented frozen identity is
`643b5adc1cf4bc4cb9c677df88aa4797dcbd6ae1be8ff0d0c0f4ee7d7f3e4cd9`, and its
recorded freeze cutoff is `2026-10-03T20:41:49Z`. A read-only local audit confirmed
the artifact identity and stored thresholds against the original collection and
report. It found zero eligible strict-temporal malicious domains: all 473,323
unique candidates have earliest usable first_seen at or before that cutoff.
No final scoring was repeated and no thresholds were changed.

The fresh-disjoint result retains only 160 malicious domains: 138 SGB domains
and 22 URLhaus domains, with no retained ThreatFox domains. High-tier recall is
69.57% for SGB and 4.55% for URLhaus (one of 22); these small, uneven subsets
limit source-generalization claims. The High FPR of 0.85% corresponds to roughly
85 false alarms per 10,000 benign domains in this corpus, exceeding its 0.1%
validation budget. This does not measure production query-frequency alert load.

The existing snapshot contains 493,259 pre-filter samples; its original
evaluator removed 473,163 development overlaps, retaining 160 malicious and
19,936 benign domains. It is preserved as historical evidence. New
`build_ml_fresh_disjoint_holdout.py` outputs remove overlap in both classes
before writing, refuse an empty class, and record
`evaluation_protocol=fresh_collection_disjoint` with
`temporal_first_seen_filter_applied=false`. This correction changes snapshot
preparation, not the previously reported metrics or temporal builder policy.

New schema-v4 reports include the evaluated `artifact_sha256`; schema-v1/v2/v3
reports remain readable and have no guaranteed byte identity. The evaluation
CLI checks the recorded frozen identity and development snapshot provenance
when supplied by the collection metadata. For temporal-builder snapshots it
requires the recorded explicit cutoff, so omitting or changing the cutoff
cannot silently weaken the report. Synthetic demo artifacts are refused as
final evidence. Loading any report in the UI is presentation only.

### Follow-up temporal readiness — 2026-10-04 local date

A separate ignored copy of the CTI cache was refreshed without changing the
original cache. SGB completed with 488,504 active records at
`2026-10-03T22:30:34.153113Z`. ThreatFox and URLhaus retained their earlier
post-cutoff snapshots because credentials were unavailable for a new keyed
refresh. PhishTank's access/security redirect prevented refresh; its previous
cache was preserved and it is not a required source for this ML protocol.

At `2026-10-03T22:36:15Z`, earliest-first-seen selection found 473,328 unique
malicious candidates: 473,323 at or before the same frozen cutoff, zero missing
usable timestamps, and **five** post-cutoff domains, all from SGB. Those five
are disjoint from the augmented development snapshot. This is a collection
readiness result, not model-performance evidence: no model prediction, threshold
tuning, final evaluation, or promotion was performed. Five examples from one
source do not supply the stronger temporal/generalization evidence needed.

Keep collecting permitted source snapshots into a separate local cache before
building a final holdout with a new untouched benign window. Do not repeat an
evaluation after each small feed update to select thresholds or models. The
readiness JSON and copied SQLite cache remain under ignored `data/evaluation/`;
only these aggregate counts are published. All 32 pre-existing local data files
retained their original checksums after this collection.

### Local assets and fresh clones

The CTI cache, dataset CSVs, CESNET windows, evaluation files and model binaries
are local/ignored assets. GitHub contains code, synthetic tests, methodology and
aggregate documentation. Git LFS does not resolve redistribution rights or
telemetry privacy and is not used for these datasets.

This checkout contains the reconstructed and augmented experimental artifacts,
but not the original configured `data/models/development-001` artifact. The
available demo runtime contains a separate synthetic `development-001` model
with `evaluation_status=demo_only_synthetic`.

A fresh clone can run the synthetic demo generator without feeds or credentials.
Real ML work requires locally acquiring permitted CTI and attributed benign
data, persisting development snapshots, training a new artifact and recording
its checksum/freeze time before collecting an untouched holdout. Live re-fetches
cannot reconstruct historical artifact identities or reproduce old metrics by
assumption. Keep development and inspected holdout windows separate, and do not
reuse the 120,000–140,000 CESNET window to select a successor.
