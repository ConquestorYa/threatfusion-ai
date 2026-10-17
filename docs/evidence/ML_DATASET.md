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
artifact policy. To quantify recall at low operational budgets:

```text
python scripts/evaluate_ml_fpr_comparison.py \
  --snapshot-dir data/snapshots/baseline-001 \
  --fpr-budgets 0.001 0.005 0.01
```

Those rates correspond to 0.1%, 0.5%, and 1% validation FPR budgets. This is
development analysis only: it does not rewrite the frozen artifact or change
runtime thresholds.

To measure the resulting score thresholds directly on the already-collected
confirmed-benign CESNET corpus without changing the artifact, pass them as
diagnostic thresholds:

```text
python scripts/evaluate_ml_benign_telemetry.py \
  --artifact-dir data/models/lexical-dev \
  --development-snapshot-dir data/snapshots/baseline-001 \
  --dns-csv data/evaluation/cesnet-benign-20k.csv \
  --confirm-benign-label \
  --diagnostic-thresholds <high> <medium> <low>
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
python scripts/train_ml_artifact.py --snapshot-dir data/snapshots/baseline-001 --output-dir data/models/lexical-dev
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


## Lexical C=4 holdout result

A development-only lexical artifact was built from the local CTI cache and the
pinned Tranco `L5PV4` snapshot (stored under the directory name
`reconstructed-development-lexical-c4`). Its identity was:

- model: `lr_char_2_6_plus_lexical_c4`
- artifact SHA-256: `8b207dc363edde3544a8dcd447b80968c433b1d2b929616d492d40d5204ef356`
- freeze cutoff: `2026-10-02T21:55:51Z`
- holdout benign window: CESNET unique-domain offset 80,000, 20,000 retained
  domains
- retained malicious domains: 155
- retained benign domains: 19,929

The frozen artifact was evaluated once on the post-freeze
holdout without retraining or threshold tuning:

| Tier | Threshold | Recall | FPR | Precision | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| High | 0.995799 | 69.68% | 14.09% | 3.70% | 108 | 2,807 | 47 | 17,122 |
| Medium | 0.972128 | 82.58% | 25.60% | 2.45% | 128 | 5,102 | 27 | 14,827 |
| Low | 0.923755 | 86.45% | 33.99% | 1.94% | 134 | 6,773 | 21 | 13,156 |

The high recall is not operationally useful at these false-positive rates. The
lexical candidate is therefore **not promoted**; the runtime stays CTI-only
without a lexical score. Any new model,
feature, sampling, or threshold change requires a new development iteration and
another untouched holdout.

## Development-snapshot feature iteration

After the lexical C=4 holdout was rejected, a bounded feature
comparison was run on the development snapshot only. The
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

These results are materially better than the earlier lexical C=4 temporal
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

The local lexical artifacts are experimental and not shipped. The demo
runtime uses a separate synthetic model with
`evaluation_status=demo_only_synthetic`.

A fresh clone can run the synthetic demo generator without feeds or credentials.
Real ML work requires locally acquiring permitted CTI and attributed benign
data, persisting development snapshots, training a new artifact and recording
its checksum/freeze time before collecting an untouched holdout. Keep development and inspected holdout windows separate, and do not
reuse the 120,000–140,000 CESNET window to select a successor.

## ThreatFox absence and candidate 2 (2026-10-10)

The augmented development snapshot's malicious side is 472,682 SGB and 493
URLhaus domains, **no ThreatFox**: the ThreatFox full-export parser stored every
row malformed (fixed in `3c054a3`). The frozen augmented model therefore never
saw malware command-and-control domains from ThreatFox. Its post-freeze temporal
evaluation (planned after the real-traffic capture, CESNET window offset 160,000)
will report recall per source.

Candidate 2 (`ml-candidate2-dev-v1`, private lab) was declared before training
and frozen at `2026-10-10T09:02:35Z`, artifact
`14acf4d0039ffb1dc2f85d1e9d10c3b4a8a54bd636f0e79fc33a7d7133fa3fb9`: same model
family (`lr_char_2_6_plus_lexical_c4`), same FPR budgets (0.1 % / 0.5 % / 1 %),
one training run. Malicious: 473,834 SGB + 39,152 ThreatFox domains from a frozen
cache copy; URLhaus hostnames excluded (often compromised legitimate hosts).
Benign: the existing development rows (Tranco L5PV4 + CESNET 100k–120k).
Validation-selected thresholds 0.988905 / 0.953436 / 0.906982. It is
development-only: no holdout result exists. Its evaluation needs indicators first
seen after its freeze (at least seven days) and the untouched CESNET window at
offset 200,000, declared separately and compared with the augmented model on the
same holdout.

## Strict temporal evaluation of the augmented model: failed (2026-10-11)

Private root `ml-lookup-temporal-v2` (plan sha256 `e92b53c2…`, summary
`f5c7940c…`, commit `84b892d`). Frozen augmented artifact `643b5adc…`,
thresholds unchanged. Malicious: CTI indicators first seen after the freeze
(2026-10-03T20:41:49Z), minus development domains: 5,558 (SGB 1,193, ThreatFox
4,245, URLhaus 120). Benign: untouched CESNET window 160k–180k (19,772 after
overlap removal). Primary configuration: the runtime popular-site context
(registrable domain in the Tranco top 100k gets no hint). Criteria declared
before the run, stricter than the never-declared draft.

| High tier (primary, popular-gated) | Result | Limit | Pass |
| --- | --- | --- | --- |
| False-positive rate, CESNET | 1.14 % (225 / 19,772) | ≤ 0.1 % | ✗ |
| High-tier hits in the user's own 24 h (621 names) | 1 (raw, ungated: 25) | ≤ 3 | ✓ |
| Recall | 12.9 % | ≥ 50 % | ✗ |
| Recall per source (n ≥ 50) | SGB 52.7 %, ThreatFox 1.9 %, URLhaus 6.7 % | each ≥ 25 % | ✗ |

Medium tier: recall 25.7 %, FPR 2.5 %; low tier: 32.2 %, 3.6 %. The
ungated reference is almost identical on CESNET (FPR 1.15 %, recall 13.0 %):
only 11.5 % of CESNET names have a popular registrable domain.

**Decision:** the score stays off; Quick Lookup shows no ML hint and the Model
evaluation page stays hidden. The CESNET 160k–180k window and these
post-freeze indicators are now inspected and must not be used for development.

**Reading:** ThreatFox recall is near zero because this model was trained while
the ThreatFox parser was broken (no ThreatFox domains in training; candidate 2
fixes that). The High threshold, calibrated mostly on Tranco names, is far too
permissive for real-traffic long-tail names. The popular-site gate removes most
false hits on the user's own traffic but does little on CESNET.

## Backdated temporal backtest of the candidate-3 recipe: failed (2026-10-11)

Private root `ml-backtest-v1` (plan `9ca5f496…`, summary `4d3420db…`, commit
`7c3c20b`). The user asked not to wait a week, so the recipe was tested
backdated: trained only on SGB + ThreatFox domains first seen up to
2026-10-03T20:41:49Z (505,573 malicious; 169,228 benign: Tranco, CESNET
100k–120k and new CESNET 240k–340k), three model families compared on the
development test split only (rule declared in advance; chosen:
`lr_char_2_6_plus_lexical_c4`, development-test High recall 60.7 % at FPR
0.098 %), then evaluated once on indicators first seen after the cutoff and the
untouched CESNET 200k–220k window. One method note: the first run stopped on a
broken download before any evaluation output and resumed from its receipts.

| High tier (popular-gated) | Result | Limit | Pass |
| --- | --- | --- | --- |
| CESNET false-positive rate | 0.23 % (45 / 19,929) | ≤ 0.1 % | ✗ |
| High-tier hits in the user's own 24 h (621 names) | 0 (ungated: 8) | ≤ 3 | ✓ |
| Recall | 16.3 % (906 / 5,558) | ≥ 50 % | ✗ |
| Recall per source | SGB 58.3 %, ThreatFox 4.7 %, URLhaus 9.2 % | each ≥ 25 % | ✗ |

Compared with the augmented model on the same malicious set, false positives
fell about five-fold (1.14 % → 0.23 %) and recall rose slightly (12.9 % →
16.3 %). Caveat: this malicious set was used in the previous evaluation and
motivated the recipe, so even this result may be optimistic.

**Conclusion.** Name-only (lexical) models do not reach the bar for new
indicators. The random development split (60.7 %) overstates real performance
because campaigns share names; new ThreatFox domains are lexically unlike older
ones (4.7 %). The score stays off; candidate 3 (`9c4aeae1…`, trained on all data
to 2026-10-11) is not promoted. Further lexical iteration is not planned. Next
directions: connection-behavior features from Zeek (needs the labeled 7-day
run) and, as a separate non-ML question for the user, domain-age context.

## Domain age as a signal: failed, development grade (2026-10-13)

Private root `ml-age-dev-v2` (plan `f53c25c3…`, amendment of `ml-age-dev-v1`
which stopped on a shutdown with no receipts; summary `451f9292…`). Rule: flag
a name when its registrable domain was registered at most D days ago (RDAP, the
same `domain_age.py` the app uses). D was chosen on development data only
(CESNET 240k–340k benign, 1,500 SGB + 1,500 ThreatFox malicious): the highest
recall with false-positive rate ≤ 0.1 % among age-known benign names. Chosen
D = 7 days (development: recall 10.9 %, FPR 0.074 %). Then evaluated once on
the `ml-backtest-v1` evaluation set. **Grade: development** — that set was
already evaluated once for the lexical model.

| Age ≤ 7 days | Result | Limit | Pass |
| --- | --- | --- | --- |
| CESNET false-positive rate (age-known) | 0.088 % (9 / 10,225); all rows 0.045 % | ≤ 0.1 % | ✓ |
| Recall | 10.7 % (594 / 5,558) | ≥ 50 % | ✗ |
| Recall per source | SGB 34.4 %, ThreatFox 4.1 %, URLhaus 9.2 % | each ≥ 25 % | ✗ |

RDAP coverage: 4,654 found, 2,076 not found, 318 errors (rate limits); about
half of the benign names and 70 % of the evaluated malicious names had a known
age. Secondary combinations with the backtest lexical model all broke the FPR
limit (best recall: age ≤ 7 d or lexical High, 22.1 % at FPR 0.53 %).

**Reading.** A very new domain is a precise warning (603 flags, 594 of them on
indicators) but most indicators are not new: phishing kits (SGB) often are,
malware infrastructure (ThreatFox) mostly is not (older or compromised domains,
shared platforms). Age stays what DEC-095 made it: context on a button, never a
verdict. Nothing is promoted; no model ships. Name and age signals together are
below the bar, so the next ML direction is connection behavior from the labeled
P2 7-day run (ends 2026-10-18).

## Connection-behavior model v1: failed (2026-10-14)

Private roots `ml-behavior-dev-v1-amend-1` (plan `fb3b1d4a…`, summary
`83d047f5…`) and `ml-behavior-recent-v1-amend-1` (plan `b8878e60…`, summary
`9a200e03…`). Amendments of the v1 roots: the first run crashed writing a numpy
bool after development scoring and before any evaluation output (dev candidate
results were seen; rules unchanged). Model: random forest family over 23
behavior features per (device, destination, port, protocol, 24 h window)
(`ml_behavior.py`). Training: Stratosphere MCFP malware captures (2011–2021,
infected host's groups to non-popular destinations labeled malicious), MCFP
normal captures and three days of the user's traffic. Captures split by number
60/15/25 %. Chosen on development data: extra-trees, leaf 10, line 0.991
(development: 86 % of malware captures, 1 flag per normal host-day).

| Evaluation | Result | Limit | Pass |
| --- | --- | --- | --- |
| MCFP held-out malware captures caught | 41.0 % (16 / 39); 56 % of malicious groups | ≥ 50 % | ✗ |
| MCFP held-out normal host-days, flags per day | 0.0 (only 1 host-day had groups) | ≤ 1 | ✓ (thin) |
| Recent malware 2023–2026 (Malware-Traffic-Analysis.net), captures caught | 3.0 % (5 / 168); 2024–2026: 0 / 82 | ≥ 50 % | ✗ |

**Reading.** The model does not generalize. Two causes are visible in the
aggregates: (1) label shortcut — malware groups to popular names were dropped
as ambiguous, so "popular name" (31 % of importance) and "has a name" separate
the classes without describing behavior; (2) length shift — MCFP captures last
hours to days, recent captures minutes, so span/active-hours features never look
like training malware. The normal side had too little held-out data.

**Decision.** Not installed; the app shows "no model". The recent set
(Malware-Traffic-Analysis 2023–2026) is now inspected: later use is development
grade unless new posts after 2026-10-14 are used. Next (v2): per-flow expert
labels from CTU-SME-11 (2023, CC BY 4.0) instead of capture heuristics, no
dropped classes, training windows of random length (minutes to a day),
synthetic jittered beacons injected into real benign traffic, first-seen and
DNS features, and P2 v2 days for the user's false flags.

## Connection-behavior model v2: failed (2026-10-14)

Private root `ml-behavior-dev-v2` (plan `e73a4585…`). Feature schema 2
(`ml_behavior.py`, commit 8130bb9): `popular_name` removed from model inputs,
DNS resolver traffic (53/853) out of scope, new rate and name-randomness
features. Training adds CTU-SME-11 (Zenodo 7958259, CC BY 4.0; 8 devices with
complete archives, per-flow expert labels) and Malware-Traffic-Analysis.net
2023–2024, with 1 h / 6 h / 24 h training windows. Chosen on MCFP development
captures: random forest, leaf 5, depth 24, line 0.867.

| Test | Result | Limit | Pass |
| --- | --- | --- | --- |
| T1 CTU-SME-11 leave-one-device-out, malware units caught | 57 % (4 / 7: Redline, Remcos exfiltration, Octo, honeypot attacker; missed Trickbot, AgentTesla, Remcos tool access) | ≥ 50 % | ✓ |
| T2 MCFP held-out malware captures caught | 54.7 % (35 / 64) | ≥ 50 % | ✓ |
| T3 Recent malware 2025–2026 captures caught (development grade) | 17.3 % (9 / 52) | ≥ 50 % | ✗ |
| T4 False flags per day: MCFP normal held-out / user eval day | 0.33 (6 host-days) / 0.0 (1 day) | ≤ 1 | ✓ |
| T5 Synthetic beacons caught, jitter 0 / 10 / 20 % | 8 / 27 / 20 % | ≥ 70 % | ✗ |

**Reading.** Removing the popularity shortcut helped (recent 3 % → 17 %;
MCFP 41 % → 55 %), but the model still learns what lab malware captures look
like — byte sizes lead the importance — not command-and-control rhythm: a
perfectly regular synthetic beacon is caught 8 % of the time. Labeled C2 in
public data is too scarce and too capture-specific for a supervised verdict.

**Decision.** Not installed. Next: rhythm is scored directly (a measured
beaconing score, checked against synthetic beacons and SME-11 C2), and the app
learns this computer's own baseline ("unusual for this computer") and the
user's review marks, which need no malware labels.

## Rhythm score: failed alone (2026-10-14)

Private root `ml-rhythm-v1` (plan `7bcb61f9…`, summary `927dd0e0…`). A fixed
RITA-style score (`rhythm.py`: Bowley skew and MAD regularity of gaps and sent
sizes, coverage, small payloads; no training). One line set on development
benign data (MCFP normal dev, the user's dev day; ≤ 1 flag per day): it rose
to **0.990**, because normal traffic already contains near-perfect rhythms
(updaters, push and sync). At that line: 0 % of synthetic beacons at any
jitter, 0 / 7 CTU-SME-11 C2 units, 0 / 52 recent captures, 0 false flags.
**Reading:** rhythm cannot separate call-home malware from normal software on
its own. Not shown as a detector.

## New for this computer + rhythm (2026-10-14)

Private roots `baseline-burden-v1` (plan `abc46914…`, summary `e3fbe87a…`) and
`baseline-burden-v2` (plan `5302983f…`, amendment). Each device is replayed day
by day with a memory of earlier days only (`baseline.py`: registrable domain,
or the IP without a name; 3 learning days).

| Measure (development) | Result | Limit | Pass |
| --- | --- | --- | --- |
| New destinations with ≥ 4 connections per normal SME-11 device-day | 14.7 (max 163) | ≤ 10 | ✗ |
| … of those also rhythm ≥ 0.8, per normal SME-11 device-day / user day | 0.5 / 0.0 (1 day) | ≤ 1 | ✓ |
| SME-11 C2 destinations that were new when first seen (after learning) | 2 / 6 | ≥ 50 % for any catch claim | ✗ |

**Decision.** The full list is too long. The app shows only the narrow list
(new for the device **and** steady rhythm) in the Experimental ML tab, as "a
reason to look, not a malware verdict", with no catch claim. Its burden is
development grade (the narrowing was chosen after seeing v1); the binding check
replays the untouched P2 v2 days (≤ 1 entry per active day) after the run ends.
