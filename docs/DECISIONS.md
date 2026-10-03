# Architecture Decision Log

## DEC-001: Multi-source rather than USOM-only

**Decision:** Build a multi-source CTI workflow rather than recreate a single public feed.

**Reason:** USOM is valuable as a data source, but merely recreating USOM would provide little added value. Combining sources with local telemetry supports questions that a public feed alone cannot answer.

## DEC-002: Common `IOCRecord` model

**Decision:** Map provider records into one common internal `IOCRecord` representation.

**Reason:** Different CTI providers must be represented consistently before correlation, matching, and later analysis can be reliable.

## DEC-003: Keep normalization separate from data models

**Decision:** Keep canonicalization functions outside the dataclasses.

**Reason:** Models describe data; normalization transforms external values. This separation keeps the model simple and makes transformations independently testable.

## DEC-004: Preserve original IOC evidence during correlation

**Decision:** Correlation groups equivalent indicators without replacing or deleting the original records.

**Reason:** Source, timing, tags, and other evidence remain important to an analyst. Grouping should organize evidence, not destroy it.

## DEC-005: Threat URLs are data only

**Decision:** Never automatically visit, resolve, open, or follow malicious IOC URLs.

**Reason:** Feed URLs are untrusted indicators. Collectors contact only their official feed endpoints, and returned IOC values are handled as text.

## DEC-006: ML rather than LLM for primary detection

**Decision:** Use machine learning for primary malicious-domain detection; reserve LLM use for optional explanation and reporting.

**Reason:** Detection should be measurable, reproducible, and independently evaluated rather than delegated to a language model whose output is difficult to validate as a detector.

## DEC-007: Start with explainable baseline ML

**Status:** IMPLEMENTED.

**Decision:** The initial malicious-domain approach uses character n-gram TF-IDF with Logistic Regression. Other classical models may be compared later.

**Reason:** This baseline is understandable, reproducible, and suitable for measuring feature and model behavior in a student project.

## DEC-008: Prevent ML data leakage

**Status:** IMPLEMENTED IN EVALUATION WORKFLOW; STRICT TEMPORAL CLAIMS REMAIN LIMITED.

**Decision:** Model development uses domain-disjoint train/validation/test
splits, validation-only threshold selection, source-aware diagnostics, and
fresh holdout workflows with optional first-seen filtering. The evaluator
describes the general fresh holdout protocol as
`fresh_collection_disjoint`; a collection timestamp alone is not treated as
proof that every IOC is temporally independent.

**Reason:** Threat intelligence and DNS observations are time-dependent, and
careless splitting can let information from the future or from the same source
leak into evaluation data. The implemented safeguards improve separation
without overstating what the available IOC timestamps prove.

## DEC-009: Secrets never stored in source control

**Decision:** API keys and other secrets must be supplied through environment variables or equivalent runtime configuration. Secret files are protected by `.gitignore`.

**Reason:** Credentials must not be embedded in source code, documentation, tests, or commits.

## DEC-010: Incremental development

**Decision:** Work in small feature increments: implementation, focused tests, Ruff, review, and Git commit.

**Reason:** Small changes make behavior easier to verify and keep the educational codebase understandable.

## DEC-011: Keep architecture simple

**Decision:** Avoid unnecessary frameworks, cloud services, and database complexity during the three-week student-project scope.

**Reason:** The project should prioritize understandable, reproducible core data and detection workflows over infrastructure that does not yet support a demonstrated requirement.

## DEC-012: SQLite for initial local persistence

**Status:** IMPLEMENTED.

**Decision:** Use SQLite as the initial local persistence layer when storage is implemented.

**Reason:** SQLite is lightweight, reproducible, and appropriate for a local educational prototype before any need for a larger database service is demonstrated.

## DEC-013: Use the current SGB API rather than build against legacy USOM naming/endpoints

**Decision:** Use the current official Siber Guvenlik Baskanligi API as the Turkish public threat-intelligence source. The code uses the neutral/current source label `SGB`.

**Reason:** The project should integrate with the current official service while preserving the original project goal of incorporating Turkish national threat intelligence.

## DEC-014: Preserve raw DNS query evidence during ingestion

**Decision:** Do not lowercase or otherwise canonicalize `query_name` when ingesting DNS CSV telemetry.

**Reason:** The original observation should remain intact. Normalization is applied only when comparing values during matching.

## DEC-015: Match URL IOCs by hostname without visiting them

**Decision:** For URL IOC records, extract the hostname locally with `urllib.parse` and compare it with DNS queries.

**Reason:** DNS telemetry observes domains and hostnames rather than full URLs, while threat URLs must remain inert data and must never be visited or resolved.

## DEC-016: Preserve source evidence during DNS IOC matching

**Decision:** Return one `DNSIOCMatch` per matching `IOCRecord` rather than deduplicating matches from multiple sources.

**Reason:** A ThreatFox and SGB record referring to the same indicator are independent evidence and should remain visible to later scoring and reporting logic.

## DEC-017: Tune high-recall thresholds on validation data only

**Decision:** High-recall operating thresholds are selected on a dedicated validation split and are never selected by inspecting test-set performance.

**Reason:** Lowering a classifier threshold can increase malicious-domain recall, but choosing that threshold on the test set would leak evaluation information and make the reported result optimistic. An untouched test set provides a more credible final measurement of each validation-selected operating point.


## DEC-018: Compare useful recall under explicit false-positive budgets

**Decision:** After the high-recall experiment, compare a small predefined set
of classical domain-string models at validation false-positive-rate budgets of
0.1%, 1%, 5%, and 10%.

**Reason:** Maximizing recall without constraining false positives can produce
an unusable detector. Security operations need to understand how much malicious
coverage is achievable at an acceptable alert cost. Model and threshold
selection therefore happen on validation data under explicit false-positive
constraints.

## DEC-019: Treat the repeatedly inspected test split as development-only

**Decision:** The current shared test split is a development test once its
results have influenced further model choices. It must not be used as the sole
basis for final performance claims.

**Reason:** Repeatedly inspecting test results indirectly tunes development to
that data. Final reported performance should later be measured on a fresh
source-aware or time-aware holdout.


## DEC-020: Use source-wise recall as diagnosis, not model tuning

**Decision:** Report malicious-domain recall separately by retained CTI source
on the development test split, but do not use those source-wise test results to
retune thresholds or select a final model.

**Reason:** Aggregate recall can hide that one feed type is much harder than
another. Source-wise diagnostics help explain failure modes, while keeping
model selection on validation data avoids additional test leakage.


## DEC-021: Keep the wider Logistic Regression model as the development candidate

**Decision:** Use character 2-6 TF-IDF with sublinear term frequency and
balanced Logistic Regression as the current development candidate.

**Reason:** It achieved the highest validation recall among the three tested
classical candidates at every evaluated false-positive-rate budget. This is a
development choice only; final claims still require a fresh holdout.

## DEC-022: Use hybrid evidence instead of treating string-only ML as the whole detector

**Decision:** Combine known IOC matches, domain-string ML evidence, and local
DNS behavior in an explainable hybrid assessment.

**Reason:** Source-wise diagnostics show that domain-string ML alone misses a
substantial fraction of retained ThreatFox and URLhaus malicious domains at
usable false-positive rates. Some malicious activity cannot be inferred from a
domain string alone.

## DEC-023: DNS behavior signals are heuristic context, not malware proof

**Decision:** DNS behavior features may strengthen a risk assessment or trigger
review, but behavior alone is not described as confirming malware.

**Reason:** High query volume, multiple clients, IP diversity, and similar
patterns can also occur in benign services. The prototype should expose these
signals transparently without overstating what they prove.


## DEC-024: Persist the train-only development model with validation-selected thresholds

**Decision:** Persist the selected character 2-6 sublinear TF-IDF + balanced
Logistic Regression pipeline together with validation-selected thresholds at
1%, 5%, and 10% FPR budgets.

**Reason:** Runtime inference should not retrain the model every time the
application starts. The thresholds were selected for the train-only fitted
model, so refitting on validation or development-test data would change model
scores and invalidate those operating points.

## DEC-025: Treat joblib model files as trusted local artifacts only

**Decision:** Load joblib/pickle-compatible model artifacts only when they were
generated locally by this project and are trusted.

**Reason:** Python pickle-compatible formats can execute code during loading.
They are suitable for this local educational workflow but must not be treated
as safe interchange formats for untrusted files.


## DEC-026: Use one local runtime orchestration layer before building the UI

**Decision:** Route DNS telemetry through a reusable runtime module that combines
known IOC matching, persisted ML inference, DNS behavior aggregation, and
hybrid assessment before adding Streamlit presentation logic.

**Reason:** The analysis workflow should be independently testable and reusable
outside the web interface. Keeping Streamlit separate from detection logic
prevents UI code from becoming the source of security or ML behavior.


## DEC-027: Persist analysis history without raw DNS telemetry by default

**Decision:** Store completed analysis summaries and per-domain findings in
SQLite, but do not persist raw uploaded DNS rows or client IP values by default.

**Reason:** The dashboard needs history and explainable findings, while DNS
telemetry can contain sensitive browsing and internal-network information.
Keeping raw telemetry ephemeral reduces unnecessary privacy risk and still
supports useful analysis history.

## DEC-028: Keep persistence separate from runtime detection logic

**Decision:** The runtime analysis pipeline returns in-memory evidence and
assessments; SQLite persistence is an explicit separate step.

**Reason:** Detection should remain testable without a database, and callers
should be able to choose whether an analysis is saved. This separation also
makes a future privacy mode straightforward.


## DEC-029: Refresh CTI separately from user analysis

**Decision:** Cache ThreatFox, URLhaus, PhishTank, and SGB IOC records locally
in SQLite and refresh that cache through an explicit maintenance workflow
rather than calling external CTI services during each user analysis.

**Reason:** User analyses should be fast, reproducible, and independent of
temporary feed/API availability. Separating refresh from analysis also avoids
needlessly exposing credentials to the interactive application path.

## DEC-030: Replace cached CTI per source only after successful fetch

**Decision:** The cache replacement operation is source-scoped and atomic.
Existing records for a source are replaced only after the caller has already
obtained a complete successful result for that source.

**Reason:** A failed network request must not erase the previous usable cache.
The storage layer itself remains network-free.


## DEC-031: Keep the Streamlit dashboard as a thin presentation layer

**Decision:** The Streamlit application calls the existing runtime, cache, and
persistence modules rather than implementing detection logic inside UI code.

**Reason:** Security and ML behavior must remain independently testable. A thin
UI also makes it easier to replace Streamlit later without rewriting the core
analysis pipeline.

## DEC-032: Raw DNS persistence remains opt-in by design and disabled in the MVP

**Decision:** The Streamlit MVP analyzes uploaded DNS CSV content in memory and
does not persist raw DNS rows or client IP values. Saving aggregate/per-domain
analysis history requires an explicit user action.

**Reason:** DNS telemetry can reveal sensitive browsing and internal-network
information. The portfolio demo should minimize retention by default.


## DEC-033: Present verdicts explicitly at domain level

**Decision:** Dashboard verdict counts and charts are labeled as domain-level
results, while DNS event counts are shown separately.

**Reason:** Multiple DNS telemetry rows can belong to one normalized domain.
Separating these units avoids making users think that event counts should sum
to verdict counts.

## DEC-034: Translate internal reason codes at the presentation boundary

**Decision:** Keep stable machine-readable reason codes inside the analysis and
persistence layers, but translate them into human-readable evidence text in the
dashboard layer.

**Reason:** Internal codes are useful for tests and storage, while portfolio and
analyst-facing UI should explain findings without requiring knowledge of code
identifiers.


## DEC-035: Treat campaign discovery as possible related activity

**Decision:** Group non-low domains into possible related-activity components
only when local DNS telemetry shows at least one shared client observation or
shared response IP. Time proximity is supporting context only.

**Reason:** Temporal coincidence by itself is weak evidence. Requiring a shared
local observation keeps the first clustering baseline conservative and easy to
explain.

## DEC-036: Do not expose raw client IP values in relationship output

**Decision:** Campaign/relationship presentation reports aggregate shared-client
counts and reason labels, not the actual client IP values.

**Reason:** Client IPs are sensitive local telemetry. The dashboard can explain
why two domains were linked without exposing the underlying identifiers.


## DEC-037: Invalidate displayed analysis when upload content changes

**Decision:** The Streamlit layer fingerprints uploaded CSV bytes and clears the
current in-memory analysis whenever the upload is changed or removed.

**Reason:** Showing results from a previous file beside a newly selected file
would be misleading. The fingerprint is used only for local UI state and does
not persist the uploaded DNS content.


## DEC-038: Use a deterministic presentation-only relationship graph

**Decision:** Render related-activity clusters with a deterministic circular
layout computed from already-derived relationship objects, without adding a
graph-analysis dependency.

**Reason:** The graph is a visual explanation of existing clustering evidence,
not a second clustering algorithm. Keeping layout logic presentation-only
avoids changing detection semantics and keeps the dependency stack simple.

## DEC-039: Keep relationship graph hover data aggregate-only

**Decision:** Graph nodes may show domain verdict/ML tier/CTI source metadata,
while edge hover text shows shared-client counts, shared-response-IP counts,
time distance, and human-readable evidence labels only.

**Reason:** The graph should explain why domains are linked without exposing raw
client IP identifiers or other sensitive local telemetry.


## DEC-040: Freeze the model and thresholds before final holdout evaluation

**Decision:** Final holdout evaluation loads the existing trusted development
artifact and applies its stored high / medium / low thresholds without
retraining or retuning.

**Reason:** The final holdout must measure a decision that was made before its
labels/results were inspected. Retraining or threshold selection on the
holdout would turn it into development data.

## DEC-041: Remove all development-snapshot domain overlap from the holdout

**Decision:** Any normalized domain present anywhere in the development
snapshot is excluded from the final holdout before metrics are calculated.

**Reason:** This conservative rule prevents direct domain memorization/leakage
from inflating final metrics. It is stricter than checking only the model's
training partition and makes the evaluation boundary easy to explain.

## DEC-042: Describe the protocol as fresh-collection disjoint, not strict temporal

**Decision:** The implemented final evaluator is described as a
fresh-collection disjoint holdout. It is not labeled a strict time-based
IOC evaluation.

**Reason:** DomainSample currently stores domain, label, and source but not IOC
first_seen timestamps. Snapshot collection date provides a later collection
boundary, but it does not prove each malicious IOC first appeared after model
development.


## DEC-043: Disable shared analysis history in public mode

**Decision:** When `THREATFUSION_PUBLIC_MODE=1`, the interactive dashboard
does not expose saved-analysis history and does not offer the save-history
action.

**Reason:** A public multi-user demo must not allow one anonymous visitor to
browse another visitor's persisted domain findings. Local mode keeps the
existing explicit-save history workflow.

## DEC-044: Keep CTI refresh credentials out of the public request path

**Decision:** The public dashboard reads an already-prepared local CTI cache and
trusted model artifact. ThreatFox/URLhaus credentials are not required by the
interactive application.

**Reason:** Feed refresh is a maintenance concern. Separating it from user
analysis reduces credential exposure and keeps user requests independent of
external feed availability.

## DEC-045: Package the hosted demo as a non-root container

**Decision:** Provide a minimal Python 3.12 container that runs Streamlit as a
non-root user, excludes local data/secrets from the build context, and uses
Streamlit's health endpoint for process health.

**Reason:** This provides a reproducible hosting boundary without embedding
local SQLite/model artifacts or credentials in the image.


## DEC-046: Deploy a sanitized CTI/model bundle instead of the developer data tree

**Decision:** Hosted runtime preparation creates a new minimal directory
containing a CTI-only SQLite database and the trusted local ML artifact. The
developer's full `data/` directory is never the recommended public runtime
mount.

**Reason:** Local development data can contain saved analysis history and
dataset snapshots that are unnecessary for public analysis. Rebuilding a
CTI-only database makes the privacy boundary explicit and reduces accidental
data exposure.

## DEC-047: Validate the trusted model before copying it into a deployment bundle

**Decision:** Deployment-bundle creation loads and validates the trusted local
ML artifact before copying its model and metadata files.

**Reason:** A hosted bundle should fail early if the configured model artifact
is missing or incompatible rather than creating a partially valid runtime
directory.


## DEC-048: Keep downloadable reports aggregate and privacy-safe

**Decision:** JSON and CSV exports contain analysis summary information and
per-domain aggregate findings, but exclude raw DNS rows, client IP values, and
response IP values.

**Reason:** Portable reports are useful for sharing findings and portfolio
demonstration, but exporting raw local telemetry would unnecessarily increase
privacy risk. Counts and evidence labels provide useful analyst context without
including those identifiers.

## DEC-049: Generate reports from the current in-memory result

**Decision:** Report export is built from the existing `RuntimeAnalysisResult`
and does not query external services or require the analysis to be saved in
SQLite first.

**Reason:** Report generation should remain independent of persistence and work
in public mode, where shared history is intentionally disabled.


## DEC-050: Persist final holdout results as aggregate-only JSON

**Decision:** The frozen holdout evaluator may write a deterministic JSON
report containing snapshot metadata, aggregate operating-point metrics, and
source-wise malicious recall, but no domain rows.

**Reason:** The dashboard and hosted demo should be able to show model
evaluation evidence without shipping the holdout dataset itself or exposing
individual malicious/benign domains.

## DEC-051: Treat the model-evaluation dashboard as read-only evidence

**Decision:** The Streamlit Model evaluation tab reads an already-generated
holdout report and never retrains the model or changes thresholds.

**Reason:** Final evaluation must remain separated from model development.
Turning the dashboard into a tuning surface would weaken the frozen-holdout
boundary.


## DEC-052: Keep analyst feedback separate from detector output

**Decision:** Analyst feedback is stored as local review context for a saved
run/domain and does not overwrite the original hybrid verdict, ML score, or
evidence.

**Reason:** Human review is useful operational context, but silently rewriting
the detector's historical output would make the system harder to audit and
evaluate.

## DEC-053: Do not retrain automatically from analyst feedback

**Decision:** Confirmed Threat / Benign / Uncertain feedback is not consumed by
the model-training pipeline automatically.

**Reason:** Feedback can be noisy or inconsistent. Any future use as training
data should require a separate curated dataset/versioning workflow so model
changes remain reproducible.

## DEC-054: Keep analyst feedback local/private

**Decision:** Analyst feedback is available only through saved local history.
Public mode keeps shared history and feedback disabled, and sanitized
deployment bundles do not copy the developer analysis-history database.

**Reason:** Analyst notes and reviewed domain findings may contain
organization-specific context that should not be exposed to anonymous hosted
demo users.

## DEC-055: Treat exported CSV as untrusted spreadsheet input

**Decision:** CSV report cells that begin with spreadsheet formula prefixes are
escaped before export. JSON report values remain unchanged.

**Reason:** DNS query values are user-controlled telemetry. Opening a CSV in a
spreadsheet must not allow a crafted value to be interpreted as a formula.


## DEC-056: Bound interactive DNS analysis

**Decision:** Runtime analysis rejects inputs above explicit event and unique
query-name limits.

**Reason:** The public/local analysis path should have predictable resource
usage even when input is malformed or intentionally oversized. The existing
Streamlit upload-size limit is helpful but is not a complete processing bound.


## DEC-057: Score only suitable internet-domain candidates with ML

**Decision:** Reverse-DNS names, mDNS/local names, localhost, and single-label
hostnames remain available to deterministic IOC matching and DNS behavior
analysis but are excluded from malicious-domain string-model inference.

**Reason:** The development model was trained on internet domain samples.
Scoring clearly out-of-distribution DNS names creates misleading model output
without adding useful evidence.


## DEC-058: Surface CTI freshness and avoid quadratic unrelated-domain scans

**Decision:** The dashboard marks CTI source cache entries as fresh/stale using
their stored refresh timestamps, and related-activity discovery generates
candidate domain pairs only from shared-client/shared-response-IP evidence.

**Reason:** Analysts should know when deterministic threat intelligence may be
out of date. Related-activity analysis should also avoid comparing every
suspicious domain pair when most pairs have no shared evidence.

## DEC-059: Distinguish unscored DNS names from below-threshold ML scores

**Decision:** Analyst-facing views and exports display `Not scored` when a DNS
name was intentionally excluded from the internet-domain ML model. `Below
threshold` is reserved for names that were actually scored but did not reach
the lowest configured threshold.

**Reason:** Treating an out-of-scope name as if the model scored it creates
misleading evidence and makes analyst review less auditable.


## DEC-060: Preserve DNS ingestion quality diagnostics

**Decision:** CSV parsing records aggregate counts for accepted rows, missing
query names, malformed timestamps, and invalid response IPs. The runtime can
return those diagnostics without persisting raw DNS rows.

**Reason:** Analysts need to know whether malformed input reduced the evidence
available to the detector, while the project's privacy boundary should remain
aggregate-only.


## DEC-061: Present IOC evidence by scope and retain source metadata

**Decision:** Known-IOC presentation distinguishes exact domain IOC evidence,
URL-hostname evidence, and response-infrastructure IOC evidence. Existing
first/last-seen timestamps, threat type, confidence, and tags are shown when
available.

**Reason:** These match types do not imply identical evidence semantics.
Preserving their scope gives analysts more context without changing the current
hybrid-verdict policy.


## DEC-062: Reject unexpectedly empty multi-source CTI refresh batches

**Decision:** The explicit refresh workflow validates that every expected CTI
source returned at least one record before replacing any cached source.

**Reason:** A transient upstream/API anomaly that returns an empty result should
not silently erase a previously healthy local CTI cache.


## DEC-063: Use ordered timestamp comparison for related activity

**Decision:** Closest event-time distance between related domains is computed
with sorted timestamp groups and a two-pointer scan instead of comparing every
timestamp pair.

**Reason:** Related-activity timing should preserve the same result while
remaining predictable for domains with many DNS observations.

## DEC-064: Make the dashboard analyst-first rather than chart-first

**Decision:** The primary analysis view presents priority findings and domain
investigation before secondary charts and full evidence tables. Low findings
remain available in the complete findings view but do not dominate the initial
triage surface.

**Reason:** The dashboard should help an analyst decide what needs attention
before presenting visualization. This improves operational usefulness without
changing detector output.


## DEC-065: Keep dashboard triage controls presentation-only

**Decision:** History verdict/review/source filters and compact system-health
presentation operate only on already-derived or persisted findings. They do not
change verdicts, model scores, CTI evidence, analyst feedback, or saved data.

**Reason:** UI ergonomics should improve review speed without creating a second
hidden decision layer or weakening auditability.

## DEC-066: Reserve Known Threat for exact known-domain IOC matches

**Decision:** Only a normalized DNS query that directly matches a DOMAIN IOC
automatically receives the `known_threat` verdict. A URL IOC whose hostname
matches the query and an IP IOC that matches a DNS response remain deterministic
CTI context, but by themselves produce at most `review`.

**Reason:** A malicious URL can be hosted on an otherwise shared hostname and a
malicious IP can be shared by unrelated domains. Treating those infrastructure
associations as proof that the queried domain itself is malicious overstates
the evidence.


## DEC-067: Support Zeek dns.log as a first real telemetry adapter

**Decision:** ThreatFusion accepts standard Zeek `dns.log` text exports through
a local parser that maps the standard fields into the existing `DNSEvent`
model and preserves aggregate ingestion diagnostics.

**Reason:** Requiring users to transform established security telemetry into a
project-specific CSV adds unnecessary friction. Reusing `DNSEvent` keeps the
runtime detector independent of input format and adds no networking.


## DEC-068: Surface prior analyst review without changing detector output

**Decision:** Local mode may retrieve and display the most recent saved analyst
feedback for a domain when that domain appears again in a later analysis.
Public mode does not read this private context.

**Reason:** Analysts should not repeatedly rediscover a previously reviewed
domain, but historical human judgment must remain separate from the frozen
detector verdict and ML score.


## DEC-069: Keep local suppression as presentation policy only

**Decision:** Local analysts may suppress a domain from the priority triage
queue with a reason and optional expiry. The domain remains in complete
findings, reports, and detector output. Suppression is stored locally and is
excluded from sanitized public deployment bundles.

**Reason:** Repeated expected findings create analyst fatigue, but silently
rewriting or deleting detector output would reduce auditability and could hide
future evidence changes.

## DEC-070: Canonicalize Unicode domains to IDNA ASCII form

**Decision:** Domain normalization converts valid Unicode hostnames to their
lowercase IDNA ASCII representation before matching, ML dataset construction,
and runtime ML inference.

**Reason:** A Unicode hostname and its punycode representation identify the
same DNS name. Treating them as different values would create duplicate samples
and missed IOC matches without requiring any network resolution.


## DEC-071: Apply strict public-domain validation at the ML boundary

**Decision:** ML dataset/runtime candidates must contain at least two valid DNS
labels, use labels of valid length and syntax after IDNA normalization, and not
be IP literals. Tolerant DNS evidence handling remains separate so malformed or
local telemetry can still be inspected and matched where appropriate.

**Reason:** The malicious-domain model was trained for internet-domain strings.
Rejecting clearly out-of-distribution or malformed names prevents meaningless
scores while preserving raw security evidence outside the model.


## DEC-072: Represent and match SGB IPv6 network IOCs explicitly

**Decision:** SGB `ip6net` / `ipv6net` values are stored as
`IOCType.IPV6_NETWORK`. A DNS response IPv6 address contained by such a
network creates `response_ip_network` contextual CTI evidence, not an
automatic Known Threat verdict.

**Reason:** Discarding CIDR semantics loses useful infrastructure evidence, but
a network-level match is broader than an exact domain IOC and must not be
treated as proof that the queried domain itself is malicious.


## DEC-073: Import Pi-hole query databases in memory

**Decision:** ThreatFusion accepts uploaded Pi-hole FTL SQLite query databases
by deserializing them into an in-memory SQLite connection and reading the
standard `queries` view. The `forward` field is not mapped to
`DNSEvent.response_ip`.

**Reason:** Pi-hole is a realistic small-network DNS telemetry source. Reading
the established query view removes manual CSV conversion while preserving the
privacy goal of not writing uploaded raw telemetry to the ThreatFusion history
database. Pi-hole's forward value identifies an upstream resolver, not the
answer IP returned for the queried domain.

## DEC-074: Show CTI corroboration without changing evidence semantics

**Decision:** The analyst dashboard may summarize how many distinct cached CTI
sources support a domain and which evidence scopes are present. Multi-source
corroboration is presentation context only and does not automatically promote a
contextual URL-hostname or infrastructure match to `known_threat`.

**Reason:** Independent-source agreement is useful analyst context, but source
count alone does not change what an IOC match actually proves about the queried
domain.


## DEC-075: Keep automation entry points local and detector-neutral

**Decision:** Provide a local CLI that reuses the same trusted model artifact,
local CTI cache, runtime analyzers, and privacy-safe report builder as the
Streamlit application. The CLI performs no CTI refresh and introduces no
separate detection policy.

**Reason:** Automation should not fork security logic. Reusing the existing
runtime path makes scripted analysis reproducible and keeps credentials and
network activity outside the analysis request path.

## DEC-076: Support AdGuard Home query logs through a local adapter

**Decision:** ThreatFusion accepts AdGuard Home query-log JSON as local
telemetry. The adapter supports the on-disk query-log record fields and the
structured query-log API response shape, mapping only available DNS evidence
into the existing `DNSEvent` model.

**Reason:** AdGuard Home is a common local DNS telemetry source. Reusing
`DNSEvent` adds practical input compatibility without introducing networking
or a second detection pipeline.


## DEC-077: Smoke-test the container separately from model/data readiness

**Decision:** CI builds the Docker image, starts it in public mode, and verifies
Streamlit's local health endpoint. The smoke test does not require private CTI
cache or trusted model artifacts.

**Reason:** Image/build regressions should be caught in CI, while local ignored
model and CTI assets must remain outside GitHub Actions. Application-level
artifact readiness remains visible through the dashboard system-health view.

## DEC-078: Extend DNS behavior with explainable v2 telemetry-aware signals

**Decision:** Keep hybrid verdict semantics unchanged while adding optional DNS
behavior v2 evidence fields: response-code/NXDOMAIN context, lexical domain
shape indicators, response-IP churn rate, and periodic timing signals. These
signals are surfaced as human-readable analyst evidence and degrade to `None`
when telemetry fields are missing or incomparable.

**Reason:** Practical DNS telemetry often varies by source. The system should
explain what was observed without requiring model retraining or treating any
single behavior heuristic as proof of maliciousness.

## DEC-079: Persist aggregate reproducibility context with saved analysis runs

**Decision:** New local history runs persist the trusted model name, a SHA-256
identity over the model/metadata files, artifact and audit schema versions,
the exact high/medium/low thresholds used, and per-source CTI refresh
timestamp/count/freshness captured when the analysis completes. Existing
history databases are upgraded in place with nullable columns so legacy runs
remain readable.

**Reason:** A saved verdict should be explainable in terms of the detector and
CTI state that produced it. Keeping this context aggregate-only improves audit
and reproduction without storing raw DNS rows, client IP values, secrets, or
local filesystem paths.

## DEC-080: Keep analyst history maintenance explicit and detector-neutral

**Decision:** Local history may support bulk analyst review for explicitly
selected findings, deletion of one saved run, keep-latest retention cleanup,
and comparison with the immediately previous saved run. Retention always keeps
at least one run, destructive UI actions require explicit confirmation, and
feedback never rewrites detector verdicts.

**Reason:** Repeated analyst use needs practical history management without
turning review actions into hidden detection logic or creating an accidental
database-wipe control. Run deltas should describe saved findings only and stay
separate from model inference.

## DEC-081: Report holdout uncertainty and source-aware class metrics

**Decision:** Frozen final-holdout reports include 95% Wilson score intervals
for precision, recall, and false-positive rate. They also retain source-aware
diagnostics that report malicious recall and benign false-positive rate only
when the corresponding class exists for that source. Legacy schema-version 1
reports remain readable.

**Reason:** Point estimates can look more precise than the available sample
size justifies, especially for small source subsets. Class-specific
source diagnostics expose uneven performance without inventing undefined
metrics, while backward-compatible report loading preserves reproducibility of
older evaluation artifacts.

## DEC-082: Defer augmented runtime promotion until stronger temporal evidence

**Decision (2026-10-04):** Retain the augmented lexical C=4 artifact as an
experimental candidate. Do not change runtime defaults or frozen thresholds
from its inspected fresh-disjoint result. Require a new untouched post-freeze
temporal collection before reconsidering promotion.

**Reason:** Fresh-disjoint High/medium/low recall is 60.62%/78.75%/81.87%, but
FPR is 0.85%/1.95%/2.62%, exceeding the corresponding validation budgets of
0.1%/0.5%/1.0%. The malicious sample has only 160 domains, uneven source recall
and no retained ThreatFox examples. All 473,323 unique current malicious
candidates have earliest usable first_seen at or before the frozen cutoff.
Refreshing a cache does not make those indicators temporally new.

**Consequences:** Existing holdout evidence remains inspected and cannot select
or tune a successor. New fresh-disjoint snapshots remove development overlap
before persistence. Aggregate reports identify exact artifact bytes and the UI
shows their actual protocol. The original default artifact is absent from this
checkout; the synthetic demo remains a separate presentation asset.

## DEC-083: Make operation without ML an explicit mode

**Decision (2026-10-04):** Add `THREATFUSION_CTI_ONLY=1` for the dashboard and
`--cti-only` for the CLI. Preserve deterministic CTI and DNS behavior while
skipping artifact loading and scoring. Disable provenance-dependent history in
this mode, label ML as disabled, and export absent ML values honestly.

**Reason:** The original runtime artifact is missing from this checkout. A
trusted-model backup can restore it privately; retraining or choosing an
experimental/synthetic substitute cannot restore its historical identity.
Explicit CTI-only operation keeps the core analyst workflow usable without
changing the default model or promoting the augmented candidate.

## DEC-084: Build the hosted demonstration entirely from synthetic inputs

**Decision (2026-10-04):** Use a dedicated non-root Docker image and free Render
Blueprint. Generate synthetic CTI/model assets at build time, pin the model
outside its read-only directory, and place Nginx request and connection limits
in front of Streamlit. Keep health checks independent of visitor limits.

**Reason:** Local CTI, ML snapshots and telemetry must not enter the deployment
context. Anonymous presentation needs transport security and resource limits
without live-feed credentials or third-party data redistribution. Actual hosted
HTTPS and ingress verification remain required before the final release tag.
