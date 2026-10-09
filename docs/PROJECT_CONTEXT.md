# ThreatFusion AI — Project Context

For the current target product and active work order, start with
[PRODUCT_PLAN.md](PRODUCT_PLAN.md). This file also preserves dated development
history; earlier “Next” notes are superseded by that plan's current queue.

## Current checkpoint (2026-10-09)

Manual acceptance: sections A–F and the redesigned two-theme UI (Section H)
passed with the user; only the free-form Section G remains. P1: the CTI reload
memory step was reduced (loader high-water 672 → 277 MiB, reload plateau ~640
vs ~1,212 MiB) and a second security review found no new vulnerability. The
declared soak rerun-2 was interrupted by a host shutdown (no verdict); rerun-3
with unchanged acceptance is running. Section G feedback was fixed and PhishTank
was removed at the user's request (DEC-089). The user re-checked these;
P0 manual acceptance passed. Next: soak verdict, then P2.

### Previous checkpoint (2026-10-07)

P1 operational confidence has started. A predeclared fault matrix against the
real collector CLI fixed two defects: CTI cache locks longer than SQLite's busy
timeout no longer stop collection (last complete indicators, disclosed as
`cti_reload_deferred`), and the cached-analysis comparison no longer deep-copies
a 616k-indicator cache. The final candidate passes all nine cases; 1,328 local
tests pass. The 6-hour wall-clock soak completed 15/16 declared checks: the RSS
growth limit failed because one CTI reload adds ~290 MiB that is not released
(flat afterwards). A security review fixed DNS rebinding to the loopback app and
a ThreatFox redirect key leak. See [OPERATIONAL_CONFIDENCE.md](OPERATIONAL_CONFIDENCE.md).

### Previous checkpoint (2026-10-06)

Verified runtime main `35423bc` fixes nine reviewed correctness/privacy problems
and failed-analysis retry: DNS client attribution/all IP answers, literal-IP
report privacy/counts, private local identity controls, schema-3 legacy coverage,
SQLite maintenance, match/work limits, IPv6 lookup, IDNA details and JSON validation.
**1,321 local tests / approximately 91% coverage and six CI jobs passed.**
The 34 original local data hashes remain unchanged. See
[repair contracts](SOURCE_REVIEW_REPAIRS.md) and the newest
[handoff](RELEASE_HANDOFF.md) for exact scope and limitations.

The goal is a useful local network investigation workbench with the web UI and
Linux automation, not merely a URL checker. Manual user acceptance is pending;
next priorities are operational confidence, measured analyst usefulness and
independent traffic evidence, focused detector coverage, then a versioned SIEM
pilot integration. Wazuh and other SIEM adapters are planned, not delivered.
No public site is authorized; trusted ML availability/promotion remains unchanged.

## Problem

Public threat feeds answer **what is known to be malicious**, but they do not directly answer **what appeared in a user's environment** or **what should be reviewed first**.

ThreatFusion AI connects external intelligence with local telemetry so an analyst can ask:

- Which known indicators appeared in my telemetry?
- Which unseen domains deserve review?
- What evidence produced this verdict?
- Are multiple suspicious observations related by local infrastructure?
- Is the threat-intelligence cache fresh enough to trust for triage?

## Core goal

ThreatFusion AI aims to be a **useful, local-first network investigation and
triage tool** for technically capable individual users and small teams who run
Zeek: it correlates their telemetry with CTI and conservative behavior evidence
and explains which client and destination deserve a look and why (DEC-090).

**Current status: early prototype.** The workflow runs end to end on synthetic
and replayed data and passed the developer's manual acceptance, but it has not
been validated on the user's own real traffic or by independent users, and
detection efficacy is unmeasured. The installed default runs CTI-only; the
lexical ML model is experimental and off by default. Status and gates are in
[PRODUCT_PLAN.md](PRODUCT_PLAN.md).

Earlier versions of this file described an "educational / portfolio" project.
That framing is retired; it remains in dated history and the v0.1.0 notes.

## Earlier measured position (2026-10-06, before runtime repairs)

The accelerated multi-day operational gate freezes all 83 runtime modules and
detector/ML policies. Three event days of hourly mixed rotation, independent
retained-window modeling, own worker RSS/state/latency measurements and declared
restart/open-close/gzip/CTI/expiry/ledger cleanup contracts exercise 360,000 base
observations plus 120 late-closed rows. A monitor race probe and method-only
amendment preserve the original run and acceptance, with ten new controls.
Two further real SQLite page-budget exhaustion controls prove per-file rollback,
old report preservation and exact-once repair/restart in owned synthetic state.
Both full runs pass predeclared limits. Amended worker RSS is 648.5 MiB, sampled
state 131.7 MiB, maximum scan 7.181 s, warm idle median/p95 0.304/0.347 s;
steady-state ratios remain near 1.003. All 83 runtime and 34 original local data
files stay byte-identical. Scope excludes web/large CTI cache/input/parent memory.
All 1,276 local tests pass (approximately 91% coverage); twelve new controls.
This is operational engineering evidence, not a 72-hour wall-clock soak, fresh
accuracy, RITA parity or enterprise qualification. See `MULTIDAY_COLLECTION.md`.
Next: actual bounded wall-clock soak and broader filesystem/database faults,
representative site/security checks, then untouched detector/SIEM/analyst gates.
The earlier cancelled capacity CI passes all six jobs on retry; no public site.

Collector connection diversity is now independent of the DNS 25k-name bound.
Above 1,000 connection groups, a prioritized bounded snapshot discloses omissions
and full-retained counts; a private generation-verified gzip exports every retained
connection group within 256 MiB expanded / 64 MiB compressed budgets. Global CTI,
UID/conflict, detector/ML and section bounds remain; upload limits are unchanged.
Default-100k IoT-3 now completes with 56,462 records pruned and coverage explicit.
Four known cases plus synthetic 100k targets reconcile retained offline/export/
restart/gzip evidence; an actual interrupted writer preserves previous publication
and recovers without duplicates. Windows/known IoT-8 original evidence stays.
1,264 tests pass; 31 new controls, 75 of 82 original runtime modules and 34 local
data files stay identical. All first failures remain intact. See
`CONNECTION_CAPACITY.md`. Next: predeclared multi-day load/resource/security/
recovery checks, then untouched detection/SIEM/human gates. No public site or
runtime ML promotion. Earlier paragraphs retain historical experiment outcomes.

Bounded Linux completed-log preparation now conserves eligible rows across
private shards, with strict-by-default and explicitly opted-in raw DNS quarantine.
Collector/dashboard verify inventory and disclose incomplete-input coverage;
expected declarations cannot hide groups when inputs are incomplete. Known-source
replays retain Windows/IoT-8 original evidence and all 19,360 eligible Linux rows
plus 49 private quarantine rows. IoT-3's 156,462 eligible rows import in a
separately declared 20k window with pruning disclosed; default 100k analysis still
fails the existing 25k unique-target bound. This is an explicit remaining product
limit, not full retention/detection efficacy. All first failures remain preserved.
Thirty new controls; 1,233 tests pass. Four existing runtime modules change and
77 remain identical, alongside original local data and all detector/ML policies.
See `LOG_PREPARATION.md`. Next: diverse-target/report-capacity behavior, then
representative load/security and untouched detection/human validation. No public site.

The official `unknown_transport` enum now imports/persists under a narrow parser
exception while arbitrary overlong values and TCP eligibility stay unchanged.
Predeclared repair contracts and full connection-only replays reconcile 39,957
rows, including all 10,662 Linux rows. The first mixed-log replay still fails on
missing DNS identity/type; this is preserved, not filtered into success. Only
one runtime module changes; sixteen new controls and 1,203 total tests pass.
See `INDEPENDENT_REPLAY.md`. Next is bounded scalable ingestion and DNS quarantine
handling; independent malicious/enterprise/security/human gates remain open.

`independent-replay-v1` widens normal controls to real Windows/Linux website
captures and exposes input compatibility/capacity defects without tuning. One
new normal source fully reconciles; Linux has two legitimate unknown-transport
fields rejected by the importer, and a new malicious source exceeds file/shared
record bounds. IoT-8 is a known-source replay, not fresh evidence. Complete
baseline cases retain 44,384 mixed rows; native units stay separate. PCAPNG and
source-history guards preserve original evidence. See `INDEPENDENT_REPLAY.md`.
Fixing valid enum import and declaring scalable ingestion precede new behavior
coverage; independent malicious/enterprise/security/human gates remain open.

`analyst-guidance-v1` adds bilingual TCP/DNS next-check guidance and pre-filter
TCP review/context counts, preserving original evidence. Two new synthetic
packet replays retain eight reviews each while supplied lab inventory separates
five; CTI/expiry restore visibility. Offline/collector/restart/gzip/context checks
support the flow. This is not human efficacy, independent traffic accuracy or
ML promotion. See `ANALYST_REVIEW.md`; independent permitted windows and actual
analyst validation remain the next gates.

`review-workload-v1` adds repeatable private acquisition/generation, structural
source rejection and separate normal-review/native-RITA units without changing
runtime policies. Two new two-hour synthetic windows each put 5/7 normal TCP
groups and 3/5 simulated groups in Review; cache/shared-resolver limits, wide
jitter and sparse failures remain explicit. One new intact normal IoT capture
also produces a TCP and a DNS review. Two preselected official PCAPs are truncated
and excluded, so the independent real-source gate remains partial. All three
successful sources reconcile full offline/collector/timeline/restart/gzip outputs.
See `REVIEW_WORKLOAD.md`. Next work prioritizes measured analyst tasks/context and
new intact permitted windows before separately declared detector changes. These
results do not establish malware FPR/recall, RITA parity or analyst efficacy.

## Local network lab direction

A separate local Ubuntu/KVM guest now runs synthetic three-client experiments.
`periodic-controls-v1` has a real short live capture and a deterministic packet
replay representing a synthetic day, compared with RITA v5.1.2 using identical
Zeek records. Both CTI and ML are disabled for the behavior comparison. It shows
why periodicity alone cannot distinguish legitimate update checks from a
suspicious simulation; the current ThreatFusion verdict also does not elevate
these patterns by itself. RITA is an optional comparison tool, not a runtime
dependency or an integrated detector. See `LOCAL_LAB.md` for measured outputs,
artificial-traffic limitations and reproducible protocol. No production or ML
promotion claim follows. Client/target triage now evaluates devices independently,
exposes sustained DNS periodicity as review work without a malware verdict,
and provides a local privacy-controlled device view/export. See
`DETECTION_ROADMAP.md` for coverage gates and the intended RITA-alternative scope.
Connection-start timelines are now available for uploaded and collected groups,
with bounded UTC/state/byte summaries and report-local aliases. Two isolated
live reset/close controls each reconcile 72 starts across offline, collector and
restart/gzip paths. This is plumbing evidence, not analyst efficacy or detection
accuracy. See `CONNECTION_INVESTIGATION.md`.
Device/domain DNS query timelines now complement connection-start charts, with
bounded UTC/response summaries and stable selection while mappings match.
Rotating-log/recovery/resource contracts are documented in `DNS_INVESTIGATION.md`.
Incremental active-log tailing and retroactive CTI investigation workflows remain
future work. Completed-log collection is now
implemented as described below.

An earlier increment added `cached-http-controls-v1`: isolated real packet capture
with DNS TTL caching, HTTP persistence, variable browser response sizes and
polling jitter. Three validated runs each observed five DNS queries, 78 HTTP
requests and 61 TCP sessions; this remains a short synthetic lab workload.
`zeek-connection-context-v1` now retains UID/ports/duration/bytes/state and
offers conservative long-session/sustained-timing review in a separate tab and
CLI report. Constructed longer controls produced nine benign reviews out of
33 benign groups, plus three simulated heartbeat reviews; this is review burden,
not malware FPR/recall. Native RITA on the same short cached capture emitted
High/beacon 1 for updater and heartbeat, with no browser row or modifiers.
Longer independent recordings and expected-software context are still needed.

`expected-connection-context-v1` now provides optional local, expiring exact-pair
analyst declarations with duration/count/byte limits. It separates declared
expected activity reversibly and keeps original connection priority/evidence.
Client/destination CTI conflicts override declarations; incomplete evidence cannot
qualify. Schema-v2 connection reports retain all groups and omit declaration
IDs/configuration. Eleven constructed controls include an identical heartbeat
that also matches: software identity and safety remain unverified. See
`EXPECTED_CONNECTIONS.md`.

`iot23-connection-coverage-v1` now evaluates four preselected official real-device
logs (1.91–23.98-hour observed spans), keeping labels outside detector input and
CTI/ML/context disabled. Benign connection reviews were 0/16 and 0/176; malicious
capture reviews were 1/10 and 0/41. The missed capture and two separate benign
domain/IP fallback Review verdicts explicitly limit efficacy claims. See
`NETWORK_EVALUATION.md`; enterprise representativeness and analyst usefulness
remain unmeasured.

`closed-zeek-collector-v1` adds a foreground Linux consumer for completed TSV
connection logs/gzip archives, a private SQLite checkpoint/evidence window and
atomic aliased snapshots. Rotation/restarts/content copies are deduplicated;
active files wait for closure. CTI reloads from the user's existing cache, rules
expire/recheck each scan, and capacity loss disables expected filtering. The
local web Collected connections view refreshes without uploads. Installed
`threatfusion-ai collect` and standalone `threatfusion-collect` expose automation;
no public listener, packet sensor or system autostart is introduced. See
`TELEMETRY_COLLECTOR.md`. Four isolated real-source imports reproduced the frozen
offline results and survived restart/gzip duplication. This is operational
contract evidence, not calibrated C2 detection or production sizing.

`tcp-attempt-review-v1` adds a separate bounded five-minute S0/REJ review
queue for failed port/host diversity and dense retries. Benign inventory scans
and service outages can also match. All 64 predeclared contract checks pass;
a new isolated live 120-record run produces three scoped patterns. A new official
8-1 capture imports 10,403 rows but produces no attempt review: sparse failures
remain uncovered. Original findings/verdicts and ML policy are preserved. See
`TCP_ATTEMPT_REVIEW.md`; no increased malware recall or analyst efficacy claim.

`closed-zeek-collector-v2` now also consumes completed TCP/UDP DNS archives into
an independent device/domain queue, retaining multiple transactions per UID and
excluding same-identity full-row conflicts. The original connection outputs,
DNS review thresholds and ML policy stay unchanged. Private SQLite schema 2
upgrades only after a schema-1 backup; 100k shared records, 25k DNS names and
1000 exported/500 visible DNS groups keep explicit coverage limits. Two new
isolated live recordings each reconcile 24 DNS transactions and two connections,
with zero reviews and restart/gzip duplication checks. These synthetic operational
contracts do not establish real benign FPR, tunneling coverage or RITA parity.
See `DNS_COLLECTION.md`. Mixed-log rotation/resource controls and device DNS
timelines are now implemented (`DNS_INVESTIGATION.md`); representative multi-day
load, active-file tailing and independent analyst evidence remain open. No public
service is authorized.

## Linux first-run flow

Connection policy v2 now includes eligible bidirectional payload from incomplete
close/reset endings while preserving SF/S1 confirmed counts and existing timing/
duration gates. Four new aliased report/UI fields expose payload, resets, partial
closes and failed/half-open attempts. Expected declarations cannot hide these
partial/reset groups. Predeclared controls pass; three new independent captures
add 1,637 payload sessions in one capture but do not increase Review groups.
Another malicious capture still produces none. See `TCP_TERMINATION.md` for
protocol, source identities and coverage limits; no field efficacy or ML change
is claimed. Collector records remain compatible and snapshots recompute on restart.

The READMEs provide a single copy-paste command for Linux x86_64/glibc 2.28+.
It installs private Python 3.12.14 and hashed runtime dependencies, immutable
source, the `threatfusion-ai` command and an applications-menu shortcut. New
installations open real CTI mode (ML disabled), with an initially empty cache.
Debian 12/Ubuntu 24.04 clean installations are tested without Python/Git.

The local-only sidebar panel accepts the user's own masked API keys, applies
session-only credentials by default, offers explicit optional 0600 plaintext
storage inside the 0700 installation, and can refresh source caches manually.
Opt-in 6/12/24-hour automatic refresh runs during the application's lifetime,
uses saved keys/public sources and catches up at next launch. Refreshes are
serialized; upstream failures preserve old source data and show safe aggregate
status. CLI status/refresh/stop and a web stop button control this installation.
Closing the browser does not stop the server; Ctrl+C/SIGTERM/SIGHUP do.

Demo is an explicit separate mode; its reserved synthetic cache/model never
enter real CTI scoring. Existing installations retain their selected mode on
upgrade. No developer cache, model, key or holdout is copied, distributed or
promoted. First-run telemetry is session-local and shared history is disabled.
See `INSTALL_LINUX.md`. Source updates target `main`; no host is connected
(the Render demo service was deleted by the user on 2026-10-07, DEC-086).

## Intended users

The prototype is most relevant to:

- cybersecurity students and researchers;
- small SOC/security teams evaluating a lightweight workflow;
- small organizations learning how CTI and local telemetry can be combined.

## v0.1.0 implemented scope

### Threat intelligence

Implemented sources:

- ThreatFox;
- URLhaus;
- PhishTank verified-online public feed;
- T.C. Siber Güvenlik Başkanlığı (SGB).

The local SQLite CTI cache supports:

- normalized values;
- active/inactive lifecycle state;
- refresh metadata;
- indexed Quick Lookup keys;
- URL hostname indexing;
- stale-source visibility;
- independent source refresh with previous-snapshot preservation on failure.

### Passive Quick Lookup

A user can submit one:

- URL;
- domain;
- IPv4/IPv6 address.

ThreatFusion checks the local CTI cache without visiting the destination. Domain ML is only used for eligible domain targets.

### Telemetry ingestion

Auto-detect currently supports:

- CSV / TSV / TXT;
- XLSX / XLS;
- Zeek <code>dns.log</code>;
- Zeek <code>conn.log</code>;
- PCAP / PCAPNG / CAP classic UDP DNS;
- Suricata EVE JSON / JSONL;
- Pi-hole FTL SQLite;
- AdGuard Home query logs;
- dnstop-style domain rows.

<code>.capinfos</code> is recognized as metadata and is not analyzed as packet telemetry.

### Analysis

Runtime analysis combines:

- known IOC matching;
- domain ML scoring;
- DNS behavior aggregation;
- explainable hybrid assessment;
- related-activity context.

The hybrid model distinguishes exact known-domain evidence from weaker hostname/infrastructure context.

### Machine learning

The ML component uses character n-gram TF-IDF + balanced Logistic Regression.

The development workflow includes:

- reproducible snapshots;
- train/validation/test separation;
- validation-selected thresholds;
- explicit FPR budgets;
- source-aware diagnostics;
- frozen artifacts;
- fresh/disjoint holdout evaluation support;
- temporal first-seen filtering support.

ML scores are uncalibrated and are not presented as malware probabilities.

The earlier character-only C=4 candidate completed its post-freeze temporal
holdout on 2026-09-28. That result remains historical development evidence and
supports keeping lexical ML as an auxiliary signal rather than a standalone
detector.

The current experiment is `lr_char_2_6_plus_lexical_c4`, a frozen character
2-6 TF-IDF plus bounded lexical-feature Logistic Regression artifact. The
originally recorded artifact was not available in this checkout, so a separate
reconstructed artifact was evaluated on a new untouched post-freeze holdout.
Its false-positive rates were operationally unusable, so it was not promoted
and no final standalone performance claim is made for it.

The subsequent hard-negative augmented lexical C=4 artifact measured
60.62%/78.75%/81.87% recall and 0.85%/1.95%/2.62% FPR at High/medium/low on a
fresh-collection disjoint holdout. It remains experimental: initial strict
post-freeze selection retained zero malicious domains; a later independent SGB
refresh found only five eligible disjoint domains, without model scoring. Runtime promotion
is deferred until stronger untouched temporal evidence exists (DEC-082).

The configured original `data/models/development-001` artifact is absent in
this checkout. The separately generated synthetic demo model shares the
directory name but has `demo_only_synthetic` status and supplies no final ML
performance evidence. Local caches, datasets, evaluations and artifacts are
ignored data; a GitHub clone must regenerate its own assets and cannot reproduce
historical frozen bytes simply by fetching current feeds.

When that trusted original is unavailable, explicit CTI-only operation keeps
CTI matching and DNS behavior available without loading any model. The UI/CLI
label ML as disabled and model-dependent history is disabled (DEC-083). The
synthetic public demo remains a separate presentation runtime (DEC-084).

### Analyst workflow

The Streamlit application includes:

- system health and CTI freshness;
- Quick Lookup;
- telemetry analysis;
- priority triage;
- evidence-first investigation;
- source corroboration;
- related-activity graph/context;
- optional local analyst feedback;
- optional local suppression;
- aggregate analysis history in local mode;
- privacy-safe JSON/CSV export;
- model-evaluation views.

### Privacy / release engineering

Implemented safeguards include:

- raw uploaded telemetry not persisted by default;
- raw client/response IPs excluded from portable reports;
- public mode disabling shared history;
- sanitized public-demo/runtime generation;
- non-root Docker packaging;
- secret/local-path release auditing;
- Linux + Windows CI;
- Docker build/health validation;
- dependency auditing.

## Resource boundaries

The private/local Streamlit upload limit is 100 MB. The dedicated synthetic
public-demo image limits uploads to 20 MB and bounds proxy requests and
concurrent WebSocket sessions.

Runtime analysis is separately bounded to:

- 100,000 events;
- 25,000 unique analysis targets.

The system is intentionally bounded rather than attempting unlimited packet-processing workloads in the browser-driven Streamlit application.

## Release position

The project remains in local development and security review. Previously
completed feature/CI checks do not establish public-deployment readiness.
The user requires an explicit new request before creating or resuming any public
site or hosted preview. Completed, verified source changes may be published to
GitHub independently of hosting. See `AGENTS.md` for branch and data boundaries.

Remaining release tasks are:

- preserve the deferred ML promotion decision and collect stronger untouched
  temporal evidence before revisiting it;
- retain the reviewed sanitized portfolio screenshots;
- local security review and remediation;
- public demo only if later explicitly requested by the user;
- final release checklist;
- GitHub tag/release.

Public hosting and final release are deferred while this work continues.

## Explicit non-goals for v0.1.0

ThreatFusion AI is not intended to be:

- a production SIEM;
- an EDR;
- a full IDS/IPS replacement;
- a packet-forensics suite;
- an automatic incident-response platform;
- a guarantee of maliciousness/benignness;
- an autonomous analyst.

## ML / LLM principle

The current v0.1.0 project does not depend on an LLM for detection.

If an LLM is added in a future version, its role should be explanation/reporting rather than primary detection.

> **ML assists detection. Deterministic CTI remains stronger evidence. An LLM, if added later, explains rather than decides.**
