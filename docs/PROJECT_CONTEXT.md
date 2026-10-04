# ThreatFusion AI — Project Context

## Problem

Public threat feeds answer **what is known to be malicious**, but they do not directly answer **what appeared in a user's environment** or **what should be reviewed first**.

ThreatFusion AI connects external intelligence with local telemetry so an analyst can ask:

- Which known indicators appeared in my telemetry?
- Which unseen domains deserve review?
- What evidence produced this verdict?
- Are multiple suspicious observations related by local infrastructure?
- Is the threat-intelligence cache fresh enough to trust for triage?

## Core goal

ThreatFusion AI is an AI-assisted, multi-source cyber threat-intelligence and telemetry-triage platform.

Its portfolio value comes from combining:

- CTI engineering;
- safe local telemetry ingestion;
- deterministic IOC matching;
- measured ML experimentation;
- explainable hybrid decisions;
- privacy-conscious persistence;
- analyst workflow design;
- deployment and CI practices.

It is an educational prototype, not a production security product.

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
Device timelines, incremental active-log tailing and retroactive CTI
investigation workflows remain future work. Completed-log collection is now
implemented as described below.

The next increment adds `cached-http-controls-v1`: isolated real packet capture
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

## Linux first-run flow

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
See `INSTALL_LINUX.md`. Source updates target `main` with the hosting guard in
`AGENTS.md`; the Render demo remains user-suspended and must not be resumed.

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
