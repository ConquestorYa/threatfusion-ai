# Product plan and AI continuation guide

Updated: 2026-10-07. Latest verified runtime: `d006771` (P1 repairs).
This is the **current product direction and ordered work queue**, not a record
of future features already delivered. Start here when continuing in a new chat.

## The product we are building

Build a useful, open-source, local-first **network investigation and triage
workbench** for analysts, small security teams and advanced individual users.
It consumes existing network/DNS records, correlates them with the user's CTI
cache and conservative behavior evidence, and helps answer:

> Which observed client and destination deserve investigation, why, over what
> time window, and what should the analyst check next?

Keep the local web dashboard as the analyst workspace and Linux command line
as the installation/automation interface. Quick Lookup stays a supporting tool.
The core product is ongoing telemetry investigation, not a URL upload page or
a replacement for the network sensor. The current runtime is a working
prototype; a dependable product is the goal, not an established qualification.

The intended distinguishing value is **explainable client-level DNS/connection
triage**, with honest evidence scope, visible coverage loss, normal-activity
context and usable private operation. Aim for competitive core coverage near
the RITA use case and a measured advantage in this narrower workflow. Neither
parity nor superiority has been demonstrated. RITA is an optional external
comparison baseline, not a bundled detector or runtime dependency.

## System shape and boundaries

1. Zeek or another supported source produces records from traffic it can see.
2. ThreatFusion imports those records or collects completed Zeek archives.
3. Shared analysis produces scoped CTI matches and behavior review evidence.
4. The local dashboard helps inspect clients, targets, time, coverage and context.
5. Private reports/CLI support automation; a versioned SIEM integration is future
   work, after the local workflow and evidence gates below.

Zeek is the first continuous collection source. Suricata EVE, Pi-hole and
AdGuard are existing manual-import adapters, not equivalent live integrations.
A normal workstation on a network does not automatically see every other
device's traffic. Sensor placement, mirrored traffic and visible DNS determine
coverage. ThreatFusion does not install a packet sensor or intercept traffic.
DNS observations do not prove a download, payload contents, execution or an
infected machine. Encrypted DNS and unseen traffic remain coverage gaps.

## Implemented capability inventory

“Implemented” means code exists with the referenced engineering checks. It does
not mean representative traffic, human usefulness or production operation has
been fully validated. Detailed contracts and historical results stay in their
linked documents rather than being copied into this plan.

| Area | Implemented behavior | Evidence / remaining qualification |
| --- | --- | --- |
| Linux installation and daily use | One-command private Python/dependencies, terminal command, desktop entry, loopback UI, stop/status/reopen and isolated demo | Clean Debian/Ubuntu CI; user manual walkthrough pending. [Install](INSTALL_LINUX.md) |
| CTI | ThreatFox/URLhaus/PhishTank/SGB adapters, normalization, lifecycle/freshness, indexed lookup, manual and opt-in scheduled refresh, own-key handling | Scheduling runs while the managed app runs; upstream availability/licensing are separate. [Sources](DATA_SOURCES.md), [install](INSTALL_LINUX.md) |
| Passive lookup | URL/domain/IP evidence, IDNA and IPv6 prefix context; no destination visit or DNS resolution | Supporting workflow, not a malware-content sandbox. [Architecture](ARCHITECTURE.md) |
| Manual telemetry | Delimited tables/spreadsheets, Zeek DNS/connection logs, classic UDP DNS PCAP/PCAPNG, supported EVE, Pi-hole FTL, AdGuard and dnstop | Format-specific limits; adapters do not invent missing evidence. [Architecture](ARCHITECTURE.md), [repairs](SOURCE_REVIEW_REPAIRS.md) |
| Continuous Zeek collection | Completed TSV/gzip conn/DNS archives, private checkpoints/window, deduplication/conflicts, bounded scans, rotation/restart and refreshed UI | Foreground collector; active files wait for closure, one sensor per state, no installed boot service. [Collector](TELEMETRY_COLLECTOR.md), [DNS](DNS_COLLECTION.md) |
| Large input and reports | Private preparation/shards, explicit DNS quarantine, incomplete-input guards, bounded prioritized snapshots, verified full connection JSON.gz | Retention/omission limits are visible; not unlimited ingest or full DNS export. [Preparation](LOG_PREPARATION.md), [capacity](CONNECTION_CAPACITY.md) |
| DNS/client triage | Independent client/target assessments, exact-domain versus infrastructure CTI, sustained periodic review, volume/NXDOMAIN/shape/IP-answer context | DNS caching/resolvers/normal polling limit interpretation; tunneling detector not implemented. [Roadmap](DETECTION_ROADMAP.md), [investigation](DNS_INVESTIGATION.md) |
| Connection triage | Typed TCP sessions, long/periodic review, partial/reset payload coverage and a separate failed-attempt diversity/retry queue | Broad beaconing, jitter, sparse failures and UDP coverage still incomplete. [Termination](TCP_TERMINATION.md), [attempts](TCP_ATTEMPT_REVIEW.md) |
| Analyst investigation | Bilingual tables, bounded DNS/connection timelines, next-check guidance, pre-filter counts, expiring expected declarations with CTI override | Reversible presentation context preserves original evidence; human time/usefulness not measured. [Analyst review](ANALYST_REVIEW.md), [context](EXPECTED_CONNECTIONS.md) |
| History and reports | Aggregate history/feedback/suppression in eligible trusted-model local mode, explicit IP opt-ins, report aliases and spreadsheet-safe CSV | Managed CTI/demo history stays disabled. Aliases are not anonymization or stable assets. [Repairs](SOURCE_REVIEW_REPAIRS.md) |
| Operational safeguards | Private state/schema-3 backups, local generation-bound identity display, all IP answers, explicit work/match budgets, failed-analysis retry, release privacy audit | 1,328 local tests for `d006771` (CI per newest handoff); CTI busy reads keep the last complete indicators with disclosure; complete security and enterprise qualification remain open. [Repairs](SOURCE_REVIEW_REPAIRS.md) |
| Lab and comparison | Isolated local Zeek/RITA experiments, declared independent source/retention/recovery/resource methods and aggregate results | Some inspected sources are incomplete/missed; accelerated event days are not a wall-clock soak. [Lab](LOCAL_LAB.md), [replay](INDEPENDENT_REPLAY.md), [multi-day](MULTIDAY_COLLECTION.md) |
| ML | Local lexical domain-model development/evaluation, provenance, trusted artifacts and explicit CTI-only operation | Original runtime artifact absent; augmented candidate experimental; collector ML disabled. [ML](ML_DATASET.md), [handoff](RELEASE_HANDOFF.md) |
| Packaging/CI | Docker health, isolated synthetic public-mode/proxy tests, Linux/Windows quality/dependency checks | Packaging exists; no public site or hosted preview is authorized. [Deployment reference](DEPLOYMENT.md) |

## Current checkpoint

- **P1 first increment (2026-10-07):** predeclared nine-case fault matrix on the
  real collector CLI found and fixed two defects — a CTI lock above the 5 s busy
  timeout stopped collection, and a deep copy of every indicator cost ~430 MiB /
  ~7 s per recompute with the 616k-indicator cache. Final candidate passes 9/9;
  every earlier failing run is preserved. 1,328 local tests, ~91% coverage. A
  declared 6-hour real wall-clock collector+web soak was interrupted by a Claude
  Code restart; the detached rerun completed with **15/16 checks** — the
  declared RSS growth limit failed (collector 1.32 vs 1.25) from a single
  ~290 MiB step at the CTI reload, flat afterwards. Security review fixed DNS
  rebinding to the local app and a ThreatFox redirect key leak. Next P1: lower
  the reload high-water and re-soak with several reloads. See
  [OPERATIONAL_CONFIDENCE.md](OPERATIONAL_CONFIDENCE.md).
- Runtime repairs are merged to main at `35423bc`; 45 added regression cases,
  1,321 local tests and approximately 91% coverage. Six CI jobs passed at
  [run 37455481084](https://github.com/ConquestorYa/threatfusion-ai/actions/runs/37455481084).
  Counts are evidence for that commit, not a permanent assertion about HEAD.
- Original 34 local artifact/cache/data files were preserved. Real data and
  evaluation receipts remain ignored/private. A GitHub-only clone does not
  contain them; inventory before using a recipe, regenerate only permitted
  inputs, and do not substitute a synthetic/experimental model as a trusted one.
- Collector state is schema 3; schema-1/2 backups and legacy first-answer
  limitations are documented in [the repair contract](SOURCE_REVIEW_REPAIRS.md).
- User manual testing has **not** been completed. Automated UI checks and
  synthetic tasks do not count as the user's acceptance or an analyst pilot.
- Runtime correctness has improved; real detection efficacy, broad security,
  enterprise resources and RITA parity are still unqualified.
- Public hosting remains user-suspended; previews are off. Publishing verified
  source to main does not authorize deployment. Preserve the hosting checks in
  [AGENTS.md](../AGENTS.md).

## Ordered roadmap and completion gates

Work in this order unless new user feedback or a concrete defect justifies a
change. Record that reason here; do not choose unrelated features ad hoc.
Historical “Next” paragraphs in experiment documents are not this active queue.

| Order / status | Work | Completion gate |
| --- | --- | --- |
| P0 — next, pending user | Manual local workflow acceptance | User exercises install/start/stop/reopen, own-key CTI refresh/offline failure, completed conn/DNS collection, local identity/timelines and alias/IP exports. Record reproducible defects and fixes; do not mark passed without user results. Checklist: [MANUAL_ACCEPTANCE_TR.md](MANUAL_ACCEPTANCE_TR.md). |
| P1 — in progress | Operational confidence on the repaired source | Freeze this candidate; declare a bounded real wall-clock soak and broader permission/IO/database/resource faults before outcomes. Measure collector **and** web/representative CTI resources, exact retained counts, stale/coverage warnings, old-report preservation and recovery. No private data redistribution or physical host-disk exhaustion. |
| P2 — partial evidence, more work planned | Analyst usefulness and independent traffic validation | Predeclare actual investigation tasks on permitted independent benign/suspicious windows. Measure review burden, missed cases, correct evidence interpretation, time/task success and effects of normal context. Compare native RITA on identical inputs/configuration with separate output units; preserve negative results. User chose own-traffic + labeled-malware arms (2026-10-07): [design](REAL_TRAFFIC_EVALUATION.md). |
| P3 — planned, evidence-gated | Focused detection coverage | Prioritize observed gaps in timing/size/jitter/retry/idle/sparse failures. Develop proper registrable-domain DNS tunneling aggregation and benign CDN/update/telemetry controls. Separate development from newly reserved evaluation inputs; regress old CTI/context behavior. Each new detector needs measured incremental usefulness. |
| P4 — planned, no connector implemented | Versioned integration contract, then one pilot adapter | Define structured findings/coverage/provenance, stable event IDs and deduplication, time/source identity, privacy opt-in, authentication, backpressure/retry and schema compatibility. Select Wazuh or a generic SIEM/log destination from pilot needs; validate end-to-end delivery. Do not build many integrations before proving one. |
| P5 — planned | Repeatable private pilot and release | Independent users install/use/recover, documented security fixes and realistic resource limits, upgrade/backup behavior, useful operator guide and release checklist. Tag/release only when appropriate. Public hosting is optional and requires a new explicit user request. |

Manual feedback may arrive while independent P1 preparation continues; it must
not be silently replaced by automated checks. Fix a confirmed correctness or
privacy defect before extending detection. No feature or milestone is complete
just because code was generated or tests for its implementation passed.

## Committed direction: behavioral ML (user request, 2026-10-07)

The lexical domain model is a weak standalone signal. The user asked for ML that
goes well beyond domain names. Once P2 has produced permitted labeled real data,
design and evaluate a behavior-feature model before or within P3: connection
timing/size/jitter, destination rarity across clients, DNS patterns, CTI context
and per-device baselines. Develop only on development captures; evaluate on
untouched reserved inputs with the same discipline as other gates. Until then the
lexical model stays an auxiliary signal and frozen identities do not change.

## Deferred ideas, not automatic next tasks

- Active-file incremental tailing/shorter ingest latency, decided against rotation
  reliability and recovery requirements; current closed-log behavior stays clear.
- Optional collector service/supervision and multi-sensor/site identity, retention
  and capacity design; current one-sensor foreground contract is not multi-tenant.
- More source adapters, incident/case workflow and retroactive CTI investigation,
  justified by actual pilot tasks and privacy/operational cost.
- Better ML remains a separate evidence-gated track. CTI-only product development
  continues without waiting for a new model. Do not change frozen thresholds,
  tune on inspected holdouts, call fresh-disjoint strict temporal, or promote the
  augmented candidate without new sufficient untouched temporal evidence.
- LLM explanations may be considered later; no LLM is required for detection.
  Private telemetry must not be sent to an external model by default.

## Continue in a new chat or with another AI

Read in this order:

1. [AGENTS.md](../AGENTS.md): authorization, local-only operation, publication
   guard, data and frozen evidence restrictions.
2. This plan: product target, current capability/status and active priorities.
3. [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) and the **newest** section of
   [RELEASE_HANDOFF.md](RELEASE_HANDOFF.md): state and latest completed work.
4. [ARCHITECTURE.md](ARCHITECTURE.md), [DECISIONS.md](DECISIONS.md),
   [DATA_SOURCES.md](DATA_SOURCES.md) and [ML_DATASET.md](ML_DATASET.md).
5. The relevant feature/protocol document, [CHANGELOG.md](../CHANGELOG.md), source
   and tests for the chosen increment. Older measured outcomes remain attached
   to their original source/model/input identities.

Before edits: inspect HEAD, branch/worktree and user modifications; inventory
ignored local assets and lab receipts without publishing contents. Check which
artifacts/protocols actually exist in this workspace. Do not recreate inspected
evidence as a fresh holdout or guess success from old counts. Resolve code/doc
disagreement with a reproducible check, preserving original failure receipts.

Choose the earliest unmet gate with work that can safely progress now. State the
problem, intended behavior and meaningful acceptance before implementing. For
evaluation, freeze source/inputs/policy and independent controls before outcomes.
Keep private receipts outside Git. Use harmless simulation/permitted records;
never access suspicious destinations just to “test” detection.

For every completed increment, update this plan's current checkpoint/status,
PROJECT_CONTEXT, the newest handoff section and CHANGELOG as appropriate. Link
the contract and verification; record limitations and unresolved failures.
Publish only tested source to main under the existing hosting guard. Never
change the user's files or consent boundaries to make a gate look passed.

Suggested prompt to paste into the next chat:

```text
ThreatFusion AI projesine devam et. Önce AGENTS.md ve docs/PRODUCT_PLAN.md'yi,
ardından docs/PROJECT_CONTEXT.md, docs/RELEASE_HANDOFF.md'nin en yeni bölümünü,
docs/ARCHITECTURE.md, docs/DECISIONS.md, docs/DATA_SOURCES.md ve
docs/ML_DATASET.md'yi oku. Kodun ve workspace'in gerçek durumunu kontrol et;
kullanıcı değişikliklerini ve özel verileri koru. Ürün planındaki en erken
tamamlanmamış uygun işten otonom ilerle; eski deneylerin Next notlarını güncel
iş sırası sanma. Public site/deploy/preview açma. Cache, dataset, model,
telemetry ve evaluation dosyalarını GitHub'a gönderme. ML'nin fresh-disjoint,
strict temporal ve runtime promotion sınırlarını koru. Tamamlanan değişiklikleri
uygun şekilde doğrula, plan/context/handoff/changelog'u güncelle ve doğrulanmış
kodu mevcut hosting güvence koşullarıyla GitHub main'e yükle.
```

## Document authority and maintenance

Current user instructions take precedence. AGENTS defines operating constraints;
this plan defines current direction/priorities; feature contracts describe
behavior; handoff/changelog/protocols record dated work and evidence. Past
portfolio/hosted-demo plans are history, not permission or a requirement to
deploy. Planned items are proposals with gates, not claims or a commitment to
implement every idea. Change scope when evidence/user needs justify it, and
record the change rather than allowing documents to drift.
