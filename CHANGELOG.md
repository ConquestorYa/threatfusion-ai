# Changelog

All notable changes to this project should be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The current unreleased state is the v0.1.0 portfolio-release candidate. The
release date is added only when the final tag/release is created.

### Fixed

- An accidentally committed `.venv` symlink (in `4ba4119`) made the Linux
  installer fail with `ValueError`; it is removed and each commit's archive is
  now tested against the installer's extraction checks.

### Changed

- Section G feedback: Turkish lookup placeholder, localized and more visible
  file-upload area, "What does this page do?" explainers on Collected
  connections and Model evaluation, and a setup note explaining what the free
  abuse.ch key adds when ThreatFox/URLhaus keys are missing.

### Verified

- Manual acceptance Section H (redesigned UI) passed by the user on 2026-10-09;
  Section G remains open.

### Removed

- PhishTank source (DEC-089): it no longer issues keys and its public feed had
  failed since 2026-10-07. Older caches drop its rows on the next refresh.

- Render Blueprint `render.yaml` and Render-specific deployment instructions, at
  the user's request (DEC-086). The host-independent `Dockerfile.public-demo`,
  synthetic demo generator and their CI checks remain. A suspended Render
  service may still exist in the user's account until the user deletes it.

### Added

- P1 security review round 2 (callbacks under a foreign Host, static serving,
  theme script, background refresh, control socket): no new vulnerability; a
  test keeps the statically served folder limited to font assets.

- Security: the local app refuses requests whose `Host` is not loopback (or an
  operator-listed name in `THREATFUSION_ALLOWED_HOSTS`), closing DNS rebinding
  to the workspace; the ThreatFox API request no longer follows redirects with
  its key. Wall-clock soak result (15/16; reload memory step) and security review
  in `docs/OPERATIONAL_CONFIDENCE.md`. Turkish manual acceptance checklist and
  P2 real-traffic evaluation design. Docs/tests included.

- P1 operational confidence methods: predeclared nine-case collector CLI fault
  matrix (CTI refresh/lock, read-only state, unreadable file/directory, corrupt
  state, truncated gzip, missing declarations, SIGTERM) and a real wall-clock
  collector+web soak with a private CTI cache copy. Receipts stay private.
  Developer tooling: `CLAUDE.md`, `lab-experiment` project skill and a
  commit/push privacy/test guard hook. See `docs/OPERATIONAL_CONFIDENCE.md`.

- Current product plan/AI continuation guide with implemented capability status,
  ordered milestones and acceptance gates, current checkpoint, document reading
  order and copyable resume prompt. AGENTS, both READMEs, context/handoff and
  docs index use this entry point. Corrected stale portfolio-only feature-complete/
  public-demo-next wording and operational schema-3/all-answer references;
  historical experiments remain attributed to their original source. Docs only.

- Predeclared accelerated 72-event-hour mixed collector protocol: 144 immutable
  synthetic logs, 360k base observations plus 120 late-closed rows, independent
  retained SQL-window modeling and eight offline/full-export checkpoints. Separate
  own-worker RSS/state/idle measurements, two idle SIGKILL/restart proofs,
  open-close/rename/gzip/CTI/expiry and ledger/archive cleanup preserve all 83
  runtime modules and detector/ML policies. Ten new process/retention/privacy/
  freeze controls; deterministic temporary-file sampling race repaired under
  method-only amendment with original successful receipts and unchanged acceptance.
  Two real SQLite page-exhaustion controls prove file/checkpoint rollback, old
  report preservation and exact-once budget repair/restart without host disk fill.
  Prior interrupted CI passes six jobs on retry. Methods/tests/docs only; all
  generated traffic/state/receipts stay private. Not a real 72-hour soak, accuracy/
  parity/security/enterprise claim or ML promotion. No public site. See
  `docs/MULTIDAY_COLLECTION.md`.

- Collector-only diverse connection analysis with unchanged DNS/legacy bounds,
  global CTI/UID/conflict and detector policies. Bilingual prioritized 1,000-group
  snapshots disclose omissions and full-retained counts; verified private full
  JSON.gz retains all connection groups within 256/64 MiB budgets. Digest-owned
  atomic generations, declaration/CTI/retention cache invalidation, race protection
  and intact-archive cleanup preserve unrelated files and previous reports.
  Frozen known-source default-100k regression and synthetic 100k target export/
  actual SIGKILL/restart/gzip proofs pass; IoT-3 pruning stays explicit. Thirty-one
  new controls, 1,264 total tests; installed Linux check adds full export. Prior
  failures and all raw data stay local. No accuracy/parity/enterprise claim, ML
  promotion or public site. See `docs/CONNECTION_CAPACITY.md`. Earlier entries
  retain the limits/outcomes at their original implementation.

- Linux atomic private completed-log preparation with bounded validated shards
  and explicit raw incomplete-DNS quarantine. Collector verifies manifest/shard
  integrity, exposes bilingual aggregate coverage and disables expected context
  on rejected/quarantined/pending input. CLI/install checks and 30 new controls;
  frozen known-source row conservation and offline/restart/gzip regressions.
  Windows/IoT-8 original evidence stays; Linux retains 19,360 eligible + 49
  quarantined rows. IoT-3 default diverse-target analysis remains excluded;
  separate 20k arm processes 156,462 eligible rows with pruning disclosed.
  First failures and all private data stay local; no threshold tuning, accuracy/
  full-retention/parity claim, ML promotion or public site. `LOG_PREPARATION.md`.

- Separately frozen connection compatibility replays and sixteen transport/
  persistence/scope contracts. All 39,957 existing connection rows reconcile;
  the mixed Linux/DNS failure and capacity exclusions stay explicit.

- Frozen official Windows/Linux/IoT packet replay method, bounded complete PCAPNG
  qualification and capture-family history guards. Complete baseline cases
  reconcile 44,384 mixed rows. Valid unknown-transport import and large-log/window
  limits are exposed as exclusions; an earlier inspected source is explicitly a
  known replay. No truncated scoring, fresh-malicious success or RITA parity claim.
  Method/tests/aggregate attribution only; raw outputs remain private.

- Bilingual selected TCP/DNS investigation guidance, original/context workload
  counts before filters and safe canonical selections with upload identity reset.
  CTI remains visible, expected filtering reversible, reports retain original
  evidence. Two new complete synthetic replays reconcile supplied context,
  CTI override, expiry and collector/restart/gzip paths. Fifteen automated task/
  integrity checks; detector/ML policies unchanged. Independent real recordings
  and human analyst efficacy remain open.

- Frozen normal-review workload protocol, private reproducible packet generation
  and bounded official acquisition, strict complete-PCAP validation and separate
  TCP/DNS/attempt/native-RITA metrics. Two new synthetic windows and one intact
  normal IoT capture reconcile full offline/collector/timeline/restart/gzip paths;
  two truncated sources are explicitly excluded. Measurements document normal
  review burden, caching/shared-resolver and wide-jitter/sparse-failure gaps.
  Runtime/ML policies stay unchanged; independent real-source gate remains partial.

- Device/domain DNS investigation for uploads and collection: bounded UTC query
  and response-code timelines, explicit missing-time/gap limits, additive private
  exports and bilingual selectors. Collector scan/rejection health, idle analysis
  reuse with CTI/retention invalidation, stable mapping selection epochs and safe
  disk-full guidance. Declared private rotating-log recovery and 120k-record
  capacity protocols preserve original verdicts and disclose pruning/latency
  limits; no new detector, ML promotion, production accuracy or public site.

- Automatic completed TCP/UDP Zeek DNS collection alongside independent original
  connection results, transaction-aware copy/conflict handling, bounded bilingual
  client/domain snapshot queue and explicit shared retention/name/group limits.
  Private schema-1 state is backed up before schema-2 migration; old snapshots
  remain readable. Two new isolated 24-DNS/2-connection captures reconcile offline,
  collector and restart/gzip paths. 22 declared contracts pass; existing DNS/ML
  policy is unchanged. No tunneling, real benign FPR or public deployment claim.

- Separate bounded TCP-attempt review queue for sliding-window failed port/host
  diversity and repeated S0/REJ failures, explicit coverage and dedup/conflicts,
  bilingual upload/collector views and additive private schema-v2 exports.
  Predeclared controls and a real isolated 120-record workload pass; a new
  official 10,403-record capture exposes a sparse-failure coverage gap without
  increased recall. Original connection/domain/ML verdicts remain unchanged.

- Bounded connection-start investigation charts and state/known-byte/missing-byte
  summaries for uploaded and automatically collected groups, bilingual local
  views, report-local group references and additive schema-v2 timeline exports.
  UID conflicts/dedup match existing findings; detector/ML policies are unchanged.
  Two predeclared isolated real TCP termination captures each reconcile 72 starts
  across offline/collector/restart/gzip paths. No analyst efficacy claim.

- Zeek connection policy v2 includes bidirectional payload from incomplete TCP
  closes/reset endings under existing long/timing gates, explicit payload/reset/
  partial/failed-attempt counts and bilingual private reports/collector views.
  Expected declarations retain conservative SF/S1 coverage. Predeclared controls
  and three new official captures document added evidence and remaining gaps;
  real-source review counts do not increase. No ML or accuracy promotion.

- Linux completed Zeek TSV/gzip collector with private bounded SQLite evidence,
  crash/restart checkpoints, rotation/content deduplication, fair bounded scans,
  capacity-loss handling and SIGTERM cleanup. Installed `threatfusion-ai collect`,
  standalone `threatfusion-collect` and bilingual local refreshing snapshot view;
  active files wait for closure. No packet capture, public listener or autostart.
- Immutable four-capture official IoT-23 connection evaluation protocol and
  aggregate results/coverage gaps; labels excluded, no threshold tuning or ML
  promotion. Private collector imports reproduce offline results after restart
  and gzip duplication. Raw data, cache and outputs remain external/ignored.

- Optional expiring exact-endpoint connection declarations with upload-wide
  count/duration/byte limits, scoped CTI override and reversible local expected
  activity filtering. Schema-v2 connection exports retain original evidence and
  all groups, omitting declaration configuration/IDs. Eleven frozen context
  controls explicitly cover the same-endpoint software-identity limitation.

- Typed Zeek TSV connection metadata and independent originator/responder/port
  review for long bidirectional TCP sessions and sustained successful timing;
  duplicate/conflicting UID handling, missing-data limits, bilingual connection
  view and separate owner-only CLI export with endpoint aliases by default.
- Real isolated cache/persistent-HTTP/jitter workload capture and immutable
  synthetic connection workload controls measuring benign review burden.
  Shared-log RITA comparison retains its native scoring; no C2 accuracy,
  production parity, private telemetry upload or ML promotion claim.

- Client/target triage with independent CTI/behavior evidence, a separate
  sustained-periodic DNS review queue, coverage limits, bilingual local device
  view and explicit private device JSON export. Existing domain verdicts,
  aggregate export privacy and frozen ML thresholds remain unchanged.
- Immutable external synthetic device controls (12 types, two fixed seeds),
  client-evidence/privacy/UI regressions and a measured-capability roadmap for
  the intended Zeek/RITA alternative. No production accuracy or parity claim.

- Frozen three-client periodic-control protocol with real short live capture,
  deterministic checksum-valid synthetic-day replay, isolated pinned RITA lab
  setup and native-output comparison reporting. Records inputs/limitations and
  preserves legitimate periodic traffic as a negative control. No CTI/ML
  promotion or production efficacy claim; generated/downloaded data stays local.

- Local Ubuntu/KVM lab runbook and digest-pinned synthetic DNS/HTTP capture
  smoke sources; three-client Zeek capture and ThreatFusion DNS ingestion were
  verified. VM disks, credentials and traffic outputs remain local. RITA
  comparison and behavior-detection validation remain pending.

- User-scoped Linux applications-menu shortcut and `threatfusion-ai` command,
  with status/refresh/stop commands and supervised Ctrl+C/SIGTERM/SIGHUP cleanup.
- Managed local CTI settings panel: real CTI default, explicit synthetic mode,
  masked user-owned keys, session-only use or opt-in private plaintext storage,
  manual source refresh and optional 6/12/24-hour updates while the app runs.
- Serialized refresh attempts, safe aggregate status, failed-source cache
  preservation and startup catch-up without a system service or hidden autostart.
- Release audit/ignore protection for saved local credentials, plus local UI,
  ownership/permission, scheduling, command/shortcut and shutdown regression tests.

- Refreshed the three README interface screenshots from the current local UI,
  using only an isolated synthetic runtime and reserved demo telemetry.

- One-command Linux x86_64/glibc first installation without preinstalled
  Python/Git or sudo: fixed uv archive checksum, private Python 3.12.14, 49
  pinned/hash-required wheel dependencies and immutable source checkout.
- Offline local launcher with separate synthetic demo and explicit CTI-only
  collection, preserved runtime data, no saved API keys, loopback-only server,
  health-gated browser opening, free-port selection and supervised shutdown.
- Debian 12/Ubuntu 24.04 clean-install CI, real WebSocket UI/shutdown checks,
  first-run failure/privacy regression tests, Linux guide and English/Turkish
  copy-paste installation instructions.
- First-run verification: 805 local tests passed with 90% coverage; clean Debian
  and Ubuntu installations and ShellCheck passed, with no known pip-audit
  vulnerabilities and no changes to the 32 previously recorded local data files.
  All six GitHub CI jobs passed; the exact README command was also verified using
  only downloaded GitHub source, including foreground UI and Ctrl+C cleanup.

- Explicit CTI-only dashboard/CLI operation when a trusted ML artifact is
  unavailable, with disabled ML scoring and provenance-dependent history.
- Synthetic-only public-demo Docker image and free Render Blueprint, independent
  read-only model pin, Nginx request/connection/upload limits and supervised
  shutdown. CI checks the generated runtime and proxy behavior without private
  data or feed credentials.
- Artifact SHA-256 identity in schema-v4 aggregate ML reports, with legacy
  schema-v1/v2/v3 report support and collection-provenance validation.
- Fresh-disjoint builder regression coverage for domain separation, empty
  classes, post-cutoff refreshes, existing-output preservation and inert output.
- Release audit rejection of local dataset/cache/model paths, including binary
  artifacts in the tracked tree and reachable history; SQLite sidecar ignores.

- Multi-source IOC collection and normalization for ThreatFox, URLhaus, and SGB.
- DNS telemetry ingestion for generic CSV, Zeek `dns.log`, Pi-hole FTL, and
  AdGuard Home.
- Deterministic domain, URL-hostname, response-IP, and IPv6-network IOC
  matching with evidence-scope metadata.
- Explainable hybrid assessment combining CTI evidence, ML domain scoring, and
  DNS behavior signals.
- Character n-gram TF-IDF + Logistic Regression development-model workflow,
  trusted local artifact persistence, explicit FPR-budget threshold selection,
  and source-aware evaluation.
- Fresh/disjoint frozen-model holdout evaluation, long-tail benign evaluation,
  confidence intervals, base-rate caveats, malicious IOC timing preservation,
  and explicit post-freeze first-seen filtering support.
- Streamlit analyst dashboard, privacy-safe JSON/CSV report export, and local
  SQLite CTI/history persistence.
- Analyst feedback, prior-review context, expiring local suppression, and
  explainable related-activity analysis.
- Public-mode privacy controls, sanitized deployment bundles, non-root Docker
  packaging, and scheduled CTI refresh guidance.
- Ubuntu Ruff/pytest/coverage/pip-audit CI, Windows pytest CI, Docker
  build/health checks, and public-release tracked-tree/Git-history auditing.
- `SECURITY.md`, MIT `LICENSE`, data-source attribution notes, and release
  readiness documentation.

### Fixed

- Collector CTI reload memory (P1 soak failure: one-time ~300 MiB step): CTI
  records use `__slots__`, bulk loads stream rows and share repeated sources,
  threat types and timestamps, and the cached-analysis change check keeps a
  count plus field hash instead of a field copy. With the 616k-indicator cache:
  loader high-water 672 → 277 MiB; repeated in-process reloads plateau at
  ~640 MiB instead of ~1,212 MiB. Loading is ~10% slower under the same load.

- Switching to Collected connections, Analysis history or Model evaluation was
  hard to notice: the large primary-workspace cards stayed on top and the new
  page header appeared below the fold (user P0 section E). Secondary views now
  start with their header plus a compact way back, and the active sidebar entry
  is highlighted.

- "Download again even if fresh" is now an explicit one-shot option: it applies
  to the next update, clears when that update starts and says so. Previously it
  cleared silently when the box was disabled during the update, so a follow-up
  update was unexpectedly not forced (user P0 section C). Keys are read at
  click time.

- Quick lookup "no threat signal" summary no longer mentions ML thresholds when
  ML is disabled or calls an IP a "domain or URL".

- CTI update results (last attempt and per-source notes) now sit directly under
  the update button instead of below the schedule settings, and the PhishTank
  source card says when its keyless public feed is unavailable upstream rather
  than only "update time unavailable" (user P0 report: the note was not found).

- "database is locked" in the dashboard while a CTI update wrote (user P0
  report): readers ran the schema script, which needs the write lock, and the
  rollback journal blocks readers during a large write. The CTI cache now uses
  SQLite WAL (readers never wait for the refresh writer), skips schema writes
  when the schema is current, closes every connection after use (previously
  handles lingered until garbage collection; 45 after 10 reads), and the
  status panel shows a note instead of an exception if a lock still occurs.
  Packaged/demo caches are switched back to rollback mode for read-only
  directories. Quick lookups during an update no longer fail either.

- Quick lookup input-validation details are translated in the Turkish UI.
- Manual acceptance checklist reviewed end to end: the collection step used a
  sample that yields no review groups (empty default tables); it now uses the
  synthetic `analyst-guidance-v1` development set (818 records, 8 connection and
  1 DNS review group, verified). Removed a non-existent CSV export, corrected
  control names, made the offline test possible via the force option, and
  consolidated rounds into one ordered list while keeping the user's marks.

- CTI update UX from user P0 feedback: after a background update the sidebar
  button stayed disabled until another interaction and the result toast was
  easy to miss. Completion now reruns the whole page, shows a two-minute result
  message and distinguishes "already up to date", "no source reachable"
  (offline) and partial failures; keyless SGB/PhishTank failures no longer say
  "check your key". A "download again even if fresh" option and the time until
  the next due download are shown.
- SGB downloads its ~50 pages with at most four concurrent requests (page
  order kept, any page failure still fails the snapshot); a full fetch took
  95 s here versus about 165 s estimated sequentially (~3.3 s/page server time).
  The progress bar shows SGB record counts.

- Keyless PhishTank failures are shown as an upstream public-feed outage
  (information) instead of "check your key", and no longer turn every update
  into "finished with problems". On 2026-10-07 the public URL redirects to a
  CDN 404 image; the redirect is still refused and previous data is kept.

- Manual "Update CTI now" ran inside the Streamlit script, so any click during
  an update (including the same button, navigation or language change) aborted
  it mid-source without recording a failure (user P0 feedback). Updates now run
  in a background thread, the button is disabled while one runs, stale
  "running" status from a dead process is ignored, and the main workspace shows
  a progress bar (finished sources, SGB page estimate, source/stage) with
  start/finish notifications. Status files keep only safe aggregates.

- Collector no longer stops when the CTI cache is busy/locked beyond the SQLite
  busy timeout; it keeps the last complete indicators, discloses
  `cti_reload_deferred` in status and the dashboard, and never scans a busy
  first read as an empty cache. The analysis cache no longer deep-copies every
  indicator (~430 MiB / ~7 s per recompute with a 616k-indicator cache).

- Source-review correctness/privacy repairs: PCAP reply direction and bounded
  transaction pairing; all DNS IP answers in Zeek/AdGuard/Suricata/CSV/PCAP;
  literal IP target aliases and truthful export counts/privacy; explicit private
  collector identity display; bounded transactional SQLite history cleanup with
  separate maintenance failure status; hard match fanout/work limits and indexed
  IPv6 membership; cached IPv6-prefix lookup; IDNA detail normalization; safe
  malformed JSON validation. Failed collector analysis now retries committed
  records rather than reusing stale evidence. Schema-3 backup/migration exposes
  legacy first-answer coverage and reconciles identical old/new source rows.
  Original ML policies/private data are preserved; no public deployment.
  See `docs/SOURCE_REVIEW_REPAIRS.md`.

- Legitimate Zeek `unknown_transport` fields no longer make a completed connection
  file invalid solely because the official enum has 17 characters. A narrow
  exception preserves the original value; arbitrary oversized fields still fail,
  and unknown traffic never becomes eligible for TCP/UDP behavior detection.

### Changed

- Bundled IBM Plex Sans/Mono fonts (OFL-1.1, served locally) replace the stock
  Streamlit font. The sidebar is now one **Pages** navigation list plus compact
  CTI status; setup, API keys and CTI updates moved to a **Setup & CTI updates**
  page (default on a fresh install) with a source details table.

- Visual redesign after P0 feedback (DEC-088): two themes (Dark, Light) bound to
  Streamlit's native theme so tables and inputs match; one accent color;
  bundled Source Sans/Source Code Pro fonts; new two-ring logo; compact header
  with language and theme controls; tab-style primary navigation; no emoji,
  pill tags, uppercase kickers, glows or step diagrams; ML panels hidden when
  no model score exists; CTI-only caveat shown as a quiet note. Browser-based
  contrast audit: no text below WCAG AA in either theme.

- The Turkish manual acceptance checklist lists only remaining tests (sections
  A–G with goal, prerequisites including whether API keys are needed, exact
  steps and expected results); completed user results moved to the handoff.

- CI installs development dependencies explicitly on Ubuntu and Windows, so
  lockfile regeneration cannot silently remove Ruff/pytest from checks. Ruff
  advances to 0.16.9 while preserving unrelated locked dependency versions.

- Integrated verified Linux first-run and credential privacy work into `main`
  at the user's request; both README download commands and the installer's
  default ref use `main`. The existing Render demo remains user-suspended;
  integration uses `[skip render]` and adds no hosted resources.

- CTI refresh diagnostics no longer forward raw collector errors to callbacks,
  outcome details or CLI logs; authenticated URLs/private response values are
  omitted and the safe SGB pagination instruction is retained.
- Secret-file paths (`.env`, Streamlit secrets and private-key containers) are
  ignored and rejected by tracked-tree/history release auditing. First-run keys
  remain caller-provided only, with no developer/shared credential fallback.
  Follow-up verification: 818 local tests passed with 90% coverage, zero secret
  audit findings and unchanged checksums for all 32 original local data files.

- The privacy-profile caption now describes a session-only workspace; using
  shared-history privacy controls does not imply public hosting.

- Development remains local; public hosting requires a new explicit user
  request. Verified source updates can still be published to GitHub. The
  retained Render Blueprint disables automatic deploy and previews; CI also
  supports separate `local-development/` branches to avoid an active main-branch
  hosting integration. Existing service suspension and Blueprint Auto Sync
  must be handled and verified separately.
- Fresh-disjoint snapshots now remove malicious and benign development overlap
  before persistence and use the canonical protocol identifier.
- The evaluation dashboard describes each report's actual temporal protocol,
  cutoff and artifact identity. Loading a report never promotes its artifact.
- Final evaluation rejects synthetic demo artifacts, mismatched recorded
  artifact/development provenance and missing/changed recorded temporal cutoffs.
- Augmented runtime promotion is deferred pending stronger untouched temporal
  evidence; the missing original default artifact is distinguished from the
  separately generated synthetic demo runtime.
- Independent follow-up CTI collection found five unscored post-cutoff SGB
  domains. Original local data remains unchanged; this readiness count does not
  replace the fresh-disjoint result or justify promotion.

- ML terminology uses `ml_score` rather than implying calibrated malware
  probability.
- The v1 scope is frozen around final evaluation, portfolio presentation,
  hosted demo, and release instead of expanding into API/streaming/Suricata,
  SOC integrations, LLM features, or neural-network model families.
- The runtime default remains the earlier trusted artifact while experimental
  candidates are evaluated separately and never auto-promoted.
- Documentation now distinguishes the completed historical character-only C=4
  holdout, the rejected reconstructed lexical candidate, and the improved
  augmented lexical candidate measured with a fresh-disjoint protocol.

### Release gates still open

- Collect stronger untouched temporal evidence before reconsidering augmented
  runtime promotion; the current decision is to retain it experimentally.
- Complete local security review and remediation. Public hosting is deferred
  unless the user explicitly requests it again.
- Complete final manual release verification, then create the `v0.1.0` tag
  and GitHub release.
