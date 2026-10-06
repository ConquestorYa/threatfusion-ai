# v0.1.0 Release Handoff

Status date: 2026-10-06

## P1 fault matrix, collector repairs and wall-clock soak (2026-10-07)

- Started P1 from verified main `8d93abe` (docs-only after runtime `35423bc`;
  1,321 tests re-run on HEAD, 34 local data hashes unchanged). Lab VM is shut
  off (the lab README's "left open" note is stale); Kali/system VMs untouched.
- `operational-faults-v1`: nine collector CLI cases declared before outcomes.
  Five runs, all receipts preserved: original 0/9 (method error, which also left
  that run's own collectors running; stopped by PID), amendment 1 7/9 (real CTI
  lock defect; unreadable-directory byte check was a method race), amendment 2
  8/9 (repair + method fix; Linux directory-move method error), amendment 3 9/9,
  amendment 4 on the final candidate 9/9 with zero orphaned processes.
- Repairs in `d006771`: busy/locked CTI reads keep the last complete indicator
  view, set `cti_reload_deferred` and show a bilingual dashboard warning; a busy
  first read waits (or `--once` exits 1) and never scans as empty. The analysis
  cache keeps a shared immutable indicator field view instead of
  `copy.deepcopy` (~430 MiB / ~7 s per recompute with the 616k cache), still
  detecting in-place changes. Seven new tests; six fail on the unrepaired source.
- `wallclock-soak-v1` (6 real hours, collector CLI + local Streamlit with an
  emulated persistent and periodic fresh tabs, private copy of the developer CTI
  cache, 115,200 synthetic observations, CTI change at hour 3) is declared with
  fixed acceptance. Two method smokes preceded it (not evidence): the first
  exposed the deep-copy cost; the second showed a one-time ~1.2 GiB reload
  high-water, so the growth check may fail — the limit was not changed. The first
  full run was interrupted ~45 min in by a Claude Code restart (receipt kept); a
  detached rerun with the same candidate is in progress. No soak result yet.
- Developer tooling (not runtime): `CLAUDE.md` imports AGENTS; project skill
  `lab-experiment` encodes this protocol; `.claude/hooks/publish_guard.sh` blocks
  commits/pushes carrying private data and pushes failing Ruff/pytest/privacy
  audit. It loads only when Claude Code starts in this repository and does not
  verify Render.
- Hosting before publication: user confirmed the Render service is "Suspended by
  you", the last deploy was 2026-10-04, the Blueprint shows only manual sync.
  Auto-Deploy is still "After CI Checks Pass"; source-only commits use
  `[skip render]`. Previews were not visible; no PR is used.
- Verification: 1,328 local tests, ~91% coverage, Ruff clean. Manual acceptance
  (P0) remains pending and is not replaced by these checks.


## Current product plan and continuation (2026-10-06)

- [PRODUCT_PLAN.md](PRODUCT_PLAN.md) is now the entry point for target product,
  capability/status inventory, latest verified runtime, ordered milestones,
  evidence gates, deferred ideas and a copyable Turkish continuation prompt.
  AGENTS, both READMEs and the docs index point to it. Historical “Next” notes
  are preserved as dated results, not an active queue.
- Replaced the stale “feature-complete / public demo next” framing with the
  local analyst workbench direction: manual acceptance, operational confidence,
  independent analyst/traffic evidence, focused detection, one SIEM pilot
  contract and a private pilot/release. Web UI/Linux automation remain; RITA
  stays external. Wazuh/SIEM integration and tunneling detection are not delivered.
- Current runtime stays `35423bc`: 1,321 local tests, approximately 91% coverage,
  six successful CI jobs. User manual acceptance is pending. No runtime code,
  ML identity/threshold, local data, hosting or authorization changes are made
  by this documentation update. Operational schema/answer references now link
  to schema-3 repair contracts; older measurements retain their source scope.
- Documentation verification: 168 relative file links resolve, staged diff
  checks and tracked-tree/reachable-history privacy audits pass. Runtime/test/
  script/data files are unchanged; no extra local runtime test run is claimed.


## Pre-manual-test correctness and privacy repairs (2026-10-06)

- Reviewed the complete source/test/installation/reporting paths against main
  `4b37123`, with original findings and owned synthetic probes privately preserved.
  Fixed nine confirmed problems: PCAP client direction/query pairing, discarded
  additional DNS IP answers, literal IP leakage/misleading report counts, managed
  local identity controls, SQLite cleanup variable limits/maintenance reporting,
  unbounded CTI match fanout, cached IPv6 prefix lookup, IDNA evidence details and
  malformed AdGuard JSON exception handling. No ML threshold/model promotion.
- Collector schema 3 preserves schema-1/2 private backups and old checkpoints;
  legacy first-answer coverage is disclosed. Reimport of an identical original
  row reconciles old/new representations; changed source rows still conflict.
  Reports alias literal IP targets by default; explicit local exports describe
  their IP inclusion. New history rows alias IP targets; existing history is
  preserved. Aggregate CSV adds `target_type`; JSON distinguishes domain/IP/
  total target counts. CLI aggregate report files are written atomically as 0600.
- A separate ignored 0600 identity mapping bound to the selection generation
  enables explicit local host/device display. Shared snapshots/full archives
  retain aliases. Real managed CTI mode no longer needs public-mode restrictions
  to disable history; demo/public profiles retain their restrictions.
- Matching fails explicitly above 250k evidence objects or one million lookup
  operations; no partial success/truncated evidence. IPv6 prefix membership is
  indexed and idle collector polls reuse CTI data until DB/WAL changes. Failed
  analysis preserves the published report and retries committed rows, including
  on the next idle tick. This is a safety bound, not enterprise-scale proof.
- PCAP pairing is Ethernet/classic UDP DNS only, within 120 seconds and matching
  client/resolver/ports/ID/name/type; most recent eligible query is paired. Query
  retransmissions and unmatched replies remain separate observations, with
  visible diagnostics; encrypted DNS/TCP reconstruction is not added. Supported
  single-question Suricata detailed/grouped v2/v3 exports retain every IP answer;
  missing endpoint direction evidence remains unattributed.
- See [SOURCE_REVIEW_REPAIRS.md](SOURCE_REVIEW_REPAIRS.md) for contracts and
  migration/manual-test implications. Earlier frozen collector measurements
  describe earlier source identities and are not new performance evidence for
  this revision. Wall-clock soak, broader faults, representative permitted
  traffic, detection efficacy and analyst pilot remain open. Reserved evidence
  and original 34 artifact/cache/data files stay local and unchanged.
- Verification: **1,321 local tests passed / approximately 91% coverage**,
  including 45 added regression cases; Ruff, 12 Bash syntax checks and diff
  validation pass. Original 34 data hashes and the predeclared repair scope
  remain intact. Owned probes confirm 32,767-row cleanup above the actual
  32,766 SQLite variable limit, all-answer order invariance, IDNA evidence,
  contextual IPv6 lookup, correct PCAP client and working managed local controls.
  A 1,000-event/1,000-URL same-host probe fails explicitly at the production
  match bound, without returning partial evidence; not whole-product sizing.
  Source-only publication uses `[skip render]` after user-suspended hosting/
  preview-off verification; no hosted resources or deployment are added.


## Accelerated multi-day collection and own-process resources (2026-10-06)

- `multiday-collector-v1` freezes main `36b1823` and all 83 runtime modules before
  outcomes, permitting no runtime/detector/ML changes. Three accelerated event
  days rotate 144 completed conn/DNS logs, 360,000 base observations plus 120
  late-closed rows. This is not a 72-hour wall-clock soak or new detection evidence.
- Independent hash/event/ingestion/capacity modeling reconciles retained SQL
  payloads every ordinary/idle hour scan. Eight predeclared full-export checkpoints
  match offline findings/timelines/attempt/DNS calculation. Parsing is shared;
  retained-policy modeling is independent. The 100k window and pruning remain.
- Two own idle-worker SIGKILL/restarts preserve the published snapshot and
  selection, add zero old records, defer open logs and import their 60 rows once
  after closure. Rename/gzip copies are duplicates. Synthetic CTI changes
  invalidate caches. Eight/further-eight-day jumps prove expiry/no resurrection
  and empty record/file/path ledgers plus intact managed archive cleanup.
- Resource collection separates the long-lived worker from parent fixture/oracle
  computation. OS RSS high-water plus 50ms samples and state logical bytes measure
  warm idle latency and steady-state ratios against limits declared beforehand.
  Prior evaluator-only memory measurements retain their original scope.
- Both original and method-amended runs pass all predeclared limits. Amended
  collector RSS high-water 648.5 MiB, peak sampled state 131.7 MiB, maximum hour
  scan 7.181 s, warm idle median/p95 0.304/0.347 s. Last-day RSS/state ratios
  1.0030/1.0031. Final hour exports 63,981 groups / 1,000 visible within the
  100k mixed record window; expiry/cleanup state is 60,843 bytes. This host/
  two-indicator synthetic scope excludes web/cache/input/evaluator memory and
  does not establish enterprise throughput or a product performance improvement.
- First full run succeeds; a separate deterministic monitor temporary-file race
  is preserved with the frozen original method. A method-only amendment uses
  single non-following stat/disappearance handling and final declaration/source/
  candidate byte recheck, repeating unchanged source bytes and acceptance in a
  new private root. Ten new retention/process/security/freeze controls pass.
- Two separately declared real SQLite page-budget cases (3/1,001 original +
  1,200 new connections) produce `SQLITE_FULL` without filling host disk. Failed
  file payload/checkpoint rollback, preserved original snapshot/full archive,
  integrity and exact-once retry/restart/full export all pass. Only owned
  synthetic state is used; physical IO/corruption faults remain open.
- Prior capacity CI run `37364427665`, cancelled during the Actions incident,
  passes all six jobs on attempt 2 for exact main `36b1823`. Hosting remains
  user-suspended, previews off and deploy history unchanged. All generated logs,
  SQLite, snapshots, archives, sources/receipts remain private; only method/tests/
  documentation go to main with the suspended-hosting guard. No public site.
- See `MULTIDAY_COLLECTION.md` for acceptance, measurements and reproduction.
  Next: an actual bounded wall-clock soak and broader filesystem/database faults,
  representative permitted traffic/security review, then untouched timing/sparse/
  tunneling evidence, SIEM contracts and analyst pilot. Reserved sources and all
  frozen ML/promotion decisions remain.
- All 83 runtime modules and 34 original local data files remain byte-identical;
  both runs use identical 144-source hashes. First method/test copies, successful
  receipts and deterministic monitor failure probe stay privately preserved.
- **1,276 local tests / approximately 91% coverage**, twelve new controls; Ruff,
  Bash/diff and public tree/history audits pass. A first sandbox-bound suite
  records two EPERM socket denials; the authorized local socket run passes all.


## Diverse connection capacity and private full reports (2026-10-05)

- Collector-only connection analysis separates IP diversity from the unchanged
  DNS 25k-name bound. Global UID/conflict handling, CTI and existing detector/
  timeline/attempt behavior stay. Upload/legacy bounds remain; no IP-domain ML.
- Above 1,000 connection groups, the bilingual dashboard uses a prioritized
  snapshot with exact omissions and full-retained workload counts. Separate
  deferred JSON.gz download verifies the exact private generation and retains
  every connection group within retained evidence. Two digest-owned atomic slots
  preserve previous publication on failures and avoid adopting unrelated files.
  Expanded/compressed budgets are 256/64 MiB; other section bounds remain.
- Frozen default-100k replay now completes IoT-3: 100,000 retained records,
  56,462 pruned, 40,706 full groups / 1,000 visible, two attempt reviews and no
  TCP reviews. Linux retains all 19,360 eligible rows, with 49 private quarantine
  rows; Windows/known IoT-8 original evidence is identical. Offline independent
  retained-payload/full-report/restart/gzip checks reconcile all arms.
- Synthetic 100k diverse IPv6 targets produce 74,132,073 expanded report bytes
  and 100k full groups, with 99k snapshot omissions. Actual own-writer SIGKILL
  during encoding preserves old snapshot/archive; restart retains 100k with
  zero new records. One private unpublished temporary remains, never served.
  Large idle arms reuse archives. Peak evaluator RSS 1,092.3 MiB includes oracle/
  source/report copies, not collector-only RSS or an enterprise guarantee.
- First verifier tuple/JSON-array failure remains; separately frozen method-only
  amendment corrects comparison. Earlier preparation strict/default exclusions
  remain historical evidence. These are inspected-source engineering regressions,
  not fresh detection accuracy or RITA parity. Reserved inputs remain unacquired.
- **1,264 local tests / 91% coverage**, including 31 new capacity/security/recovery
  controls; clean Linux installer check adds 1,002-group full export. Seven
  existing runtime modules change, 75 of 82 stay identical, one module is added;
  34 original local data files remain identical. Method/tests/aggregate docs only
  go to main with the suspended-hosting guard. All raw data/SQLite/archives/
  receipts stay private. No public site, thresholds change or ML promotion.
- Next: representative multi-day load/resource/security/recovery protocol, then
  untouched timing/sparse/tunneling evidence, SIEM and analyst validation. See
  `CONNECTION_CAPACITY.md` for contracts, limits and reproduction. The older
  sections below describe their original outcomes, not current collector limits.

## Bounded preparation and incomplete-input coverage (2026-10-05)

- Linux `threatfusion-ai prepare-logs` / package entry point atomically publishes
  private validated completed TSV/gzip shards outside Git. Existing destinations
  survive races; active/changing/invalid/budget-exhausted sources publish no prefix.
  Bounds: raw/expanded 256 MiB, 500k rows, 256 KiB lines/headers, 8 MiB/25k-row
  shards (at most 64), 64 MiB raw quarantine. Original rows/timestamps/UIDs stay.
- Missing DNS query/type is strict by default. Explicit quarantine preserves
  original bytes/reason privately; other metadata errors still fail closed.
  Collector verifies inventory/content and exposes aggregate counts in both
  languages. Rejection/quarantine/pending input disables expected declarations,
  surviving restart and one ingestion window after removal. Original evidence,
  shared 100k retention and detector/ML policies are unchanged.
- A frozen known-source regression preserves first strict IoT-3 DNS and default
  unique-target failures in separate roots. Final amended replay conserves all
  rows: Windows 33,981; Linux 19,360 eligible + 49 quarantine; IoT-3 156,462
  eligible + 6 quarantine; known IoT-8 10,403. Windows/IoT-8 original findings,
  timelines/DNS remain identical. Successful arms reconcile retained offline/
  collector/restart/gzip with zero rejection/pending/new-on-restart records.
- **IoT-3 default analysis remains excluded** by the existing 25k unique-query
  bound, also applied to connection destination IPs. Separately declared 20k
  window imports eligible source rows, retains 20k, prunes 136,462 and discloses
  coverage loss. It is not full retention or fresh detection efficacy. The
  existing 64 MiB snapshot remains another bound. Next: declare safe diverse-
  target/report-capacity behavior, then representative load/security and untouched
  detection/analyst evidence. Reserved inputs remain unacquired.
- **1,233 local tests / 91% coverage**; 30 new controls, Ruff/Bash/diff checks.
  Linux black-box installer checks now exercise preparation and duplicate-free
  recollection. Four existing runtime modules change; 77 other existing modules
  and 34 original local data files remain identical. Method/tests/aggregates only
  go to main with suspended-hosting guard; raw traffic/manifests/quarantine/SQLite/
  receipts remain private. See `LOG_PREPARATION.md`. No public site or ML promotion.

## Official Zeek enum compatibility repair (2026-10-05)

- A separately predeclared `unknown-transport-import-v1` permits only the exact
  official 17-character `unknown_transport` enum through the existing 16-character
  protocol bound. Other overlong values/metadata limits stay rejected; unknown
  traffic remains ineligible for TCP long/timing/attempt review. Only parser
  module changes; all 80 other runtime modules and original local data stay.
- The full mixed-source compatibility replay remains failed: Normal-21 DNS has
  eight missing queries and 49 missing type values. No rows filtered/invented or
  original exclusions overwritten. An explicit connection-only amendment then
  reconciles all 39,957 existing connection rows across offline/collector/timeline/
  restart/gzip, with zero rejected/pruned/new-on-restart records. Linux's 10,662
  rows and two unknown groups survive; unknown reviews remain zero. Windows and
  known IoT-8 original full connection evidence is unchanged.
- **1,203 tests / 91% coverage** pass, including sixteen new enum/eligibility/
  persistence/scope controls. Ruff/Bash/diff checks pass. Source-only main carries
  method/tests/aggregates; all raw traffic, caches and failed/successful receipts
  remain private. A separate private Unix exclusion test leaves portable
  acquisition checks enabled on Windows. Reproduction and strict scope:
  `INDEPENDENT_REPLAY.md`.
- Next: bounded large-log ingestion/window coverage and malformed/missing DNS
  identity handling; mixed Linux/new malicious gates still open. This repair is
  input compatibility, not increased recall or RITA parity. Reserved sources,
  frozen ML policies and deferred runtime promotion remain. No public site.

## Real-capture diagnostic replay (2026-10-05)

- Four complete official packet acquisitions, frozen before native/detector
  outcomes, retain unchanged runtime/ML policies. PCAPNG qualification was
  explicitly amended before outcomes while preserving first receipts/bytes.
- Normal-20 retains 33,981 mixed rows with one TCP and 25 DNS reviews; 143 DNS
  groups exceed the snapshot group bound. Known IoT-8 retains 10,403 rows with
  no TCP/attempt reviews; it is an earlier inspected source, not fresh evidence.
  Both exactly reconcile offline/collector/restart/gzip paths.
- Normal-21 is excluded by a legitimate 17-character `unknown_transport` enum
  rejected by the 16-character importer bound. IoT-3 exceeds both 16 MiB/file
  and 100k shared rows. Complete native processing does not repair product
  exclusions. No post-outcome replacements, truncation or detector tuning.
- Added bounded acquisition, conservative complete PCAPNG qualification, frozen
  output reconciliation and capture-family history guard. Aggregate results,
  hashes, reproduction, attribution and remaining gates: `INDEPENDENT_REPLAY.md`.
  Raw traffic/native outputs/SQLite/evaluations remain private. Two further
  source identities remain unacquired; new independent malicious gate is open.
  Next: explicit unknown-transport compatibility repair, then scalable ingestion
  contracts. Source-only integration uses suspended-hosting guard; no public site.
- Baseline method validation: **1,186 tests / 91% coverage**, Ruff/Bash/diff checks
  pass. The entire 81-module runtime stays identical to `cc38d32` at this point.

## Analyst guidance and preserved review context (2026-10-05)

- `analyst-guidance-v1` freezes eight task families against main `450c958` before
  implementation. Bilingual selected TCP/DNS guidance explains original evidence,
  coverage and next checks, including CTI precedence, declaration/identity limits,
  expiry/bounds and shared-resolver attribution. Guidance survives chart caps.
- Pre-filter TCP counts distinguish original/declared/unexplained/CTI units; DNS
  and attempt queues stay separate. Original findings/all-group exports remain;
  expected filtering is reversible. Canonical selection mappings are preserved
  across language changes; upload TCP mapping changes reset stale selections.
  No automatic declarations, extra persistence, requests or keys.
- Two new complete synthetic recordings (seeds 20261071/20261171) represent two
  hours each and yield 675+143 and 670+144 mixed rows. All 1,632 reconcile complete
  manifest/offline/collector/restart/gzip evidence without rejection/pruning.
  Supplied inventory separates five of eight original reviews, leaving three.
  A CTI fixture restores one; expiry restores all eight. Same-endpoint unrelated
  processes can still match. No detector threshold change or inferred identity.
- Fifteen new task/integrity tests; **1,147 tests / 91% coverage pass**. Ruff,
  Bash/diff checks and 295-file tracked-tree privacy audit pass with zero findings.
  Detailed reproduction,
  hashes, units and limits: `ANALYST_REVIEW.md`. Raw traffic/rules/SQLite/evaluation
  receipts stay outside Git. Seven existing UI/translation modules change; 73
  frozen runtime modules and all 34 original local data files remain identical.
  Three owner-only Unix lab-directory controls are explicitly Unix-only; portable
  UI/task contracts still run on Windows. No product test is bypassed.
- Human decisions/time and new independent normal/malicious windows remain open;
  no accuracy/RITA parity/production claim. Previous truncated source exclusions
  remain. Fresh-disjoint is not strict temporal; original model artifact remains
  missing and augmented runtime promotion deferred. Owned offline lab work ends
  with VM restored off; no public hosting action is authorized.
- Source-only `[skip render]` main integration requires exact tested-tree/all-six
  CI verification and unchanged user-suspended service, previews off and deploy
  history. Hosting auto-deploy/Blueprint auto-sync are not claimed disabled.

## Ruff dependency PR #173 recovery (2026-10-05)

- Old PR run failed before application validation: Ubuntu reported `No module
  named ruff`, Windows `No module named pytest`. Dependabot had regenerated
  `requirements.txt` without development tools, while CI installed only that
  file. This does not contradict the successful six-job main run at `fd8f87e`.
- Ubuntu/Windows CI now install `requirements-dev.in` explicitly alongside the
  tested lockfile. Ruff is consistently pinned to 0.16.9 in both declarations;
  unrelated locked dependencies are preserved. The repaired existing PR includes
  current main rather than replaying old project state. No runtime/ML/data or
  hosting change is part of this update.
- Local validation: Ruff 0.16.9 passes, pip's combined-requirement dry run resolves
  without conflicts, **1,132 tests / 91% coverage** pass in a separate worktree.
  A timed-out automatic approval review was retried successfully for existing
  loopback/Unix socket tests. Keep raw logs/private data outside Git; verify the
  repaired PR and merged main's complete CI plus the unchanged suspended hosting
  guard before reporting integration complete.

## Normal review workload and same-source comparison (2026-10-05)

- `review-workload-v1` was declared before traffic bodies/product results:
  baseline `c82f8d21b6867915abda7a016a2e2a62811e32f1`, twelve profiles, two
  represented two-hour seeds and three new official source identities. All 80
  top-level runtime modules remain byte-identical. CTI/ML/expected declarations
  are off, labels stay outside detector inputs, no threshold/ML policy change.
- Added private repeatable method preparation, seeded packet generation, bounded
  official acquisition, complete-PCAP structure validation, frozen input/tooling
  verification and independent TCP/DNS/attempt/fallback/native CSV units. Packet
  generation never transmits traffic. Offline Zeek uses no network/capabilities;
  native RITA remains optional, not a product/runtime dependency.
- Separate RITA configuration preserves previous configs/databases and upstream
  scoring. Only declared provider internal subnet context and matching private
  input-owner UID/GID are added; feeds/update checks stay off. The initial UID
  import failure is retained, an absent fresh database verified before retry,
  and successful Zeek outputs reused unchanged. No file permission relaxation.
- New development/reserved packet replays yield 672/671 connection rows and 144
  DNS transactions each, with eight TCP reviews among twelve groups and one DNS
  review among eleven observed-client groups. Both have **5/7 normal TCP reviews**
  versus **3/5 simulated TCP reviews**. Normal endpoint DNS reviews are 1/6,
  simulations 0/4; shared resolver has a separate 16-query group and no endpoint
  attribution. Wide jitter and sparse attempts remain uncovered. This is review
  workload and observable-intent overlap, not malware FPR/recall.
- New provider-described normal Somfy-02 PCAP yields 52 connection + 52 DNS rows,
  one TCP Review/2 groups and one DNS Review/2 groups over 83,250.28138 seconds.
  Somfy-03 and Trojan-42 raw acquisitions match declared byte lengths but contain
  truncated final packets: Zeek and structural validation fail. Partial logs are
  excluded, not repaired, scored as zero or replaced after results. The new
  independent real-source gate is **partial**; no successful new malicious-source
  comparison or representative enterprise normal coverage is claimed.
- Native RITA on identical complete logs exports 23/23/1 rows. Development
  Critical/High/Medium/Low = 6/5/2/10, reserved = 6/4/3/10, Somfy-02 = one High.
  Native rows/severities and ThreatFusion queues have different units; synthetic
  payloads/prevalence/time influence scoring. No RITA equivalence/ranking claim.
- All three successful cases retain **1,735 mixed records** without rejection/
  pruning and exactly reconcile offline connection/DNS findings, timelines and
  attempts. Retrospective seven-day collector clocks preserve full inputs.
  Each restart adds zero and two gzip copies duplicate. Complete method,
  attribution, hashes, aggregate results and reproduction: `REVIEW_WORKLOAD.md`.
  Raw PCAP/log/native CSV/evaluation/SQLite receipts remain private outside Git.
- Validation: **1,132 tests / 91% coverage**, including thirteen new protocol
  controls; Ruff/Bash/diff checks pass. Initial socket tests were sandbox-blocked
  and rerun with loopback/Unix socket permission. A pre-existing public-directory
  fixture now explicitly sets its mode so strict umask cannot silently make it
  private; the complete suite also passes under umask 077. Staged-source and
  reachable-history privacy auditing passed with zero findings.
- All 34 original local data files and frozen runtime modules keep checksums.
  Owned comparison backend stopped, no interactive guest users/remaining running
  containers; VM restored shut off. Original ML artifact is still missing,
  fresh-disjoint is not strict temporal, augmented promotion remains deferred.
- Next: predeclare analyst tasks and scoped normal-activity context, preserve
  original/CTI-conflicting evidence and measure workload. Actual analyst efficacy
  requires participants. Select several new intact permitted normal/malicious
  windows before separately scoped timing/sparse-failure changes; reserve new
  untouched inputs. DNS tunneling/general UDP, multi-day/security/SIEM contract
  gates remain open. Do not retune on these now-inspected sources.
- Source-only main uses `[skip render]` with confirmed user-suspended service,
  previews off and no Blueprint resource changes. Recheck all six CI jobs and
  unchanged suspension/deployment history after publication; no public hosting
  action is authorized.

## Device DNS investigation and collector reliability (2026-10-05)

- Added `dns-device-timeline-v1` to uploaded device triage and collected DNS:
  select a device/domain for UTC query-count and response-code charts, existing
  evidence and explicit untimed/gap/coverage limits. First 200 eligible groups,
  48 adaptive >=60-second buckets; first 500 visible selectors/table groups.
  Additive optional schema-1 device report block; old snapshots readable.
  Unknown clients/IP fallback targets have no DNS chart. Default aliases omit
  raw client/answer addresses; existing explicit local upload IP toggle remains.
  Original detector priorities, aggregate history and ML gates are unchanged.
- Current collector retains selections while ordered connection/DNS mappings
  match, using a random exported epoch. Raw comparison identities/hash stay
  private in SQLite. Idle evidence/CTI reuse analysis, CTI mutations/pruning/new
  rows invalidate it; declaration expiry still reevaluates each scan. Additive
  timestamp/ingestion/name indexes, bounded scan/rejection metadata and safe
  disk-full diagnostics retain SQLite schema 2 and completion policy v2.
- Private `collector-reliability-v1` plan preceded implementation; a frozen
  source bundle precedes the new 20-minute rotating capture. The protocol
  includes real mixed DNS/connection logs, 30-second rotation, SIGTERM/SIGKILL
  restart and a 45-second pause, plus exact offline/state/report reconciliation.
  Initial sensor capability/policy-read setup failures remain private receipts.
  Successful 30-second preflight: 72 queries/six connections, no reported drops,
  exact offline/collector/restart/gzip match. Evaluation initially omitted final
  `dns.log`/`conn.log`; tooling was corrected without changing records/runtime.
- Actual unreadable/repaired files, malformed gzip, fair scan quota, snapshot
  ENOSPC with preserved committed evidence, SQLite-full diagnostics, mutable CTI,
  retention and idle-rule expiry have regression controls. Disk-full injection
  does not establish real filesystem/power-loss recovery. A 120-file/120k-record
  mixed backlog attempts 64 then 56, discloses 20k capacity pruning, retains
  40k connection + 60k DNS rows and reuses idle analysis without resurrection.
  Full tick walls 8.611/12.293/0.103 s, sampled RSS 456,998,912 bytes and owned
  state 82,087,782 bytes (50 ms samples, fixture creation excluded). One sizing
  run, not representative throughput/guaranteed peak or complete retention.
- Workflow, live/capacity aggregate receipts and reproduction:
  `DNS_INVESTIGATION.md`. Raw logs/PCAP/evaluation/SQLite remain private outside
  Git. Active-file tailing is deferred; closure/delivery/polling latency is
  explicit. No new listener/API credential/deployment or ML promotion.
- New `rotation-live-20261004T231339Z`: 1,200-second capture, observer 1,195.19 s/
  115 snapshot ticks, 84 closed files, 2,880 DNS (UDP/TCP 1,440/1,440) and 240
  connection rows. All offline connection/DNS findings/timelines/attempts match;
  SQLite integrity ok, no rejection/pruning/tcpdump-reported drops. Clean restart
  adds zero; two gzip copies duplicate. Planned kill/restart/pause recovers all
  3,120 rows. Closed-mtime-proxy/delivery p95 5.012 s; delivery/snapshot-observation
  p95 10.658 s, max 44.852 s including pause. Rotation latency is additional.
  Sampled RSS 217,874,432 bytes/state 2,564,349 bytes (1-second observations).
  Zero short-window reviews is not FPR/recall or behavior-gate validation.
- Frozen live evaluation passed before a final UI-only device-switch fix:
  multi-domain targets now reset safely and format stale widget state. Frozen
  bundle/delta receipts preserved; collector/analysis hashes unchanged. Actual
  live-snapshot EN/TR selection and **1,119 tests / 91% coverage** pass; Ruff/
  Bash/diff/source audit pass. All 34 original data files unchanged. Own test
  containers/network cleaned, no interactive guest sessions, VM restored stopped.
  Original ML artifact still missing, strict temporal insufficient, augmented
  promotion deferred. Source-only main uses `[skip render]`; verify all CI and
  unchanged user-suspended Render/previews/deploy history after publication.
- Next: independent permitted benign updater/cache/resolver controls and an
  actual analyst task study; representative multi-day recovery/load/security
  checks. Predeclare tunneling/general UDP and sparse-failure changes separately
  with new reserved evidence. No FPR/recall/RITA parity/analyst-time claim.

## Automatic DNS collection increment (2026-10-05)

- `closed-zeek-collector-v2` consumes completed TSV/gzip connection and TCP/UDP
  DNS logs from one sensor root. DNS UID identifies a connection, so separate
  transaction IDs/timestamps survive. Exact full-row copies deduplicate and
  differing source rows at the same UID/transaction/time are explicitly excluded.
  Invalid identity/path/row width/future clocks reject the entire file. The
  existing permissive upload parser and first-IP-answer analysis scope remain.
- Independent DNS snapshot/UI queue reuses `dns-device-triage-v1` with the user's
  existing cache and no ML/key/feed requests. Original connection findings,
  timelines, attempts and domain fallback outputs remain separate and preserved.
  Bilingual local/public-boundary checks, client/answer CTI isolation and reload
  without new traffic pass. DNS aliases/connection aliases are independent;
  no hostname/flow join, tunneling detector, endpoint compromise or download claim.
- Private SQLite schema 2 upgrades after an owner-only schema-1 backup, retaining
  old record hashes/checkpoints/binding. Old snapshots render; old collector
  software rejects new state. Backups retain private evidence outside active
  retention and need explicit local lifecycle management. Shared 100k record/
  event/ingestion window plus 25k DNS-name cap can prune mixed evidence; coverage
  loss disables expected filtering. DNS exports cap 1000 prioritized groups,
  UI 500, with omitted counts; its review count applies to snapshot groups.
- Inputs froze before implementation: 11/11 development and 11/11 reserved
  identifier contracts pass, including benign periodic UDP/TCP updates that
  both Review under unchanged thresholds. These are the same declared scenario
  types, not independent traffic or held-out malware accuracy. A runner restart
  clock assumption (+301 seconds becomes valid after advancing one second) and
  UI fixture clock were corrected without weakening product guards. Partial/
  failed receipts remain external; inputs were not rewritten.
- Runtime/workload hashes froze before new live recording. An experiment path
  traversal/parent-symlink safeguard was subsequently strengthened; original
  runtime/workload hashes stayed identical, original freeze retained, final
  tooling refrozen and the inspected contract set rerun explicitly. Two new
  isolated real packet captures `dns-collector-live-20261004T222024Z` and
  `dns-collector-live-20261004T222416Z` each yield 24 DNS rows on two UIDs plus
  two connection rows: UDP/TCP 12/12, NOERROR/NXDOMAIN/SERVFAIL/unanswered 8/6/6/4,
  zero invalid/rejected rows/reviews/reported kernel drops. Offline, collector,
  restart and gzip match; restart adds zero and two copies are duplicates.
  Short .test-only internal guest workload, not real benign FPR/recall/visibility.
- Validation: **1,091 project tests passed**, **90%** coverage, Ruff/Bash/diff
  checks pass. Migration/backup, checkpoint crash/restart, original connection
  regression, DNS conflicts/full-row answer differences, capacities, malformed
  snapshots, privacy, CTI scoping and bilingual/public UI are covered. One
  constructed 10k-record collector tick: all evidence retained, 1000 DNS groups
  exported/9000 omitted, 5.57 s/47.03 MB traced Python peak/716,115 JSON bytes.
  Excludes fixture allocation/total RSS; not production throughput.
- Full method, aggregate fingerprints, reproduction and limitations:
  `DNS_COLLECTION.md`. Raw logs/PCAP/cache/SQLite/evaluation receipts remain
  private external files. All 34 original local data files retain checksums.
  Model identities/thresholds unchanged; original artifact missing, strict
  temporal insufficient, augmented runtime promotion remains deferred.
- Source-only main publication uses `[skip render]`; verify all CI and unchanged
  suspended-service/previews/deployment history after publication. Next:
  representative longer mixed-log rotation/latency/backlog/resource/recovery
  tests and device DNS timelines; separately predeclare tunneling/general UDP
  and new independent benign/sparse-failure controls. Analyst efficacy is open.

## TCP attempt review increment (2026-10-05)

- Added separate `tcp-attempt-review-v1`: inclusive sliding 300-second source/
  target/port windows, 20 distinct S0/REJ failed ports or hosts, or 30 repeated
  failures with >=90% among comparable records. Equal timestamps evaluate as a
  batch; missing/conflicting/gapped source-window evidence blocks retry ratios.
  Observed diversity can remain with explicit source coverage limits. One peak
  per key/pattern, at most 500 findings, with omitted count/warning. Shared UID
  identity logic preserves original connection/timeline semantics.
- Schema-2 connection reports add an optional attempts block and collector
  status adds a separate attempt-review count. Bilingual uploaded/local collector
  queues remain visible under original/expected filters. Existing CTI/context and
  original connection/domain/device/ML verdicts are unchanged. IPs default to
  existing report-local aliases, raw UIDs/rows/source paths remain omitted; no
  private SQLite/history migration, credentials, feed fetch or public listener.
- `tcp-attempt-controls-v1` froze inputs before implementation: **32/32 development
  and 32/32 reserved constructed checks pass**, including benign inventory/outage
  review burden. An initial input-generator boundary construction correction was
  made before coding, preserving its prior private receipt. No threshold tuning.
  Candidate fingerprints then froze before new official/live traffic inspection.
- New isolated guest run `attempt-live-20261004T214016Z`: **120 real packet-derived
  records** (84 REJ, 36 SF), three scoped new patterns and zero original connection
  reviews. Zero invalid metadata/reported kernel drops. Offline/collector match,
  restart adds zero and gzip replay is one duplicate. This is synthetic plumbing
  evidence, not real-world malware detection or human efficacy.
- New official uninspected IoT-23 capture 8-1, selected by HEAD byte size before
  body acquisition: **10,403 accepted rows**, no invalid/skipped metadata, original
  groups/reviews **9/0**, new attempt patterns **0**. Trusted isolated baseline
  `b00fc836367c7ff0f408c6d1bd56d1130a7d5d59` matches original findings/timelines and
  domain verdict counts. Collector retains all rows in the declared seven-day
  proof window; restart/gzip contracts pass. Labels stay outside detector input.
- Post-evaluation coverage diagnostic: 8-1 has 8,222 S0 and two OTH TCP rows, plus
  2,179 UDP rows. Same-endpoint five-minute failure peak is 16; failed port diversity
  is one. The sparse-failure gap remains, no increased malware recall/FPR/parity
  claimed. No fresh independent benign capture. Existing experiment files are not
  rewritten/rescored as untouched evidence. Full method/attribution/aggregate
  receipts: `TCP_ATTEMPT_REVIEW.md`. Raw artifacts/state remain private/external.
- Validation: **1,042 project tests passed**, **90%** coverage, Ruff/Bash/diff checks
  passed. Coverage includes contracts, inclusive/sliding boundaries, coarse time/
  denominator order, cross-source conflicts, privacy, caps/omitted counts, malformed
  snapshot blocks, bilingual queues and actual collector/restart behavior. One
  initial test assumption about all existing domain verdicts being Low was
  corrected to compare unchanged original assessments; duplicate volume already
  creates Review in the original pipeline. No product verdict was weakened.
- One 100,000-record/1,000-source constructed attempt-analysis check retained 500
  patterns and disclosed 500 omitted, taking 2.27 seconds and 5.77 MB traced Python
  allocation peak for that phase only. Input/pipeline allocation and total RSS
  excluded; not production throughput. All 34 original local data files keep their
  checksums. Original ML artifact remains absent; fresh-disjoint is not strict
  temporal and augmented runtime promotion remains deferred.
- Source-only main integration uses `[skip render]` and suspended hosting/previews
  guard. Verify all CI and unchanged deployment history after publication. Next:
  UDP/DNS predeclared scope, new independent benign/sparse-failure recordings,
  longer live rotation/resource/latency checks and human analyst task evaluation.

## Connection investigation and live termination controls (2026-10-05)

- Added `connection-start-timeline-v1` to uploaded and collected connection views:
  report-local group selection, UTC start buckets, Zeek state counts, known byte
  sums and separate unknown-byte counts. No packet/transfer-time inference or
  detector/ML policy changes; same global UID dedup/conflict exclusion. Missing/
  ambiguous time is counted outside the chart; unrecognized states become unknown.
- Summaries are bounded to 200 detector-sorted groups (Review first) and 48
  adaptive buckets each; both views render/select at most 500 filtered groups.
  All findings remain downloadable. Schema 2 adds Group references and optional
  timelines; old snapshots remain readable. No SQLite/history/raw-row migration.
  New collector snapshots reset selection because aliases/IDs are report-local.
  Default exports still omit IPs, UIDs, source paths and declaration configuration.
- `tcp-termination-live-v1` declares 12 attempts each SF/RSTO/RSTR/S2/S3/REJ
  before capture, using pinned images and an isolated guest-only internal bridge.
  Two new real packet captures each produce **72 accepted records**, six Observe
  groups, zero invalid/skipped metadata and zero reported kernel drops. Each
  timeline retains exactly 72 starts; offline/collector outputs match, restarts
  add zero records and gzip replay is one duplicate. Scripts/protocol and aggregate
  hashes are in `CONNECTION_INVESTIGATION.md`; raw artifacts/proofs stay external.
- These short synthetic live runs validate plumbing/termination coverage only,
  not hour/30-minute detection gates, malware accuracy, RITA parity, production
  throughput or human analyst time saved. Existing frozen captures/ML metrics
  are not retuned or rescored as fresh evidence. Historical experiment runners
  still require their documented frozen source revision when fingerprints differ.
- Validation: **995 project tests passed**, **90%** coverage, Ruff passed. Checks
  cover global/bucket caps, duplicate/conflicting UID reconciliation, timezones,
  missing bytes/times, corrupted snapshot rejection, report privacy, bilingual
  uploaded/collector UI, filter selection and snapshot selection reset. Initial
  test-fixture/old UI-count assumptions were corrected; full tests run with local
  socket permission required by the existing installer suite.
- One constructed 100,000-record/200-group summary build retained all starts
  in 9,400 buckets (1.85 MB timeline JSON), taking 2.53 seconds and 11.0 MB
  traced Python allocation peak for that phase alone. This excludes input/pipeline
  memory and is not production throughput or total RSS evidence.
- All 34 pre-existing local data files retain their checksums. No API keys,
  caches, traffic logs, PCAPs, datasets or models are included in source release.
  Original ML artifact remains absent, strict-temporal evidence insufficient,
  augmented runtime promotion deferred. Source-only main integration uses
  `[skip render]`; verify all CI and suspended-service/history guard afterwards.
- Next: predeclare failure/scan and UDP/DNS controls with new reserved inputs;
  longer live rotation/resource and latency tests; actual human analyst workflow
  assessment before usefulness claims. No public deployment is authorized.

## TCP termination coverage increment (2026-10-04)

- Added `zeek-connection-context-v2`: S2/S3/RSTO/RSTR sessions with positive
  bidirectional payload/zero gaps can supply existing long/periodic review gates.
  Thresholds remain 3,600 seconds / 20 timestamps / 1,800 seconds / 0.85.
  Missing, conflicting, gapped or unconfirmed evidence cannot qualify. Reset/
  partial-close and failed/half-open counts now appear in bilingual connection
  views, collector snapshots and aliased schema-v2 reports. Confirmed sessions
  keep SF/S1 meaning; four fields are additive. Expected declarations still
  cannot hide partial/reset groups. No connection-state persistence migration.
- `tcp-termination-coverage-v1` predeclared immutable inputs before implementation:
  **32/32 development** and **32/32 separate reserved** constructed checks pass.
  Benign periodic updates and matching heartbeat both Review; these are contracts,
  not malware truth. Candidate fingerprints/control manifests froze before source
  acquisition; earlier v1 captures were not rescored or used for tuning.
- Three new official capture files (Somfy-01, malware 34-1 and 21-1) provide
  **26,561 accepted rows**, no invalid/skipped metadata and 1.38–24-hour spans.
  Same-input trusted isolated v1 baseline versus frozen v2: reviews **1/20→1/20**,
  **1/52→1/52**, **0/51→0/51**; domain/IP verdicts unchanged. A benign Somfy flow
  is reviewed; no false-positive reduction or increased malware recall claimed.
- Post-evaluation coverage diagnostic: 34-1 has 1,642 eligible payload sessions
  versus five original confirmed sessions, exposing 1,584 partial closes and
  53 reset endings. This adds 1,637 sessions of observed evidence, not new Review
  groups. 21-1 has zero eligible payload; its 14 malicious-labeled flows include
  ten S0, one REJ, and one each SF/S2/S1. Eleven failed/half-open attempts and one
  incomplete close are visible; the detection gap remains explicitly documented.
  Full protocol, fingerprints and limitations: `TCP_TERMINATION.md`.
- Validation: **973 project tests passed**, **90%** coverage, Ruff passed.
  New checks cover termination states, missing/capture-gap evidence, unconfirmed
  state exclusion, expected-context safety, private reports, bilingual rendering
  and actual collector snapshot integration. One new Turkish column-label issue
  was fixed before final verification. Inputs/reports/state remain external.
- ML model/threshold policy and strict-temporal promotion stay unchanged. Source
  integration into main uses `[skip render]` with user-suspended hosting/previews
  guard; CI and deployment history must be verified after publication.
- Next: representative real reset/close workloads and analyst workload; separately
  predeclared failure/scan and UDP/DNS coverage with new untouched inputs. Do not
  tune on these now-inspected captures or claim field efficacy from contract tests.

## Independent coverage and automatic collector (2026-10-04)

- Completed `iot23-connection-coverage-v1`: four predeclared small official
  real-device connection logs, immutable pre-acquisition plan/hash and source
  receipts, frozen detector commit `0a3e17c1f4724f2f3d75966b08125ee5e26c8c1d`.
  Source spans are 1.91–23.98 hours, not new live collection. All 5,272 rows parse
  without invalid/skipped records. Labels removed before analysis; CTI/ML/rules
  disabled, no threshold changes or native RITA comparison. Attribution/license
  references and source fingerprints are in `NETWORK_EVALUATION.md`; inputs,
  label-free logs/reports and proof state remain outside the repository.
- Connection reviews: benign 0/16 and 0/176; malicious capture 1/10 (long session)
  and 0/41 (no confirmed qualifying sessions). The latter exposes partial-session
  coverage limits. Separate benign domain/IP fallback output has two Review
  verdicts; do not claim zero overall false positives, malware recall or parity.
  These inspected v1 inputs cannot serve as untouched evaluation for tuning.
- Added `closed-zeek-collector-v1`: Linux foreground reader for completed TSV
  connection logs/gzip, owner-only state and lock, transactional typed evidence/
  checkpoints, content and semantic dedup, retained-window UID conflicts, finite
  event/ingestion retention, file/scan/ledger limits and rotating scan cursor.
  Reports regenerate after interrupted writes/restart. Capacity drops are explicit
  and disable expected declarations for one ingestion window. Rules and the user's
  existing CTI reload each tick; no credential use, feed fetch or ML on this path.
- Installed `threatfusion-ai collect`, package `threatfusion-collect`, and local
  English/Turkish Collected connections view with ten-second refresh, stale/error/
  empty-CTI/coverage warnings and reversible expected filtering. Exports keep all
  groups with endpoint aliases and omit raw UIDs/source paths/declaration IDs.
  Managed real CTI loopback mode can read its state; demo/hosted public profiles
  cannot expose it. `TELEMETRY_COLLECTOR.md` documents rotation latency and separate
  collector/web lifetime. No public site or hidden background service created.
- Four isolated official-source collector imports matched offline counts/groups/
  reviews; restarts added zero records and each gzip copy was one duplicate.
  Initial scans 0.25–0.44 seconds, private state 0.17–1.67 MB locally; these are
  small single-run measurements, not throughput/peak-memory guarantees.
- Validation: **959 project tests passed**, **90%** total coverage, Ruff passed.
  Coverage includes real-process SIGTERM/restart, interruption after commit,
  conflict/retention/capacity, corrupt/oversized gzip, symlink/FIFO/locks, fair
  scanning and actual managed/public app rendering. Clean Linux installer CI
  additionally exercises the installed collect launcher and repeat ingestion.
  The same black-box flow passed locally in disposable Debian 12 and Ubuntu
  24.04 containers without preinstalled Python/Git, preserving synthetic model
  and fixture CTI checksums. Source-path release auditing rejects private
  collector/analyst JSON directories in addition to caches/models/evaluation.
- ML artifacts/thresholds and strict-temporal promotion gate remain untouched.
  Render was verified user-suspended with previews disabled before source
  publication; integration uses `[skip render]`. Recheck suspension/history and
  all CI jobs after publishing source; never resume hosting.
- Next: predeclare partial/reset/retry/jitter/idle development controls and new
  reserved evaluation windows; actual analyst workflow review; longer live
  rotation/resource tests and active-tail latency decision. A genuine analyst
  time-saved claim requires a human workload measurement.

## Expected connection context increment (2026-10-04)

- Added optional `expected-connection-context-v1` after detection. Exact observed
  originator/responder/TCP port, <= 30-day aware validity and whole-upload group
  count/duration/byte ceilings are mandatory. Wildcards, networks, extra/duplicate
  fields, ambiguous timestamps and oversized files are rejected (64 KiB/128 rules).
  Expired/future/out-of-window, incomplete, conflicting or excessive sessions
  cannot qualify. Missing originator port is now explicit endpoint coverage loss.
- Existing client/destination CTI response-IP/network matches override declarations,
  regardless of port. Conflicts remain visible even for Observe-priority groups.
  No new originator CTI lookup or shared-IP domain attribution was introduced.
  Original findings/priorities, domain/device verdicts and ML thresholds/artifacts
  remain unchanged; context never proves software identity or safety.
- Local Connection activity accepts session-only declaration JSON and reversibly
  separates declared expected activity. Public mode never offers the uploader.
  `--expected-connections` requires Zeek-conn input and the explicit separate
  report. Invalid CLI files abort before export without echoing private content;
  invalid UI files apply no declarations. Rules are not written to history.
- Connection export schema is now v2, adding context/evaluation time/count. All
  groups and original priorities/evidence remain present. IPs default to aliases;
  declaration IDs/configuration remain omitted even with explicit IP inclusion.
  Private local declaration paths/patterns are ignored. `EXPECTED_CONNECTIONS.md`
  documents usage, limits, schema migration and analyst responsibilities.
- New immutable `expected-connection-controls-v1`: **11/11** predeclared constructed
  cases passed, covering benign updates/streams, expiry, device/port/volume
  deviations, capture gaps, unknown heartbeat and synthetic CTI conflict. An
  identical heartbeat on the declared endpoint also matches, explicitly recording
  a software-identity limitation. This is contract evidence, not measured FPR,
  recall, improved detection or analyst time saved. Intent labels are not inputs
  to the product's detector/context matcher. Logs/configs/reports remain external.
- Validation: **943 project tests passed**, **90%** total coverage; Ruff/diff checks
  passed. Tests exercise exact/network CTI, unchanged aggregate evidence, privacy,
  expiry/bounds, CLI and bilingual local/public filtering. Original periodic
  comparison and shared input hashes are rechecked without rewriting outputs.
- Next: longer independent permitted capture and actual analyst workflow workload
  validation, followed by restart/rotation-safe continuous collection. No ML
  holdout was rescored or promoted. All hosting remains user-suspended.

## Cached workload and connection review increment (2026-10-04)

- Added typed standard-TSV Zeek connection evidence: UID, endpoints/ports,
  observation direction, duration, payload bytes, state and missed bytes. Missing
  or invalid optional fields remain unknown and are diagnosed. Labels in supplied
  datasets are ignored. Metadata does not imply URLs, downloads or execution.
- `zeek-connection-context-v1` groups originator/responder/protocol/target-port;
  duplicate UIDs count once and conflicting UIDs are excluded across groups.
  Long-session Review requires a known originator/target port, nonconflicting
  UID, TCP SF/S1 state, positive bytes in both directions, zero missed bytes and
  at least 3,600 seconds of duration. Sustained-timing Review additionally
  requires complete metadata, 20 distinct aware timestamps over 1,800 seconds
  and regularity score >= 0.85. These engineering rules are not calibrated C2
  detectors. DNS/device/domain threat verdicts and frozen ML policy are unchanged.
- New bilingual Connection activity tab and `--format zeek-conn`,
  `--connection-json-output` CLI export. Both endpoints default to report-local
  aliases; explicit `--include-connection-ips` affects only that separate report.
  Exports refuse existing files and use owner-only POSIX permissions. Public-mode
  rendering has no address toggle. Raw rows/UIDs are not persisted in history.
- `cached-http-controls-v1`: 60-second live internal guest-network capture with
  DNS TTL caching, persistent browser TCP, variable response sizes, matching MIME
  extensions and polling jitter. Three validated captures each had five DNS queries,
  78 HTTP 200 requests and 61 TCP sessions (browser 1, updater 30, heartbeat 30),
  zero kernel drops and zero invalid connection fields. Queue reviews were zero
  because the observation span is intentionally short; this is not zero FPR or
  successful detection of the simulated heartbeat. It is not production traffic.
- Same immutable first capture imported into native pinned RITA with unchanged
  scoring/disabled feeds: updater and heartbeat both High / beacon 1, no browser
  row and no modifiers. Short-window queue differences are not tool superiority.
  Original `periodic-controls-v1` inputs and stored domain/RITA report remain
  identical. RITA backend returns to its previously stopped state; VM stays up.
- `connection-workload-controls-v1` predeclares 11 constructed Zeek-record cases
  at three fixed seeds. There were nine Review groups among 33 benign groups
  (updates, jittered polling and long streams) and three among three heartbeat
  simulations. These counts measure review workload, not FPR/recall or real
  traffic efficacy. No threshold selection or model/holdout scoring occurred.
- Validation: **904 project tests passed**, **90%** coverage, Ruff and Bash syntax
  passed; auto-detection, typed fields, incomplete/invalid metadata, UID handling,
  CLI file privacy and complete bilingual/local/public UI rendering were exercised.
  Inputs/PCAPs/logs/native CSVs/reports/synthetic cache remain outside the repository.
- Next gate: longer independent permitted captures, robust timing/size evidence,
  and explicit expected-software/analyst context to manage benign review burden.
  Keep strict-temporal ML promotion deferred and all hosting user-suspended.

## Client-level triage increment (2026-10-04)

- User direction: aim for competitive core network-analysis coverage, with a
  specific measured advantage in explainable DNS/CTI triage. Keep the local web
  workspace and CLI. `DETECTION_ROADMAP.md` records capability gaps and evidence
  gates; RITA remains an external comparator, not a mandatory dependency.
- Runtime now includes independent client/target assessments and scoped match
  evidence. It reuses one ML inference and the selected artifact's thresholds;
  no model changes, holdout scoring or runtime promotion occurred. Domain-wide
  assessments, aggregate exports and persisted history are unchanged.
- `dns-device-triage-v1`: sustained periodic DNS enters the Review queue only
  with a valid client, complete aware timestamps, 20 distinct timestamps and
  at least 1,800 seconds of span. The existing periodicity rule is retained.
  These engineering coverage gates are not malware detection thresholds.
  Benign updater and matching heartbeat both get review work, not malware proof.
  Unknown identities and IP-only connection targets cannot get this DNS reason.
- Added bilingual Device triage tab with aliases by default; optional IP
  display/export is local-only. Separate CLI `--device-json-output` uses aliases
  unless `--include-client-ips` is explicit, writes new owner-only POSIX files
  and refuses overwrite. Domains/times are still sensitive telemetry. No device
  queue persistence, third-party redistribution or public hosting is added.
- Immutable external `dns-device-controls-v1` checks passed **24/24** at two
  fixed seeds: periodic/jittered benign controls, identical heartbeat simulation,
  sparse/short/duplicate/missing records, client pooling and scoped synthetic
  CTI. This is policy-contract evidence, not real-world FPR/recall evaluation.
- Frozen `periodic-controls-v1` inputs and original domain/RITA JSON report
  recheck identically. CLI accepted all 816 frozen replay DNS records and
  produced two device reviews plus three observations; original five Low domain
  verdicts persist. Local 100,000-event / 10,000-pair CTI/behavior workload took
  0.87 seconds on this host; this is not a production throughput claim.
- New reports, inputs and synthetic cache stay in the sibling local lab.
  Validation: **877 project tests passed**, including 21 new client-triage and
  control-protocol tests; Ruff and diff checks passed. Whole-dashboard rendering,
  local/public IP visibility, private CLI export and frozen baseline preservation
  were exercised. Socket tests require normal local socket permissions.
  Tracked-tree/reachable-history privacy audit found no findings; pip-audit
  reported no known dependency vulnerabilities. No runtime credential was used.
  Next increment: realistic benign collection/independent windows, then preserve
  connection metadata for long-session/beacon analysis. Existing `conn.log`
  destination-IP ingestion does not provide that detector yet. Stronger untouched
  strict-temporal ML evidence is still required before promotion.

## Local network lab — periodic controls and RITA comparison (2026-10-04)

- Implemented/froze `periodic-controls-v1`: three concurrent synthetic clients,
  irregular web traffic, benign periodic updater and suspicious heartbeat
  simulation. Both periodic roles have identical timing; labels stay out of
  detector inputs. Live capture: 18/30/30 requests, 78 DNS and 78 HTTP exchanges.
- Added deterministic 24-hour **synthetic PCAP replay**, 240/288/288 requests;
  Zeek checksum verification remained enabled, and 816 DNS plus 816 HTTP records
  matched the prewritten manifest. This is not 24 hours of real collection,
  production validation or new temporal ML evidence.
- RITA v5.1.2 / ClickHouse 24.1.6 run only inside the local guest with pinned
  image identities, internal analysis networking, no published ports, no
  autostart/restart policy and no feed credentials. Official release assets
  are SHA-256 verified and remain local. Scoring/modifiers are unchanged; only
  feeds/update checks and the internal-lab subnet mapping differ.
- Both tools receive the same frozen Zeek records. CTI/ML are off; RITA consumes
  DNS/HTTP/connection metadata, ThreatFusion's current verdict uses DNS only.
  ThreatFusion keeps both periodic controls Low with periodic context. RITA
  marks both Critical / beacon 1.0; synthetic MIME/user-agent modifiers also
  produce browser findings. This limited observation establishes no accuracy
  or superiority claim. Preserve v1 inputs and scores without retuning.
- Public additions: scenario generator/live runner, isolated RITA wrapper and
  preparer, hashed native-output reporter, tests and updated lab runbook.
  Runtime models/caches, third-party downloads and all evaluation/traffic files
  remain outside the repo. VM stays running for the user's active SSH session.
- Validation: 856 project tests passed (including six new protocol/boundary
  regressions); Ruff, Bash syntax and tracked-tree/history privacy audit passed.
  The user-facing `lab scenario` was black-box tested on a new live capture.
  Native RITA import/CSV export succeeded for both live and replay datasets.
- Next gate: realistic benign controls and independent permitted recordings;
  continuous collection, tunneling, long connections, device triage and real
  deployment performance are not validated. Frozen ML work is unchanged.

## Local network lab — first capture gate (2026-10-04)

- Created a separate Ubuntu 24.04 QEMU/KVM user-session VM with four vCPUs,
  16 GiB RAM, a sparse 250 GiB disk and localhost-only SSH management. Existing
  Kali VM/networks are preserved; VM images, keys and telemetry remain outside
  the repository. Docker and Compose are installed inside the guest.
- Added reusable synthetic DNS/HTTP smoke sources in `scripts/lab/` and the
  operational runbook in `docs/LOCAL_LAB.md`. Dedicated guest bridge capture,
  internal Docker network, immutable image digests, offline unprivileged Zeek
  analysis and cleanup were exercised. Fixed the image's offline plugin path
  and output-ownership issues before recording passing results.
- Three synthetic clients produced three DNS exchanges and three HTTP 200
  responses; the real ThreatFusion Zeek reader accepted all three DNS events
  with the correct fields. Related regression: 29 passed. This is capture and
  ingestion evidence only, not detection efficacy or production-readiness.
- Full regression: 850 passed with normal local socket permissions; Ruff,
  Bash syntax and tracked-tree/history privacy audit passed. VM graceful
  shutdown/restart and localhost SSH were verified; the VM is left shut down
  with autostart disabled to release host RAM.
- RITA installation/comparison and labeled behavior scenarios are the next
  gate. ML artifacts, thresholds, holdouts and runtime promotion are unchanged.
  No real CTI keys/data or private host traffic were used in the lab.

## Current user instructions — local development only

This policy supersedes the earlier hosted-demo/release plan below. Continue
development and security checks locally. Do not create or resume a public site,
tunnel or hosted preview unless the user explicitly asks. Completed and verified
code/configuration/documentation may still be published to GitHub, keeping all
private/third-party data local and ignored. See the root `AGENTS.md`.

A new read-only Render check for the user's explicit `main` integration request
confirmed `threatfusion-ai-demo` is **user-suspended**, with service previews
disabled; no other services/previews exist in the confirmed workspace. The
latest deployment record still refers to `8966620` and is not evidence that the
suspended service is running. Auto-Deploy still reports `yes` / `checksPass`;
Blueprint Auto Sync is not verified. Neither setting is claimed to be disabled.

The source integration uses `[skip render]`, adds no Blueprint resources and
retains the manual-deploy/preview-disabled Blueprint. Suspension and deployment
history are rechecked after merge/CI. Do not resume hosting; the merge request
authorizes source integration only. See `AGENTS.md` and Render's documented
[auto-deploy skip phrase](https://render.com/docs/deploys#skipping-an-auto-deploy).

The retained Blueprint now requests manual deployment and disables previews;
GitHub CI also runs on `local-development/` branches. YAML/schema/lint/privacy
checks validate this configuration change. These file changes alone do not
close an existing public service or turn off dashboard Auto Sync.

## Main integration (2026-10-04)

- The user requested including the verified `local-development/linux-first-run`
  work in `main`. Preserve its commits and all private/ignored local data.
- Both README download commands and `scripts/install_linux.sh` now select
  `main`; each install still resolves one immutable source SHA before download.
- Source work had 818 local tests and all six CI jobs passing before integration.
  Integration uses a `[skip render]` commit and a confirmed user-suspended
  service, with no preview creation or service resume. Verify main CI and the
  exact main download command before reporting completion.

## Linux first-run delivery (2026-10-04)

- `scripts/install_linux.sh` is the normal-user, one-command entry point. It
  installs pinned uv 0.12.23, private Python 3.12.14 and 49 hashed binary-wheel
  dependencies from `requirements-linux.lock`; Python/Git/sudo are not needed.
- Immutable source downloads and private environment identities are managed by
  `scripts/bootstrap_linux.py`. The saved `start` launcher supports offline
  restart; setup refuses unrecognized directories and preserves existing data.
- First launch is a clearly synthetic demo. Explicit `--mode cti-only
  --refresh-cti` collects separate real CTI; keys are not saved or passed to the
  Streamlit child, refresh output omits upstream URL/error details, and ML stays
  disabled. No experimental artifact is selected or promoted.
- `scripts/start_local.py` / `local_setup.py` bind only 127.0.0.1, open a browser
  after health readiness, choose a free port and supervise shutdown. Shared
  persistent analyst history is disabled in this first-run profile. The UI calls
  this a session-only workspace, avoiding a misleading public-hosting label.
- Fresh Debian 12 and Ubuntu 24.04 containers, running as a normal user with no
  Python/Git, passed full installation and repeat installation. Black-box checks
  exercised actual Streamlit WebSocket UI rendering in demo and CTI-only modes,
  loopback binding, occupied-port handling, duplicate-launch exclusion, both
  Ctrl+C/SIGTERM shutdown and preserved synthetic/CTI fixture data. A path with
  spaces was covered. No real feed credentials or developer data entered tests.
- Local regression: **805 passed**, **90%** coverage; Ruff and ShellCheck passed,
  and pip-audit found no known dependency vulnerabilities.
- Published implementation `633323be61cde41edb296f827471489bea1203b4` passed all
  six [GitHub CI jobs](https://github.com/ConquestorYa/threatfusion-ai/actions/runs/37164159694),
  including Windows and both clean Linux installations. The exact README
  copy-paste command also passed in a third clean Ubuntu environment with no
  mounted checkout: immutable GitHub source retrieval, real foreground UI,
  Ctrl+C shutdown and temporary-file cleanup were verified.
- CI adds the same two clean-install jobs alongside Ubuntu quality, Windows
  pytest and both existing Docker jobs. Ruff, Bash syntax, ShellCheck,
  dependency auditing and tracked-tree/history privacy auditing are part of the
  verification. Original 32 local data files retain their recorded checksums.
- See `INSTALL_LINUX.md` and both READMEs for the copy-paste command, supported
  baseline, optional credentials, restart and recovery. The work was initially
  published on `local-development/linux-first-run`; the user now requested its
  guarded integration into `main`.
- This flow does not change the fresh-disjoint metrics, five unscored eligible
  temporal samples, missing original runtime artifact or deferred promotion.

## Credential privacy follow-up (2026-10-04)

- Rechecked the first-run flow: credentials come exclusively from the caller's
  environment; no developer/shared fallback exists. Missing ThreatFox/URLhaus
  keys skip those collectors. Demo needs no key or upstream CTI collection.
- Closed a legacy refresh diagnostic exposure: raw collector exceptions could
  reach progress callbacks, returned outcome details and CLI logs. Failures now
  use fixed safe messages while preserving the actionable SGB page-bound hint;
  neither authenticated URLs nor private payload text is forwarded.
- Ignored `.env`/Streamlit secrets/private-key files are also rejected by path
  in the tracked-tree and Git-history release audit, including short keys and
  binary containers not covered by recognizable token patterns.
- Regression tests cover callback/result/CLI redaction, absent-key collector
  exclusion, secret-file paths and removed secrets retained in history. No live
  keys are used in tests. The credential/privacy follow-up does not complete
  the broader local security review or authorize public hosting.
- Follow-up validation: **818 local tests passed**, **90%** coverage; Ruff and
  tracked-tree/history secret audit passed. All 32 recorded original local data
  files retain their checksums. No known secret-file/token finding was detected.

## Current position

- The earlier character-only C=4 model has a completed historical post-freeze
  holdout. Its metrics are documented in `ML_DATASET.md` and
  `RELEASE_NOTES_v0.1.0.md`.
- The improved candidate is an augmented
  `lr_char_2_6_plus_lexical_c4` artifact trained with a separate CESNET
  hard-negative development window.
- Its fresh-disjoint evaluation completed with High/medium/low recall of
  60.62%/78.75%/81.87% and FPR of 0.85%/1.95%/2.62%.
- It is not the runtime default because fresh-disjoint evidence is not strict
  first-seen temporal evidence.
- Runtime promotion is deferred until stronger untouched post-freeze temporal
  evidence is available. The augmented artifact stays an experimental candidate.
- The default configuration still points to `data/models/development-001`, but
  that original artifact is **absent in this checkout**. The available synthetic
  demo runtime has a separate `development-001` directory and
  `demo_only_synthetic` status; it is not the original measured artifact.
- Explicit CTI-only operation is now available when the original artifact is
  unavailable. It does not change the default or promote either candidate.

## Completed in this checkout

- Documentation was synchronized across the README files, architecture,
  project context, decision log, deployment guide, release notes, checklist,
  and changelog.
- The synthetic public-mode demo starts successfully and its Streamlit health
  endpoint returns `ok`.
- A sanitized local deployment bundle was generated at
  `data/deployment/runtime/`. It contains only the synthetic CTI cache and
  demo model artifact; analysis history and evaluation reports are absent.
- The Docker image was built successfully and the sanitized runtime passed the
  public-mode Streamlit health check. The test used a refreshed `docker`
  group shell; the temporary container has since been removed.
- A forced CTI refresh without credentials successfully refreshed SGB with
  488,361 active records, ThreatFox with 110,075 active records, and URLhaus
  with 16,072 active records. PhishTank was rejected by its access/security
  redirect and its previous cache was preserved.
- The indexed URLhaus lookup audit covered 1,000 active URL records with 100%
  exact and hostname-index coverage. No IOC destination was opened or
  resolved.
- A reconstructed development-only snapshot was generated at
  `data/snapshots/reconstructed-development/` from the refreshed local CTI
  cache and Tranco `L5PV4` (50,000 rows). It contains 523,114 final samples.
- A corresponding development-only lexical C=4 artifact was generated at
  `data/models/reconstructed-development-lexical-c4/`. Its thresholds are
  validation-selected at FPR budgets of 0.1%, 0.5% and 1.0%. This artifact is
  not the previously documented frozen candidate and has no final holdout
  claim.
- A new CESNET benign window was streamed into
  `data/evaluation/cesnet-benign-lexical-final-20k.csv`: 20,000 unique domains
  after an 80,000-domain offset, with SHA-256
  `6ffc45cca5e089ad648f54e2d05f5d42bf4fc2bd6514ff2aa8e484af497da287`.
- The reconstructed artifact identity is
  `8b207dc363edde3544a8dcd447b80968c433b1d2b929616d492d40d5204ef356`,
  frozen at approximately `2026-10-02T21:55:51Z`.
- The reconstructed artifact was evaluated once on the post-freeze holdout.
  High/medium/low operating points measured 69.68%/82.58%/86.45% recall with
  14.09%/25.60%/33.99% FPR. It was not promoted because the false-positive
  rates are operationally unusable.
- A follow-up bounded feature comparison on the development snapshot did not
  justify promotion. Lexical C=4 was the more conservative candidate at the
  0.5% and 1.0% development FPR budgets, but the comparison remains
  development-only and requires a new untouched holdout for any future
  selection.
- The next final-holdout build was attempted with the augmented artifact and
  a post-freeze CTI refresh, but no malicious domain had a usable
  `first_seen` strictly after the new artifact cutoff. The evaluator correctly
  refused to create an empty temporal holdout. A later collection with new
  eligible IOC timing, or a separately documented fresh-disjoint non-temporal
  protocol, is required before promotion.
- A separately documented fresh-disjoint evaluation was completed for the
  augmented artifact after removing all development-domain overlap. It measured
  High/medium/low recall of 60.62%/78.75%/81.87% at FPRs of
  0.85%/1.95%/2.62%. This is a meaningful improvement over the earlier
  reconstructed temporal result, but it is not strict temporal evidence and
  the artifact remains unpromoted.
- The fresh-disjoint builder is implemented at
  `scripts/build_ml_fresh_disjoint_holdout.py`; it preserves the temporal
  builder’s stricter behavior and labels the alternative protocol explicitly.
- The initial verification passed all 709 pre-existing tests.

## Continuation audit — 2026-10-04

- GitHub's three context documents matched the local pre-edit versions. The
  initial worktree had only the user's untracked `komutlar.txt`; it was preserved.
- The augmented artifact checksum is
  `643b5adc1cf4bc4cb9c677df88aa4797dcbd6ae1be8ff0d0c0f4ee7d7f3e4cd9`.
  Its bytes match the recorded collection identity, and all three frozen
  thresholds match the existing aggregate report. No holdout rescoring or
  threshold tuning was performed.
- A read-only audit against the recorded `2026-10-03T20:41:49Z` cutoff retained
  **zero** strict-temporal malicious domains: all 473,323 unique candidates had
  usable earliest timing at or before the cutoff. The required sources were
  refreshed at `2026-10-03T21:20:55.415866Z`. No feed refresh was performed in
  this continuation.
- The existing fresh-disjoint snapshot is a legacy pre-filter collection:
  the evaluator removed 473,163 development overlaps, leaving 160 malicious
  and 19,936 benign domains. Its report remains unchanged. New builder outputs
  remove both classes' development overlap **before persistence**, require both
  retained classes, and use the canonical `fresh_collection_disjoint` identifier.
- New schema-v4 aggregate reports carry the evaluated artifact SHA-256.
  Evaluation checks recorded artifact/development provenance and refuses to
  drop or alter a temporal snapshot's recorded cutoff. Synthetic demo artifacts
  are refused as final ML evidence. Schema-v1/v2/v3 reports remain readable.
- The evaluation page describes the actual first-seen protocol, cutoff and
  removal counts, distinguishes legacy reports without artifact identity, and
  explains that loading a report does not promote its candidate.
- SQLite sidecars are ignored. The release audit checks local data/model paths
  in the tracked tree and history even when file contents are binary.
- CTI caches, datasets, models and existing evaluation files remain local and
  ignored. Neither Git LFS nor publishing these files is part of this release.

The augmented High tier still has 0.85% measured FPR against a 0.1% validation
budget, and source coverage is uneven: SGB contributes 138 malicious domains
with 69.57% High recall; URLhaus contributes 22 with 4.55%; ThreatFox contributes
none after overlap removal. These inspected aggregates strengthen the decision
to defer promotion; they are not new tuning data. See DEC-082.

## Validation after continuation

- Full pytest suite with coverage: **742 passed**, **88%** total coverage.
- Ruff and `git diff --check`: passed.
- Public-release tracked-tree and full reachable-history audit: zero findings;
  newly added task files were also scanned explicitly before any staging.
- Historical artifact path aliases are checked even if a binary blob also
  appeared under a permitted path and the artifact was later removed.
- Isolated synthetic runtime: Streamlit localhost health returned `200 / ok`;
  the application loaded its checksum-verified demo model without UI errors,
  and public mode hid shared history. The temporary server was stopped.
- Checksums verified all 32 existing local data files unchanged at the end of
  that audit. The initial untracked note was not modified by the agent; it was
  no longer present when the subsequently authorized implementation started.
  No commit, push, hosted deployment or release tag was created in that audit.

## Authorized release implementation — 2026-10-04

- A local backup search did not find the trusted original runtime artifact.
  The CTI-only dashboard and CLI paths skip model loading/scoring, preserve
  exact CTI and behavior evidence, and label exports without fabricated ML
  values. Model-dependent history is disabled in this mode (DEC-083).
- `Dockerfile.public-demo` generates only synthetic assets, keeps code/model
  and the independent checksum pin read-only, and supervises loopback Streamlit
  behind Nginx. Request, WebSocket connection and upload limits are applied;
  access logs and request buffering are disabled (DEC-084).
- The Docker context is an allowlist of application/configuration files. Private
  CTI, datasets, model binaries, telemetry, secrets, tests and Git metadata do
  not enter either image. No live-feed credentials are needed for the demo.
- `render.yaml` targets the free Frankfurt plan, Docker runtime and health
  endpoint. Official Render JSON Schema validation passed. A dedicated CI job
  builds the synthetic image and checks proxy limits and a real Streamlit session.
- Full verification: **763 tests passed**, **90%** coverage; Ruff and
  tracked-tree/reachable-history release auditing passed. The standard and demo
  Docker images both built successfully. Local proxy checks verified HTTP 200,
  security headers, oversized-body HTTP 413 and burst HTTP 429; health remained
  HTTP 200. A real WebSocket session rendered the UI without exceptions.
- A separate ignored CTI cache copy was refreshed: SGB retained 488,504 active
  records and five development-disjoint post-cutoff domains. All five come from
  SGB and remain unscored. ThreatFox/URLhaus retained the earlier post-cutoff
  cache snapshots because new keyed credentials were unavailable; PhishTank
  refresh failed at its access/security redirect and preserved previous data.
  The original cache and all 32 existing local data files retained their
  checksums. No inspected holdout was rescored and no threshold was tuned.
- Hosted deployment is still pending: the Render connection requires user
  workspace confirmation, its service-creation tool cannot configure the custom
  Dockerfile, and this session has no controllable browser. The ready Blueprint
  can be applied from the Render dashboard after publication to `main`.
- The final `v0.1.0` tag/release remains gated on actual hosted HTTPS and ingress
  verification; local Docker success is not claimed as a hosted deployment.
- Source implementation was published to GitHub `main` as
  `dc03e368308e91c14b74ff389b269c594e926f9d`. Its reachable-history audit passed
  again after publication. CI run `37159279681` verifies this implementation;
  deployment assets still contain no private data.
- That CI run completed successfully: Ubuntu Ruff/pytest/coverage/pip-audit,
  Windows pytest, standard Docker build/health, and synthetic-demo privacy,
  proxy limits and real WebSocket-session checks all passed.
- The three existing portfolio screenshots were reviewed visually: they use
  inert `.example` synthetic findings and show no private telemetry or secrets.
  PNG metadata and EXIF were empty. This historical review is superseded by
  the current interface captures recorded below.

## Remaining release gates

1. Collect stronger untouched post-freeze temporal evidence before reconsidering
   augmented runtime promotion. This is a future ML gate; v0.1.0 can retain the
   documented auxiliary/default policy without promoting the candidate.
2. Complete local security review and fix confirmed issues.
3. Revisit final release timing after those checks. Public hosting requires a
   new explicit user request and is not an active development task.

## Current blockers

- The follow-up collection has only five unscored post-freeze malicious domains,
  all SGB, after the initial zero-eligible result. This is insufficient stronger
  temporal evidence. The available augmented performance report remains
  fresh-disjoint, not strict temporal; promotion stays deferred.
- The original configured runtime artifact is absent locally. Use the synthetic
  demo generator for presentation, or restore the trusted original artifact from
  its private/local source. Retraining produces a new identity and requires new
  evaluation; it cannot restore the historical model claim.
- CTI-only operation is available now without that model. For full historical
  ML operation, restore the trusted backup privately if one exists elsewhere.
- Keep the Render demo user-suspended. Auto-Deploy still reports enabled and
  Blueprint Auto Sync is not verified; disable them when dashboard access is
  available. The guarded, explicitly requested source integration above does
  not authorize resuming the service or bypassing its deployment safeguards.
- The normal pre-existing terminal may still lack the refreshed `docker` group
  membership. Open a new terminal or run `newgrp docker` before using Docker.

Do not create final ML metrics from the synthetic demo artifact or substitute
an older holdout for the lexical candidate.

## Current interface screenshots (2026-10-04)

- Replaced Quick Lookup, telemetry overview and domain investigation PNGs used
  by both README languages with actual current Streamlit UI captures.
- Captured with isolated Chromium on 127.0.0.1, English/Mid theme and a separate
  temporary synthetic-only runtime. The input contains 24 events across five
  reserved example domains; no upstream feeds, private data or API keys used.
- Browser verification exercised lookup, CSV upload, analysis and investigation.
  Screenshots were reviewed visually and checked for empty PNG/EXIF metadata.
  The 48 targeted UI/theme/release-audit tests passed; all 32 previously recorded
  local data files retain their original checksums.
  Source model policy, private artifacts and runtime promotion are unchanged.
- Source-only main update uses [skip render]; the Render service was confirmed
  user-suspended with previews disabled before publication. No public site
  deployment is authorized.

## Managed Linux daily-use follow-up (2026-10-04)

- Default fresh installation now opens real CTI-only operation; the empty cache
  directs users to local setup. Demo remains explicit and isolated. Existing
  installations preserve their previous mode and data when upgraded.
- Installer registers `~/.local/bin/threatfusion-ai` and an XDG applications-menu
  entry, preserving unrelated commands/entries and shell content. Optional
  `--no-integrations` omits desktop/command/PATH changes. A new terminal picks
  up required PATH registration; the full saved launcher always works.
- Local-only panel supports masked own-key entry, session use by default,
  explicitly optional 0600 plaintext credential storage in a 0700 root, forgetting
  keys, manual refresh and opt-in 6/12/24-hour refresh. No developer environment
  key fallback is used by the managed collector. Hosted/developer profiles lack
  these controls unless the managed loopback launcher explicitly enables them.
- Scheduler runs only while the app runs and performs due startup catch-up.
  Saved keys/public sources are used; unsaved browser-session keys remain local
  to manual refresh. Failed attempts are throttled, PhishTank retains its minimum
  24-hour cadence, and a process lock serializes manual/CLI/automatic collection.
- `threatfusion-ai status/refresh/stop`, a web stop button and Ctrl+C/SIGTERM/SIGHUP
  supervise lifecycle. An owner-only Unix socket avoids stale-PID process kills.
  Browser-tab closure leaves the supervised app running; no system/login service
  or hidden background updater is installed.
- Full local validation: **850 passed**, **90% coverage**, Ruff/Bash syntax/diff
  checks and tracked-tree/reachable-history privacy auditing passed. Clean Debian
  12/Ubuntu 24.04 installs without Python/Git passed repeat install, actual
  WebSocket UI, registered shortcut/command, loopback binding, duplicate exclusion,
  offline restart, control status/stop and fixture-data preservation. XDG desktop
  entry validation passed. Real isolated Chromium verified password clearing,
  explicit save/forget and web shutdown; a real bootstrap SIGHUP check verified
  terminal-close cleanup without an orphan server/socket. Bootstrap imports use only the standard
  library; collector dependencies load only inside the runtime interpreter.
- Original **34** local data files recorded at this follow-up retained all
  checksums. Tests use only reserved fixture domains and fake keys. Real upstream
  availability and key validity are not guaranteed by mock/browser checks.
- README/installation guide now explain key requirements, storage, scheduling,
  reopen/stop and the unchanged trusted-model limitation. ML snapshots, temporal
  evidence, thresholds and promotion policy are untouched. No public deployment
  is authorized; main publication uses [skip render] after suspension verification.
