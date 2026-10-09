# TCP attempt review: scope, workflow and evidence

Status: 2026-10-05 (Turkey). Live capture filename uses UTC 2026-10-04.

## What the analyst sees

**TCP attempt reviews** appears in the uploaded connection view and the local
collector view. It explains observed failure diversity/concentration by source,
endpoint, UTC window, S0/REJ counts and fraction of comparable records.
Port/host diversity can reveal scan-like behavior; repeated failures can reveal
an outage or blocked service. These patterns require investigation and do not
verify scanning intent, software identity or compromise.

The original connection queue still handles long sessions and periodic payload.
Its reviews-only/expected-activity filters do not hide this additional queue.
To inspect individual endpoints behind a multi-port/multi-host pattern, disable
**Show only connection reviews**, then use the original group table/timeline.
Endpoint IPs remain a local explicit opt-in. Collector snapshots remain aliased.
The collector's separate **Attempt review patterns** metric counts retained
patterns; the existing Connection reviews metric keeps its original meaning.

## Declared engineering rules

Policy: `tcp-attempt-review-v1`. All rules use a **sliding, inclusive 300-second
window**, so an arbitrary five-minute bucket boundary cannot split a burst.
Equal timestamps are evaluated together, including all comparable records, to
prevent input ordering from changing retry fractions.

| Pattern | Grouping | Gate |
| --- | --- | --- |
| Failed attempts across multiple ports | Originator + responder | At least 20 distinct responder ports with S0/REJ failures |
| Failed attempts across multiple responders | Originator + responder port | At least 20 distinct responder IPs with S0/REJ failures |
| Repeated failures to one endpoint | Originator + responder + responder port | At least 30 S0/REJ failures and fraction >= 0.90 among comparable records |

One peak window per pattern/key is retained. Peak preference is highest failure
count, then diversity, then earliest end. Results sort deterministically by
failure count/pattern/endpoints/time and retain at most **500** findings.
`omitted_findings` and the local warning disclose capacity loss. Patterns may
overlap on the same underlying evidence; their count is not a count of incidents.
These thresholds were declared before detector implementation and were not
optimized on inspected traffic or selected as calibrated malware thresholds.

Only TCP records with a nonconflicting UID, observed originator/responder,
ports 1–65535, aware timestamp, known comparable state and `missed_bytes == 0`
can contribute. Failure numerator is specifically **S0/REJ**, not every state in
older failed/half-open connection counts. Optional byte/duration fields are not
required for failed-attempt evidence; S0/REJ rows with positive payload bytes are
contradictory and excluded. UDP, ICMP, OTH/missing states and other half-open
states do not supply S0/REJ failure evidence. Comparable non-S0/REJ states count
in the retry denominator, even without confirmed bidirectional payload.
Zeek's [official connection definitions](https://github.com/zeek/zeek/blob/master/scripts/base/protocols/conn/main.zeek)
define S0 as an unanswered attempt and REJ as a rejected attempt. Asymmetric
capture/filtering can also affect those observations.

Identity dedup/conflict handling is shared with existing connection findings and
timelines. Missing/conflicting/incomplete TCP evidence is counted explicitly.
An incomplete record from the same originator within the candidate window blocks
retry-fraction review; unknown time blocks retry review for that originator
throughout the retained input. This conservative scope includes other services
on that source. Independently observed 20-port/host diversity can still appear,
with source exclusion counts. Unknown originators are counted as unattributed
and cannot be assigned to a source. Zero reported gaps is not proof of complete
sensor visibility. Coverage is always bounded by supplied/retained logs.

## Privacy and compatibility

Schema-2 connection exports add an `attempts` block; other findings, aliases,
priorities, domain/device verdicts, timelines and original ML behavior stay
unchanged. Reports omit raw UIDs/rows, source paths and declaration configuration.
Default endpoint aliases use the same report-local mapping as connection rows.
Horizontal patterns show Multiple responders rather than dumping destination
lists. Time/counts/ports remain sensitive even with aliases.

The original aggregate report/history does not receive this queue. No new state
schema or SQLite migration. Collector snapshots validate optional attempt bounds,
counts, fractions and aware window times before rendering; older snapshots
without this block remain readable. Expected declarations cannot suppress these
reviews, and existing CTI context remains in the original group view. No new
feed/API request, originator reputation lookup, model scoring or public listener.

## Constructed and live controls

`tcp-attempt-controls-v1` freezes control inputs/expectations before coding:
**32/32 development** and **32/32 separately seeded reserved** checks pass.
Controls cover thresholds, sliding boundaries, duplicates/global conflicts,
client separation, missing/gapped/contradictory evidence, excluded protocols,
successful denominators and simultaneous timestamps. A benign inventory scan
matches the port-diversity rule and a benign service outage matches retry review;
this explicitly demonstrates review burden and ambiguous intent. These are
contract checks, not malware labels, measured FPR/recall or independent field data.
The initial preimplementation generator receipt is preserved separately; a
boundary-case construction correction occurred before detector implementation.

Candidate/parser/runtime/report fingerprints froze before the new official
acquisition and live observation. No detector parameter changed afterwards.
The live `tcp-attempt-live-v1` run uses a guest-only internal Docker bridge,
pinned images, 24 responders, four synthetic clients and no published ports.
All containers drop capabilities, have read-only roots and run ownership labels.
Existing resources are refused and cleanup removes only this run's resources.
The capture sees only its dedicated bridge and control TCP ports. Zeek's offline
`-C` option retains the existing guest offload/checksum limitation.

| Live workload | Records | State | New attempt patterns |
| --- | ---: | --- | ---: |
| Vertical closed-port control | 24 | REJ | 1 port-diversity |
| Horizontal closed-host control | 24 | REJ | 1 host-diversity |
| Benign service outage | 36 | REJ | 1 repeated-failure |
| Healthy request/response | 36 | SF | 0 |

UTC run `attempt-live-20261004T214016Z` accepted **120** rows with zero invalid
metadata and zero reported kernel drops. Original connection reviews remained
zero; the new queue supplied three separately scoped patterns. Offline/collector
findings match; restart adds zero records and gzip replay is one duplicate.
Conn-log SHA-256: `72552857f381b8b21dd58035f7ffe00badc69b3973ee2709cdf111438475af09`.
This is synthetic real-packet plumbing evidence, not field detection efficacy.

## New official capture: remaining gap

Before acquiring any bodies, only HEAD sizes were checked for previously
uninspected 33-1, 8-1 and 9-1 logs. The declared **4 MiB** bound admitted 8-1;
33-1/9-1 exceeded it. Selection used size, not observed detector outcomes.
The entire new `CTU-IoT-Malware-Capture-8-1` connection file was acquired after
candidate freeze, labels stripped before analysis and CTI/ML/rules disabled.
No destination was contacted and no malware/PCAP was downloaded.

| Observation | Result |
| --- | ---: |
| Input bytes / accepted records | 1,431,000 / 10,403 |
| Invalid/skipped metadata | 0 |
| Original connection groups / Review groups | 9 / 0 |
| New attempt patterns | 0 |
| Comparable records / excluded TCP records | 8,222 / 2 |
| Provider label totals | 2,181 Benign; 8,222 Malicious |
| Collector import / restart added / gzip duplicates | 10,403 / 0 / 1 |

A trusted isolated archive of baseline commit
`b00fc836367c7ff0f408c6d1bd56d1130a7d5d59` produced identical original connection
findings/timelines and domain verdict counts on this exact label-free input.
The new queue emits no review. A post-evaluation diagnostic shows TCP consists
of 8,222 S0 and two OTH records, with at most **16** comparable same-endpoint
failures per 300 seconds and one failed port per originator/responder pair.
Thus this capture's sparse failures are outside the declared dense-attempt
rules. **The coverage gap remains; no increased malware recall is claimed.**
The file is now inspected evidence and cannot be reused as an untouched tuning
holdout. Future sparse-failure behavior work requires new reserved inputs.

Acquired SHA-256:
`4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a`.
Source attribution: Garcia, S., Parmisano, A., & Erquiaga, M. J. (2020),
[IoT-23 v1.0.0](https://doi.org/10.5281/zenodo.4743746).
See the [provider](https://www.stratosphereips.org/datasets-iot23) and
[license record](https://zenodo.org/api/records/4743746). Raw logs, labels,
collector state, reports and experiment receipts remain private/outside Git;
only source, protocol and aggregate observations are published. One old IoT
malware capture with no new independent benign capture is insufficient for
enterprise efficacy, malware FPR/recall, native RITA or parity claims.

## Reproduce without overwriting private results

Use a new owner-only experiment directory outside the repository:

```bash
.venv/bin/python -m scripts.lab.evaluate_attempt_controls --directory /private/new-run prepare
.venv/bin/python -m scripts.lab.evaluate_attempt_controls --directory /private/new-run development
.venv/bin/python -m scripts.lab.evaluate_attempt_controls --directory /private/new-run reserved
.venv/bin/python -m scripts.lab.evaluate_attempt_sources --directory /private/new-run freeze
mkdir -m 700 /private/new-run/baseline-source
git archive b00fc836367c7ff0f408c6d1bd56d1130a7d5d59 | tar -x -C /private/new-run/baseline-source
.venv/bin/python -m scripts.lab.evaluate_attempt_sources --directory /private/new-run official --baseline-source /private/new-run/baseline-source
```

Use this increment's Git revision for historical reproduction; fingerprints
reject changed detector code and modified control manifests. The source service
may change contents/availability; another hash identifies another acquisition.
Writes are exclusive; use a new directory rather than replacing results.
Official/live collector proofs use a declared seven-day retention window to
preserve supplied input, not a production default-sizing recommendation.

For live controls, copy `attempt_workload.py` and `run_attempt_live.sh` into the
existing isolated guest's `~/threatfusion-lab`, run the latter there, and copy
its private results back outside Git. Then run:

```bash
.venv/bin/python -m scripts.lab.evaluate_attempt_sources --directory /private/new-run live --live-directory /private/path/to/attempt-live-RUN
```

No CTI key or trained model is needed for these controls. A new independent
benign recording, sparse-failure controls, UDP/DNS scope, longer live rotation
and human analyst workload assessment remain next evidence gates.
