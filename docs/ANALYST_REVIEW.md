# Analyst review tasks and context visibility

Status: 2026-10-05. Presentation and investigation workflow, not a new detector.

## Local workflow

**Connection activity** and **Collected connections** show counts across all
retained TCP groups, before filters and the 500-row display limit:

- Original TCP reviews: unchanged behavior reviews.
- Declared expected reviews: original reviews matching context, without CTI.
- Unexplained / CTI groups: undeclared reviews or destination-CTI groups,
  including CTI-only Observe groups. This is a union, not a sum.
- TCP CTI groups: a subset of that union; counts overlap.

DNS and TCP attempts remain separate units. Counts describe retained observations,
not the whole network. Check collector staleness, rejection and capacity warnings.

Select a group under **Connection investigation**. Bilingual **Review guidance**
shows original priority, evidence, limits and next checks. CTI takes precedence.
Expected activity prompts independent inventory/endpoint verification, including
the same-endpoint unrelated-process limitation. Incomplete evidence and exceeded
bounds have different guidance. Missing active exact context prompts ownership,
IP/port/protocol and expiry checks; it does not infer which check failed or renew
rules. The table retains the canonical context reason.

Reveal endpoint IPs explicitly when creating local rules and independently check
ownership. Follow [expiring exact-endpoint declarations](EXPECTED_CONNECTIONS.md).
No automatic rule creation, learning or persistence. **Include declared expected
activity** reversibly reveals separated findings. Downloads retain all groups,
original statistics and reasons, while omitting rule IDs/configuration. CTI
cannot be hidden by the expected filter.

In **Device DNS investigation**, guidance first asks whether the observed address
is an endpoint, shared resolver or NAT. Confirm with inventory/resolver logs;
the software cannot identify machines behind a shared resolver. Check query
times, span, response codes, caching and CTI. DNS does not establish connection,
download or execution. DNS-device and TCP-host alias numbers cannot be joined.

Guidance remains available when a selected group's chart is outside the 200-group
timeline cap. Selectors/tables remain capped at 500. Upload TCP selections reset
when endpoint mappings or explicit-IP display change; filtered-out selections
are cleared. Language changes preserve canonical group identity. Collector
mappings keep their selection revision contract. Legacy connection rows without
priority do not acquire invented guidance.

## Predeclared tasks and checks

Before implementation, eight task families were frozen privately against main
`450c95826832426a9d2a72e624f3616650d9666b`: normal update verification, undeclared
heartbeat, CTI override, expired/mismatched/bounded/incomplete declarations,
shared resolver attribution, omitted charts, selection changes and original
report/bilingual/privacy preservation. Task-plan SHA-256:
`fc5799ca031552019cbea86b0983ba6dd336c2fdd77380ed5fda8a08cc9b5f70`.

Fifteen new automated task/input-integrity tests join existing context, collector
and upload/public-boundary tests. They verify evidence availability, reversible
visibility and next-check wording. Actual analyst decisions/time remain
unmeasured; a participant study with independent service evidence is still needed.

## Two new complete synthetic recordings

`evaluate_analyst_tasks.py prepare` freezes seeds 20261071/20261171, five supplied
lab-service declarations, dates and count/duration/byte limits before generation
and offline Zeek. The reviewed twelve-profile generator represents two hours
without transmitting packets. New seeds reuse an inspected generator; neither
phase is independent real traffic. The reserved phase has now been inspected.
Traffic-plan SHA-256:
`43cd798820fb4223bf782f6c2835b3b924a788e2814e14d1a0efb3d57900bb9e`.

Source/input freezes refuse changes and previous result overwrite. Pinned Zeek
runs without network, capabilities, writable root or root UID:
`activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5`.
Full PCAP structure and DNS answers/HTTP exchanges/TCP counts/states reconcile
with the manifest. Partial packet/log prefixes are not scored.

| Case | Packets | conn.log rows | DNS transactions | Original TCP reviews | Expected reviews | Unexplained / CTI |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Development | 5,862 | 675 | 143 | 8 | 5 | 3 |
| Reserved | 5,804 | 670 | 144 | 8 | 5 | 3 |

Each has twelve TCP groups. Five original normal-role reviews match supplied lab
inventory; three original simulated-role reviews remain unexplained. Wide jitter
and sparse failures still miss existing gates. Inventory is explicit lab context,
not software identity inferred from traffic or an accuracy result. Another
process at a declared endpoint can match the same declaration.

Adding reserved-IP CTI to the declared regular updater restores that group:
expected reviews four, unexplained/CTI four, CTI one, original reviews eight.
Past declaration expiry, all eight reviews return without deleting observations.
Collector clocks are retrospective, not live two-hour/multi-day reliability.

All **1,632 mixed records** reconcile offline/collector findings, timelines and
attempts without rejection/pruning. Restart adds zero; two gzip copies duplicate
per case. DNS snapshots match after restart. CTI-change/expiry ticks match
independently computed context rows; original evidence/priorities remain.
PCAP SHA-256 receipts:

- Development: `9067572c022332839dd51adc17f84d1009fae9d4221ba7a7889a1404d6a4fc4b`
- Reserved: `a3e68021a09d34e75716d432a524e4fc644b6d56134af3b1d93be16a30e821af`

No native RITA rerun for unchanged detectors. Previous measurements and truncated
source exclusions are preserved. Several intact independently selected permitted
normal/malicious windows remain a separate gate, alongside participant tasks.
No malware accuracy, enterprise FPR, RITA parity or human-time claim. ML identities
and thresholds stay frozen; fresh-disjoint is not strict temporal, and augmented
runtime promotion remains deferred.

## Reproduce privately

Use a new private directory outside Git and the existing isolated guest described
in [LOCAL_LAB.md](LOCAL_LAB.md). In the active project environment:

```bash
umask 077
python -m scripts.lab.evaluate_analyst_tasks prepare --root /private/new-tasks
```

Copy `development`, `reserved` and `scripts/lab/run_analyst_tasks.sh` into the
guest's new `~/threatfusion-lab/results/analyst-guidance-v1/`. Run the script
**inside that guest**. Copy `zeek/`, `zeek.exit` and `image.txt` back into each
original host case directory, preserving frozen inputs. Then:

```bash
python -m scripts.lab.evaluate_analyst_tasks evaluate --root /private/new-tasks
```

Existing case/output directories are refused. PCAP/logs/rules/SQLite/evaluation
receipts remain local and owner-only. Seven existing UI/translation modules plus
a new guidance module change; the other 73 frozen runtime modules and all 34
original data files remain byte-identical. No keys, CTI caches, model binaries,
private telemetry or public hosting are included in the source release.
