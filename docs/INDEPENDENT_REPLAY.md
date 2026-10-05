# Real-capture diagnostic replay and input compatibility

## Purpose and frozen baseline

`independent-replay-v1` selected four official capture URLs/HEAD lengths before
packet acquisition, against runtime `cc38d3210f57d1e0174f98712c0ca609bf3648d6`.
All 81 top-level runtime modules stayed identical through baseline evaluation.
CTI, lexical ML, expected declarations and flow labels were disabled; thresholds
were unchanged. Two further source identities remain unacquired: CTU-Normal-7
and IoT-Malware-1-1. Inspected inputs must never become a new untouched holdout.

**Source-history correction:** IoT-8-1 connection logs were already inspected in
[the TCP-attempt experiment](TCP_ATTEMPT_REVIEW.md). A new PCAP acquisition/hash
does not make its traffic independent. It is a known-source packet replay, not
new malicious evidence. Three source families are new relative to earlier
experiments; only one passes the full baseline product gate. No replacement was
selected after outcomes. `audit_source_history.py` now rejects known families
unless explicitly declared as replays; unlisted is not proof of freshness.

The plan SHA-256 is
`5208372b594becc6ea848f262a2659565f8eec78c19a91b5736e19ab87db0b2a`.
Original acquisition receipts/method fingerprints are immutable and private.
Normal-21 first failed classic-PCAP qualification. Its magic identifies PCAPNG,
not corruption. Before any native/detector outcome, an explicit format revision
preserved the first exclusion and all packet bytes, qualified all four complete
files, and sealed new tooling/qualification hashes. No conversion or shortening.
New acquisitions use bounded classic-PCAP/PCAPNG qualification directly.

PCAPNG qualification supports Ethernet 1.0 sections and timestamped enhanced
packet blocks, byte order, section/interface references, lengths, padding,
option framing, complete block footers and bounded allocation. Unsupported
packet/unknown blocks fail closed; non-packet name-resolution/interface-statistic
blocks receive framing checks. It is a conservative subset, not a full capture
format implementation. See [IETF PCAPNG draft, sections 3–4](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-pcapng-06).

## Sources, permission and scope

The provider describes the [normal captures](https://www.stratosphereips.org/datasets-normal)
as old Windows/Linux HTTPS website activity. These 2017 samples extend beyond
the previous IoT normal controls, but are not representative enterprise or
multi-day traffic. The [Normal-20 directory](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/)
and [Normal-21 directory](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-21/)
give free-use terms with author/project attribution. Attribution: Sebastian
Garcia, Malware Capture Facility Project, Stratosphere IPS.

IoT-23 provides real-device malicious/normal capture scenarios from 2018–2019:
[provider description](https://www.stratosphereips.org/datasets-iot23).
Attribution: Garcia, S., Parmisano, A., Erquiaga, M. J. (2020), *IoT-23*, v1.0.0,
[DOI 10.5281/zenodo.4743746](https://zenodo.org/records/4743746).
The [Zenodo metadata](https://zenodo.org/api/records/4743746) declares CC BY 4.0.
Individual directory acquisitions are not verified against the full archive.
Scenario intent does not label every connection, group or native row.

| Source | Acquired bytes | Complete packets | Acquired SHA-256 |
| --- | ---: | ---: | --- |
| Normal-20 / Windows | 282,415,864 | 402,724 | `c78a00728f115ab8fc495fd395894c43fd90cb61054eb9ef4f2d024658d5ffc5` |
| Normal-21 / Linux | 311,638,284 | 442,488 | `53acb10b26ca6446b5bba2efd9d957a9faa15209029d58c10a8c1d1bd299c42b` |
| IoT-Malware-3-1 | 57,919,772 | 496,959 | `c674dc0c8d584fa66e6f00c60df973c5fbacad551c850a76d75ec9952641d00b` |
| IoT-Malware-8-1, known replay | 2,098,362 | 23,623 | `80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2` |

Acquisition streams at most two files concurrently, capped at 512 MiB/file,
declared HEAD length and 600 seconds. Redirects stay on the official HTTPS
origin. IoT-7-1 exceeded the size bound; 9-1 filtered derivatives and 3-1
`test.pcap` were not acquired. Packet bodies are never executed or transmitted,
payloads are not extracted, and observed destinations are not visited.

## Same-source native configuration

Offline Zeek:
`activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5`.
Native RITA v5.1.2:
`ghcr.io/activecm/rita@sha256:a2bb0ef6185e33780dbc3ce7d86e38ac7a65c98e729e17510fe29717eb34b76a`.
Same full Zeek outputs feed both tools. Zeek has no network/capabilities, runs as
input owner, with read-only root/input, bounded memory/PIDs and no public ports.
RITA uses the existing isolated private ClickHouse network; feeds/updates off.
Fresh database names prevent overwrites; previous configurations/databases stay.

Separate native configuration preserves upstream scores. Only input-owner
UID/GID and predeclared internal networks are set: RFC1918, `fc00::/7`,
`fe80::/10`. Internal/external scope and native filtering remain different from
ThreatFusion originator/responder groups. Native view uses a 100,000-row bound;
exact-limit/malformed exports fail. Zero exported rows do not mean safe traffic.
All four full Zeek/import/view commands succeeded. Product failures below remain
excluded from complete comparisons; native-only outputs do not repair them.

## Baseline observations

| Source | Full connection / DNS rows | Baseline product gate | TCP reviews / groups | DNS reviews / groups | Attempt patterns | Native rows |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Normal-20 | 18,892 / 15,089 | Pass | 1 / 806 | 25 / 1,143 | 0 | 0 |
| Normal-21 | 10,662 / 8,747 | Excluded: 2 invalid protocol fields | — | — | — | 330, native only |
| IoT-3-1 | 156,459 / 9 | Excluded: file bound, also exceeds shared capacity | — | — | — | 98, native only |
| IoT-8-1, known replay | 10,403 / 0 | Pass | 0 / 3 | 0 / 0 | 0 | 8 |

Normal-21's two fields are legitimate Zeek `unknown_transport` values (17
characters); the baseline importer permits only 16 for `proto`. The collector
therefore rejects the entire completed file. This is an input compatibility
defect, not a corrupt capture or detection success. Zeek's
[transport enum definition](https://github.com/zeek/zeek/blob/master/scripts/base/init-bare.zeek)
contains this value. A separately declared parser repair must preserve it without
mapping it to TCP/UDP or making unknown traffic eligible for their detectors.

IoT-3-1 `conn.log` is 17,701,780 bytes, beyond 16 MiB, and its 156,468 mixed rows
exceed the shared 100,000-record window. It also contains one unknown-transport
row. Do not increase bounds, truncate or sample until this fits and call that
complete validation. Scalable ingestion/coverage reporting is a separate gate.

Complete baseline cases retain **44,384 mixed records**, zero rejected/pruned
rows and exact offline/collector findings, timelines, attempts and DNS snapshots.
Restarts add zero; gzip copies are two/one duplicates. A retrospective clock
preserves full historical sources in the existing seven-day window. Normal-20
spans 11,327.484307 seconds; IoT-8-1 spans 86,395.260731. Retained rows do not mean
uncapped visible queues/charts: Normal-20 has **143 DNS groups omitted** by the
1,000-group snapshot bound; existing 500-row views/200-group timelines remain.
None of these limits is silently changed.

Native-only severity distributions, explicitly separate from product evidence:
Normal-21 Medium/Low/None = 2/16/312; IoT-3 High/Medium/None = 4/1/93;
known IoT-8 High/Medium/Low = 1/2/5. Windows exports zero rows under this native
configuration. A native row is neither a ThreatFusion review nor a malware
flow label. Counts cannot establish which tool is more accurate.

Separate destination-IP fallback verdicts are all Low: 728 in Normal-20, nine
in IoT-8. They do not cancel DNS/connection reviews. Windows normal activity
produces 25 DNS reviews and one TCP review. Known IoT-8 sparse failures still
produce no TCP/attempt review while native RITA emits one High row. This gap was
already observed in the earlier log experiment; it is not increased recall.

## Reproduce privately

Use the **baseline-method commit before the parser repair** for identical runtime
fingerprints. Later source changes require a separately named experiment, never
relabel the frozen baseline. Install normal project dependencies, then:

```bash
# Keep a new owner-only directory outside the repository.
umask 077
python -m scripts.lab.independent_replay prepare --root /absolute/private/replay
# Every source is now inspected. Declare known replays before acquisition.
python -m scripts.lab.audit_source_history --plan /absolute/private/replay/plan.json \
  --allow-known CTU-Normal-20 --allow-known CTU-Normal-21 \
  --allow-known CTU-IoT-Malware-Capture-3-1 \
  --allow-known CTU-IoT-Malware-Capture-8-1
python -m scripts.lab.independent_replay acquire --root /absolute/private/replay
```

New acquisitions already support PCAPNG; `qualify` is only an explicit amendment
for a complete older acquisition, before any native/evaluation outcome. It
preserves first receipts and seals the amended method; it cannot follow results.
Never overwrite or reuse an evaluated root.

In the existing private guest, create a separate scoring-identical native
configuration/contract, preserve old databases, copy only private acquisitions
and the matching runner. The runner's fixed guest root is
`~/threatfusion-lab/results/independent-replay-v1`; verify no prior case outputs
or database names exist. Start only the owned private ClickHouse backend, run
`bash run_independent_replay.sh`, then transfer evidence without overwriting
original PCAPs/receipts. Contract must attest pinned RITA, unchanged scoring,
empty feeds and identical declared subnets. After verifying full input/config/
output hashes:

```bash
python -m scripts.lab.independent_replay freeze --root /absolute/private/replay
python -m scripts.lab.independent_replay evaluate --root /absolute/private/replay
```

The collector reconciliation is Linux-only. Private raw captures, Zeek logs,
native CSV, models/caches/SQLite and evaluation receipts stay outside Git; only
method, tests, attribution and aggregate observations are published. Freeze and
all four source exclusions/results remain intact after later fixes.

## Decision

The new independent malicious-source gate remains **open**: IoT-3 cannot fit the
current product, and IoT-8 is known. Normal coverage is wider but not an enterprise
benchmark. No malware FPR/recall, RITA parity, analyst time benefit, production
security or strict-temporal ML result follows. Original model identity/thresholds
and deferred augmented runtime promotion remain unchanged.

Priority: repair legitimate unknown-transport import under explicit contracts;
then declare bounded large-log ingestion/window coverage before changing behavior
detection. Reserved sources remain untouched for separately scoped work. Sparse
failure/timing, DNS tunneling, SIEM, participant and multi-day security gates
remain open. Source-history checks must precede future acquisition.
