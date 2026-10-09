# P2 real-traffic evaluation design (v1, not yet declared)

Status: **design only.** No traffic has been captured or acquired for this
protocol and no result exists. Each arm becomes evidence only after its private
`plan.json` is declared under the `lab-experiment` protocol, against the exact
commit it measures. Limits below are proposals for that declaration; they must
not be changed after outcomes are seen.

## Question

[P2](../dev/PRODUCT_PLAN.md) asks whether ThreatFusion helps an analyst answer: *which
client and destination deserve investigation, why, and what should be checked
next?* That needs two separate measurements that earlier work could not supply:

| Arm | Measures | Input |
| --- | --- | --- |
| A — own normal traffic | Review burden and false alarms on current, real, permitted traffic | Zeek logs from the user's own devices, several days |
| B — labeled malware | Whether real C2/malware activity reaches the queue, how high, and with correct evidence | Untouched Stratosphere MCFP Windows malware captures |
| C — blind overlay (after A and B) | The same as B, but hidden inside A's normal background | Time-shifted, address-remapped B windows merged into A |

Earlier independent sources (IoT-23, CTU-Normal-20/21, Somfy, Trojan-21/42) are
inspected and stay out of evaluation. No `CTU-Malware-Capture-Botnet-*` capture
has been used so far.

## Arm A — own normal traffic

**Permission and scope.** Only devices the user owns and controls. If capture
sees other household members' traffic, they must agree first; otherwise capture
on this laptop's interface only. Raw logs stay in a new 0700 lab root and are
never committed, uploaded or printed. Reports contain aggregates only; no domain
lists, IPs or timelines are published.

**Capture.** Zeek (pinned container image, same version as the lab) on the
chosen interface, hourly rotation, conn + dns logs, for **7 consecutive days**
of normal use. The collector runs live on the closed logs with the user's own
CTI keys. Packet capture needs a one-time privileged step by the user
(`sudo` or Docker group); Claude does not run it unattended.

**Measured (declared before outcomes):**

- Review+ (Review / High Risk / Known Threat) client–destination groups per
  client-day; the first 7 days are reported in full, no day dropped.
- For every Review+ group the user records one label: *explained benign*,
  *unexplained*, *suspicious*, plus minutes spent. The user is the only, non-
  independent analyst; this is a usability signal, not a participant study.
- Share of Review+ groups the shown evidence lets the user explain without
  outside tools (evidence sufficiency).
- CTI matches and whether each is a true indicator match or shared hosting/CDN.
- Collector and web resource use, coverage warnings and gaps over 7 days.

**Proposed acceptance limits:** median ≤ 5 Review+ groups per client-day;
≥ 80% of Review+ groups explainable from the shown evidence; no collector
crash or silent coverage loss. Failing a limit is reported as a product defect
to fix before P3, not tuned away on these same days.

## Arm B — labeled malware captures

**Source.** [Stratosphere Malware Capture Facility Project](https://mcfp.felk.cvut.cz/publicDatasets/)
Windows `CTU-Malware-Capture-Botnet-*` captures. Terms: free use with reference
to the project and authors (Garcia, Sebastian; Malware Capture Facility Project,
CVUT). **Only the `.pcap` is acquired.** Malware sample archives, `mitm.out` and
other files are never downloaded; observed destinations are never contacted.

**Selection before inspection.** From directory metadata only (name, date, size,
README duration/infection time — no traffic, no product output):

1. Capture year 2019 or later, duration ≥ 4 h, pcap ≤ 512 MiB, single infected
   Windows host, infection time stated.
2. From the eligible list, a seeded random draw picks **4 development** and
   **8 reserved** captures. The seed, eligible list and draw are recorded in the
   plan before any pcap download.
3. Development captures may be inspected and used to find defects. Reserved
   captures are run once, on a frozen candidate, after development is closed.

**Processing.** Pinned Zeek on the pcap inside the lab VM's internal network
(offline replay, no transmission); the product and native RITA run on the
identical logs with documented configuration. Time from infection is measured
in capture time, not wall clock.

**Measured:** for each capture, whether the infected host has any Review+
group; the rank of its first Review+ group in the client queue; time from
infection to first Review+ evidence; whether the cited evidence is correct
(checked against provider labels where `conn.log.labeled` exists, otherwise
against the stated infection time and C2 destinations in the README). RITA
results are reported in their own units beside ours, not merged into a score.

**Proposed acceptance limits (reserved set):** infected host reaches Review+
in ≥ 6 of 8 captures; in those, a malicious destination is in the host's top
10 groups; no Known Threat verdict without an exact CTI indicator match.

## Arm C — blind overlay (later)

After A and B are reported, reserved-but-unused malware windows are shifted in
time and remapped to an unused address inside A's address plan, then merged
into A's logs by a script that writes the answer key to a sealed file. The user
triages the merged queue without knowing which client or day contains the
overlay. This approximates finding a needle in real background; it is still a
synthetic merge and is reported as such.

## Order of work

1. Push the P1 security repairs; finish the P1 soak report.
2. Arm A setup (user grants the capture permission step), then 7 days of
   capture. Development on Arm B's development captures runs in parallel.
3. Freeze a candidate; run Arm B reserved captures once; write results.
4. Arm C; then P2 summary with every failure kept.

## Limits of this design

One analyst who also owns the product; one household; Stratosphere captures
are lab-infected single hosts and may be old relative to current malware.
Results will not establish enterprise false-positive rates, general malware
recall or analyst time savings for other users.
