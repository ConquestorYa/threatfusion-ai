# P2 real-traffic evaluation

Status: **Arm A first 24 h measured (2026-10-11): 3 of 5 limits failed.**
Results below; the design that follows is unchanged.

## Arm A, first 24 hours: results

Private roots `real-traffic-arm-a-24h-v3` (capture, release `3c054a3`) and its
declared amendment `real-traffic-arm-a-24h-v4-dns-reimport` (labels, release
`4df7f35`). One laptop on Wi-Fi (own traffic plus multicast it hears), normal use
including a ~10 GB game download and a short Tor Browser window, system
DNS-over-TLS disabled for the window. 2026-10-10 08:43Z to 2026-10-11 08:43Z.

**Why two roots.** During the capture the installed collector rejected 16 of 25
completed DNS hours: a few question-less rows (mDNS announcements, replies
without a question section) failed strict validation and the whole hour was
dropped. The defect was fixed in source during the capture (DEC-093) but not
installed. After the capture, before any labeling or inspection of findings,
the same preserved Zeek logs were re-imported with the fixed release so the DNS
queue was complete. The live-run outcome is kept as A4 for `3c054a3`.

| Limit | Result | Pass |
| --- | --- | --- |
| A1 ≤ 5 Review+ groups per client-day | **59** (18 connection, 40 DNS, 1 TCP-attempt pattern) | ✗ |
| A2 ≥ 80 % decided from the shown evidence alone | **3 of 59 (5 %)** | ✗ |
| A3 every Review+ group labeled with minutes | 59/59, 22 minutes in total | ✓ |
| A4 collector healthy | live run on `3c054a3`: 16 rejected files ✗; re-import on `4df7f35`: 0 rejected, no coverage loss ✓ (same-data repair check, not new evidence) | ✗ / ✓ |
| A5 ≤ 5 unclear places on the page | **8**; the user reported the page as not understood overall | ✗ |

All 59 groups were labeled *explained benign*; none suspicious or unexplained.
No malware was expected, so this measures review burden, not detection.
Volume: 31,070 connection records, 13,857 DNS records, 626,537 CTI indicators
loaded; no capture hour without a rotated connection file.

**Where the 59 came from** (aggregate categories, no names published):

| Rule | Groups | What the benign causes were |
| --- | --- | --- |
| Long session ≥ 1 h | 15 | push/notification channels, app sync channels kept open, shared-CDN addresses |
| Periodic successful TCP | 3 | background app polling |
| DNS: high query volume (+ many response IPs) | 24 (5 of them local `.local`/`.arpa` names) | browser and app background services, large CDNs, a game-download CDN burst, local mDNS service discovery, reverse-address lookups |
| DNS: hostname appears in a malicious-URL IOC | 12 | large shared hosting/CDN domains where one uploaded file is listed, not the domain |
| DNS: other signal combinations (many response IPs/query types, IP churn; two "algorithmically random") | 4 | CDN and service names |
| TCP attempt pattern | 1 | benign failed attempts |

**How the labels were reached.** The labeling analyst is the product owner and
not a network specialist. Connection groups showed only pseudonyms or IPs, so the
user needed a lab-only helper that printed which DNS names answered with that IP.
For most names Claude explained what the service was (from general knowledge or
one targeted aggregate lookup, recorded in the operator notes); `ekran_yetti=h`
reflects that. One DNS name was a third-party download CDN reached via a CNAME
from the game platform; other subdomains of that CDN appear in ThreatFox/SGB,
the queried one does not.

**Product defects found** (to fix before the 7-day run; measured on new days):

1. Connection groups do not show the DNS names that resolved to the
   destination, nor the CNAME origin of a DNS name.
2. Local-only names (`.local` mDNS/DNS-SD, reverse `*.arpa`) enter the DNS
   Review queue.
3. A hostname that merely hosts a listed URL on a large shared platform is shown
   as a CTI-backed Review with no distinction from a listed domain.
4. One laptop appears as several "devices" (IPv4 plus IPv6 addresses), so the
   same name is queued repeatedly (40 DNS groups covered 25 distinct names).
5. Long-session and DNS-volume rules flag ordinary push, sync and CDN traffic.
6. The page language (guidance blocks, coverage text, timelines, wide tables) is
   not understandable for this user; a decision needs: what it is, why it was
   flagged, what to do.
7. Fixed during the run: question-less DNS rows rejected whole files (DEC-093).

**Limits.** One client, one non-independent analyst, one day; the explanations
came partly from Claude, so A2 measures the product screen, not the analyst.
Results belong to `4df7f35` (labels) and `3c054a3` (live collection). Browser
DNS-over-HTTPS and the Tor window stay invisible.
 Each arm becomes evidence only after its private
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
