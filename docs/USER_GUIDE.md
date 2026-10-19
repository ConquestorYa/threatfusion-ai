# User guide

ThreatFusion answers one question: **which device talked to which destination,
and which of those conversations deserve a closer look?** It reads Zeek logs,
compares destinations with threat-intelligence (CTI) lists and checks a few
behaviors that are typical of malware command-and-control traffic. Every flag
says why it was raised. A flag is a reason to check, never proof of infection.

Install first: [Linux installation](INSTALL_LINUX.md). To produce logs:
[Zeek sensor setup](ZEEK_SETUP.md).

## Pages

| Page | Use it to |
| --- | --- |
| **Collected connections** | Watch the logs of your Zeek sensor continuously. The main page. |
| **Analyze telemetry** | Upload one file (Zeek, DNS CSV, PCAP, Pi-hole, AdGuard, Suricata…) and analyze it once. |
| **Quick lookup** | Check one URL, domain or IP against your local CTI lists, without visiting it. |
| **Setup & CTI updates** | Choose the mode, enter your API keys, update CTI lists, schedule updates. |
| **Analysis history** / **Model evaluation** | Only in modes that run a measured ML model; hidden in the default CTI-only mode (no such model is installed). |

The sidebar shows the state of each CTI source. English and Turkish, light and
dark themes are available at the top right.

## CTI sources

| Source | Key | Content |
| --- | --- | --- |
| SGB (T.C. Siber Güvenlik Başkanlığı) | Not needed | Malicious domains and IPs reported in Türkiye |
| ThreatFox (abuse.ch) | Free abuse.ch key | Malware command-and-control servers and other IOCs |
| URLhaus (abuse.ch) | Same key | Malware download URLs |

One free key from [auth.abuse.ch](https://auth.abuse.ch/) covers both abuse.ch
sources. Keys stay in the browser session unless you choose to save them in a
private owner-only file. A failed update keeps the previous data.

The same update also downloads two public context lists without a key, weekly:
the Tranco popular-site list and the iptoasn.com IP owner table (which network,
and its registry country, an address belongs to). They are context, not threat
data, and lookups in them stay on your computer.

## Collector

```bash
threatfusion-ai collect --input-dir /absolute/path/to/zeek/logs
```

The collector checks the folder every 10 seconds and imports each **completed**
Zeek log: names starting with `conn.`/`dns.` (also `_` or `-`), ending in `.log`
or `.log.gz`, whose last line starts with `#close`. Files still being written
wait for rotation. Subfolders are scanned; symlinked folders such as
ZeekControl's `current` are skipped. Use one state per sensor.

- It keeps the last **24 hours** of evidence (`--window-hours`, 1–168).
- Ctrl+C stops it; running the same command again resumes from its checkpoints.
- It runs separately from the web app. `threatfusion-ai stop` stops the web app,
  not the collector. Nothing starts automatically at login.
- It uses the installation's CTI cache and picks up CTI updates on its next
  scan. If an update is writing the cache, the scan keeps the previous indicators
  and the page says so.
- The collector itself uses no ML. The page's **Experimental ML** tab builds
  its own view from the collected records and trains its behavior model on
  this computer (see below).

The page refreshes every 10 seconds and warns about stale snapshots, rejected
files and reduced coverage.

### What gets flagged

Connections are grouped by **device → destination IP and port**.

| Check | Rule | Why it matters |
| --- | --- | --- |
| CTI match | The destination IP is on a CTI list | Known malicious infrastructure |
| Long session | One two-way TCP session lasting at least 1 hour | Control channels are often kept open |
| Regular repetition | At least 20 connections over at least 30 minutes, at very regular intervals | Malware "checks in" on a timer |
| Failed attempts | Within five minutes: unanswered or refused TCP attempts to at least 20 different ports/hosts, or at least 30 repeated failures | Scanning, or a program that keeps trying an unreachable server |

DNS observations are grouped by **device → domain** and reach Review when:

- the domain is on a CTI list (**Known threat**), or one of its answer IPs or a
  listed URL's hostname is (CTI context);
- queries repeat at regular intervals (same 20-query / 30-minute minimum); or
- at least two volume signals occur together: many queries, many clients,
  changing answer IPs, many query types, or a burst in a short time.

Frequent "no such domain" answers, changing answers and random-looking names are
shown as context; on their own they do not raise a group.

**Context that keeps ordinary traffic out of Review** (added after the first
real-traffic test, [results](evidence/REAL_TRAFFIC_EVALUATION.md#arm-a-first-24-hours-results)):

- **Local names** (`.local` mDNS/DNS-SD announcements, reverse `*.arpa`
  lookups, local zones) stay Observe unless a CTI list matches.
- **Popular sites.** The CTI update also downloads, weekly and without a key,
  the public [Tranco](https://tranco-list.eu/) top 100,000 and the
  [Public Suffix List](https://publicsuffix.org/). When a name's registrable
  domain is in the top 100,000, volume and changing answers stay Observe, and a
  listed URL on that site is shown as context (the site hosts a listed file; it
  is not itself listed). A user's own subdomain on a shared platform (dynamic
  DNS, user pages, tunnels) is its own registrable domain and is **not**
  popular. A connection whose DNS names are all popular sites is an
  observation with that reason shown. An exact domain or address on a CTI list
  always wins.
- **Limitation.** Attackers also use popular services; this context trades
  some of that visibility for a usable list. It has not yet been measured on new
  days.

Groups that need a look appear as **Review**; everything else stays visible as
**Observe**. A connection with a CTI match is marked and always shown, even when
its behavior is Observe; DNS groups with a CTI match go to the top as
**Investigate**. Failed-attempt patterns have their own list. Normal software also matches these
rules: updaters repeat on timers, chat and notification apps keep long sessions.
That is why each row explains its reason, and why the result is a queue to check
rather than an alarm.

### The three tabs

**What to check** is an alarm list, one row per item: name (for connections,
the DNS names that pointed to the address), a short label such as *Long
connection · 2.0 h open* or *Frequent lookups · 66 lookups*, device IP →
destination IP:port with the network owner under it (for example *FASTLY · US*;
the country is where the network is registered, not where the server is), and
time. Items on a threat list come first (🔴).
**Why? What to do?** opens the reason, a short action, other names sharing the
addresses, and VirusTotal, AbuseIPDB (IP reports from other users) and urlscan
(a screenshot of the site, so you need not open it) buttons. These are outside
sites: the name or IP is sent there only when you click. Each item has three one-click marks, stored privately next to the
collector state: **I know this** hides it from now on (also when the same name
or address comes back; *Known → Show again* undoes it), **Not sure** keeps it
with a badge, and **Suspicious** pins it on top and, with a collector of this
version, sends a desktop notification when that name is seen again (once per
day). Clicking a selected mark again removes it. Items on a threat list always
stay visible. *Not marked* filters what is left to decide. A name looked up from several addresses of the
same computer appears once. Real IPs are shown on your own screen; downloads
keep aliases. **Details** keeps the full technical view. **Experimental ML**
is described below.

### Experimental ML: New for this computer

This list shows destinations that are **new** for your computer and that it
**keeps calling at a steady rhythm** (at least 4 connections in a day, rhythm
score 80/100 or more), the way a program that "calls home" does.

- **Memory.** ThreatFusion remembers which sites (registrable domain, or the IP
  when no DNS name is known) your devices used and on which days. The memory is
  one private file, `<install>/ml/baseline.json` (owner-only), and it never
  leaves the computer. It covers all devices of the sensor together, so a
  laptop keeps its memory when its address changes between networks.
- **Learning.** Nothing counts as new until 3 earlier days of traffic are in
  the memory. The memory only grows while the app is open; days the app did
  not run are not part of it.
- **Rhythm** is a fixed score from the timing and size regularity of the
  connections (robust to jitter and missed beats), not a trained model.
- **One card per site.** Addresses of the same site share one card. Marking a
  site *I know this* on any list hides its new entries; *Suspicious* pins them
  on top.
- **Measured so far:** about 0.5 entries per normal device per day on public
  research recordings and this project's own traffic (development grade). It
  is a reason to look, not a malware verdict: only 2 of 6 command-and-control
  destinations in the research data were new when first seen. The binding
  test is the 7-day real-traffic run.
- A destination whose DNS lookup happened before the collector's window can be
  treated as new; the rhythm requirement removes most of these.

### Experimental ML: behavior model trained on this computer

Below *New for this computer*, a random forest scores each device–destination
pair of the last day by *how* they talk: rhythm, sizes, durations, failures,
port, and how random the name looks. Pairs above the model's line appear as
cards with plain reasons and a rhythm chart.

- **Learning.** About once a day the app keeps the connection groups of the
  collector's newest 24 h window (features only) in `<install>/ml/local-days.json`
  (owner-only). After 3 such days it trains the forest here, in a few seconds,
  on numeric features of public malware and normal recordings shipped with the
  app plus your days, taken as normal; it retrains daily. Until then the tab
  shows how many days it has. It learns only while the app reads the collector.
- **Its line** is the lowest score that flags at most one group per day on your
  newest day and on public normal recordings.
- **Measured** (the same recipe, once, on recordings it never saw): 5 of 7
  malware families on an unseen device, 56 % of unseen malware recordings, at
  most one false flag per day; only 27 % of 2025–2026 malware and 20 % of
  simulated beacons. The **Model evaluation** page lists every test.
- **Limits.** If the computer was already infected during its first days, the
  model learns that as normal. Updaters and sync tools can look similar to
  malware; mark them *I know this*. Threat-list checks and What to check do not
  use this model.

Models trained on public recordings alone failed their declared tests and are
not used. History: [ML evaluation](evidence/ML_DATASET.md).

### Investigating a group

- Select a group to see its connection starts over time (UTC), Zeek connection
  states and byte counts; for DNS, queries and answer types over time.
- Devices are shown as aliases (`Host 1`, `Device 1`). Tick **Show observed
  endpoint IPs locally** to see real addresses on your screen; downloads keep
  aliases.
- Downloads: the visible snapshot as JSON, and for more than 1,000 groups a
  verified full JSON.gz. Treat every export as sensitive.

### Declaring expected activity

After you have verified that a connection is normal, you can describe it in a
private JSON file so it moves out of the review list (it stays visible with
**Include declared expected activity**):

```bash
threatfusion-ai collect --input-dir … --expected-connections /private/expected.json
```

```json
{
  "schema_version": 1,
  "rules": [
    {
      "id": "checked-updater",
      "originator_ip": "192.0.2.1",
      "responder_ip": "198.51.100.1",
      "responder_port": 443,
      "protocol": "tcp",
      "valid_from": "2026-10-04T00:00:00Z",
      "valid_until": "2026-10-05T00:00:00Z",
      "max_connections": 100,
      "max_duration_seconds": 60,
      "max_originator_bytes": 100000,
      "max_responder_bytes": 1000000
    }
  ]
}
```

Rules need exact IPs and port, TCP only, a validity window of at most 30 days and
traffic limits; at most 128 rules. A CTI match always overrides a declaration.
A declaration cannot prove which program made a connection. Declarations are
disabled while coverage is incomplete (rejected or pending input, capacity loss).
Evidence of these rules: [expected-connection controls](evidence/EXPECTED_CONNECTIONS.md).

### Large log files

Files above 16 MiB can be split into validated private shards first:

```bash
threatfusion-ai prepare-logs --input /private/conn.log --output-dir ~/threatfusion-prepared/conn
threatfusion-ai collect --input-dir ~/threatfusion-prepared
```

`--quarantine-incomplete-dns` keeps DNS rows without a query or type aside
(privately) instead of rejecting the whole file; the page shows how many.
This does not raise the 100,000-record analysis window.

### Limits

| Limit | Value |
| --- | --- |
| Poll interval | 10 s (1–3,600) |
| Evidence window | 24 h (1–168) |
| Retained records | 100,000 connection + DNS records together |
| DNS names | 25,000 |
| File / expanded gzip | 16 MiB each |
| Per scan | 8,192 directory entries, 64 changed files |
| Snapshot | 64 MiB, 1,000 groups in the JSON, 500 rows in the table |

Hitting a limit is shown as coverage loss. The collector holds the active CTI
indicators in memory: about 0.5–0.9 GiB with roughly 630,000 indicators.

### Desktop notification

When the collector sees traffic to a threat-list match, it shows one desktop
notification (Linux `notify-send`), once per match, in the language last chosen
in the app. Only threat-list matches notify, never behavior reviews. The
notification can appear on a lock screen, so it names a domain only when the
traffic named one and never shows an IP. Start the collector with
`--no-notify` to turn it off.

## Analyze telemetry (upload)

Auto-detect handles: CSV/TSV/TXT and Excel with DNS columns, Zeek `dns.log` and
`conn.log`, PCAP/PCAPNG (plain DNS on UDP 53), Suricata EVE JSON, Pi-hole FTL
database, AdGuard Home query logs and dnstop text. Uploads are processed in
memory; the limit is 100 MB, 100,000 events and 25,000 distinct targets.
Results include CTI evidence, behavior signals, per-device triage, related
activity and privacy-safe exports.

## Quick lookup

Paste a URL, domain or IP. ThreatFusion checks the local CTI cache only: it does
not open the page, resolve the name or download anything. No match does not
mean the target is safe.

**Site age (optional):** for a domain, the "Check site age" button asks the
domain's official registry (RDAP, found through IANA) when it was registered.
Only the registrable domain is sent (`example.com`, never the full hostname or
URL), and only when you press the button. "Very new" (30 days or less) is a
strong reason to look closer, but most listed malicious names are not new: in
the project's test only about 1 in 10 was 7 days old or less
([evidence](evidence/ML_DATASET.md)). An older site is not proof of safety; age
is context, not a verdict. Some country extensions have no public RDAP service.
A name on a shared platform where anyone can open a free name (for example `name.web.app`)
has no registry entry of its own; the result then says *Shared platform* and
names the platform, a common pattern for phishing pages.

For an IP, Quick lookup shows the network owner from the local table. Both
domains and IPs get the outside lookup buttons (VirusTotal, AbuseIPDB, urlscan).
Nothing is sent to those sites unless you click.

## Modes

- **Real CTI (default):** your own CTI cache; the lexical ML domain score is
  off. The Experimental ML tab above works in this mode.
- **Demo:** synthetic data and a synthetic model, for trying the interface. Its
  results are not measurements.

The lexical domain model is experimental and off:
[ML evaluation history](evidence/ML_DATASET.md).

## Trying it with a sample file

Any Zeek `dns.log` or `conn.log` can be uploaded on **Analyze telemetry**. To
see detections without real malware, write a few log lines whose names or IPs
are on your current CTI lists (Quick lookup shows what is listed); never
connect to them. The README screenshots were made this way.

## What ThreatFusion does not do

It is not a SIEM, EDR, IDS or malware scanner. It does not capture packets,
decrypt traffic, block connections or identify the program behind a connection.
Detection rates on real malware have not been measured yet; see the
[evidence index](README.md#evidence).
