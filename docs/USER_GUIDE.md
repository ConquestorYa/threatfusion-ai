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
| **Analysis history** / **Model evaluation** | Only in modes that run the experimental ML model; hidden in the default CTI-only mode. |

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
- ML is not used here.

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

Groups that need a look appear as **Review**; everything else stays visible as
**Observe**. A connection with a CTI match is marked and always shown, even when
its behavior is Observe; DNS groups with a CTI match go to the top as
**Investigate**. Failed-attempt patterns have their own list. Normal software also matches these
rules: updaters repeat on timers, chat and notification apps keep long sessions.
That is why each row explains its reason, and why the result is a queue to check
rather than an alarm.

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

## Modes

- **Real CTI (default):** your own CTI cache; ML is off.
- **Demo:** synthetic data and a synthetic model, for trying the interface. Its
  results are not measurements.

The ML model (a lexical domain score) is experimental and currently off:
[ML evaluation history](evidence/ML_DATASET.md).

## What ThreatFusion does not do

It is not a SIEM, EDR, IDS or malware scanner. It does not capture packets,
decrypt traffic, block connections or identify the program behind a connection.
Detection rates on real malware have not been measured yet; see the
[evidence index](README.md#evidence).
