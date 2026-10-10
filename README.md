<div align="center">

# ThreatFusion AI

### Local network investigation for Zeek users

<p>
  <strong>English</strong>
  &nbsp;•&nbsp;
  <a href="README.tr.md"><strong>Türkçe</strong></a>
</p>

<p>
  <img alt="Status: early prototype" src="https://img.shields.io/badge/Status-Early%20prototype-orange">
  <img alt="CI" src="https://github.com/ConquestorYa/threatfusion-ai/actions/workflows/ci.yml/badge.svg">
  <img alt="Python 3.12" src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white">
  <img alt="Zeek" src="https://img.shields.io/badge/Input-Zeek%20logs-2b6cb0">
  <img alt="Local only" src="https://img.shields.io/badge/Data-stays%20local-2ea44f">
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-success">
</p>

</div>

ThreatFusion reads your **Zeek** network logs, checks every destination against
**threat-intelligence (CTI) lists** and flags connections that **behave like
malware checking in**, and it tells you the reason for every flag. It runs on
your own Linux machine; your traffic never leaves it.

> **Status: early prototype.** The full workflow works and has passed the
> developer's manual acceptance on synthetic data. The first 24-hour test on real
> traffic is running now. How well it catches real malware has **not** been
> measured yet. It is not a SIEM, EDR, IDS or malware scanner.

## What it does

It answers one question: **which device talked to which destination, and which
of those conversations deserve a closer look?**

1. **Collect.** A small collector imports each completed Zeek `conn.log` and
   `dns.log` and keeps the last 24 hours.
2. **Check.** Every destination is compared with SGB, ThreatFox and URLhaus, and
   every device → destination group is checked for suspicious behavior.
3. **Explain.** Groups that deserve a look appear as **Review**, each with its
   reason, timeline and byte counts. Everything else stays visible as **Observe**.

| Check | Flags a group when | Typical cause |
| --- | --- | --- |
| CTI match | The destination is on a CTI list | Known malicious server |
| Long session | One two-way TCP session lasts at least 1 hour | Kept-open control channel, or a chat/notification app |
| Regular repetition | 20+ connections over 30+ minutes at very regular intervals | Malware check-ins, or an updater |
| Failed attempts | 20+ different ports/hosts, or 30+ repeated failures, within 5 minutes | Scanning, or a program retrying an unreachable server |

DNS logs get a separate device → domain queue (CTI matches, regular queries,
unusual volume). Normal software can match these rules too; the queue shows
evidence so you can decide quickly. Details: [user guide](docs/USER_GUIDE.md#what-gets-flagged).

## Screenshots

All screenshots use synthetic demo data with reserved test addresses and `.test` names.

<p align="center">
  <img src="docs/screenshots/collected-connections.png" alt="Collected connections: device to destination groups with Review reasons" width="100%">
</p>
<p align="center"><em>Collected connections: the review queue built from Zeek logs.</em></p>

<p align="center">
  <img src="docs/screenshots/connection-investigation.png" alt="Investigation of one connection group with a timeline of connection starts" width="100%">
</p>
<p align="center"><em>Investigating a group: connection starts over time, states and bytes.</em></p>

<table>
<tr>
<td width="50%"><img src="docs/screenshots/quick-lookup.png" alt="Quick lookup of a synthetic indicator"><br><em>Quick lookup: check one URL, domain or IP without visiting it.</em></td>
<td width="50%"><img src="docs/screenshots/setup.png" alt="Setup and CTI updates page"><br><em>Setup: your own API keys and CTI updates.</em></td>
</tr>
</table>

## Quick start

**1. Install** (Linux x86_64; Debian 12 and Ubuntu 24.04 are tested; no sudo,
Python or Git needed). Run as your normal user:

```bash
bash -c 'set -e; f=$(mktemp /tmp/threatfusion-install.XXXXXXXX); trap "rm -f -- \"$f\"" EXIT; u=https://raw.githubusercontent.com/ConquestorYa/threatfusion-ai/main/scripts/install_linux.sh; if command -v curl >/dev/null; then curl --proto "=https" --proto-redir "=https" -fsSL --retry 3 --connect-timeout 20 --max-time 300 "$u" -o "$f"; elif command -v wget >/dev/null; then wget --https-only --timeout=30 --tries=3 -qO "$f" "$u"; else echo "curl veya wget gerekli" >&2; exit 1; fi; bash "$f" "$@"' --
```

The app opens at http://127.0.0.1:8501 on the **Setup & CTI updates** page.

**2. Add CTI.** SGB works without a key. One free key from
[auth.abuse.ch](https://auth.abuse.ch/) enables both ThreatFox and URLhaus.
Click **Update CTI now**.

**3. Run Zeek** so that it writes rotated `conn.log` and `dns.log` files:
[Zeek sensor setup](docs/ZEEK_SETUP.md) (a pinned Docker recipe).

**4. Start the collector** in a second terminal and open **Collected connections**:

```bash
threatfusion-ai collect --input-dir ~/zeek-sensor/logs
```

Later: `threatfusion-ai` reopens the app, `threatfusion-ai stop` stops it.
More in [Linux installation](docs/INSTALL_LINUX.md).

## Also in the app

- **Quick lookup:** check one URL, domain or IP against your CTI cache. No page
  visit, no DNS lookup, no download.
- **Analyze telemetry:** upload a single file (Zeek, DNS CSV/Excel, PCAP,
  Suricata EVE, Pi-hole, AdGuard Home, dnstop) for a one-time analysis.
- **Demo mode** (`threatfusion-ai --mode demo`): synthetic data to try the
  interface. Its results are not measurements.

An experimental machine-learning domain score exists but is **off**: the
measured original model is unavailable and its successor produced too many
false alarms ([evaluation history](docs/evidence/ML_DATASET.md)).

## Privacy

- Zeek is configured to log connection and DNS metadata only; no page addresses,
  passwords or contents. DNS names still reveal which sites you visit: keep logs
  private.
- Logs, collector state, CTI cache and keys stay in private folders on your
  machine. Nothing is uploaded. Downloads use aliases (`Host 1`) by default.
- Suspicious destinations are never visited or resolved.
- You use your own API keys; none are bundled.

## Evidence so far

| Measured | Result |
| --- | --- |
| Synthetic normal and simulated traffic | Normal updaters and polling also enter Review: the rules are not yet selective enough ([review workload](docs/evidence/REVIEW_WORKLOAD.md)) |
| Four independent IoT-23 captures (2018–2019) | 0 reviews in two benign captures; one of two malicious captures produced one review, the other none ([network evaluation](docs/evidence/NETWORK_EVALUATION.md)) |
| Fault matrix, 6-hour soak, security reviews | 9/9 fault cases pass; after a memory fix the 6-hour soak passed 16/16 checks (collector peak 684 MiB); two security reviews ([operational confidence](docs/evidence/OPERATIONAL_CONFIDENCE.md)) |
| **Not yet measured** | False alarms on real traffic (running), detection of labeled real malware, usefulness for other users |

Plan: [real-traffic evaluation](docs/evidence/REAL_TRAFFIC_EVALUATION.md). All
records: [documentation](docs/README.md#evidence).

## Related tools

[RITA](https://github.com/activecm/rita) finds beaconing and long connections in
Zeek logs and is the baseline ThreatFusion is compared against.
[Security Onion](https://securityonion.net/) and [Malcolm](https://github.com/cisagov/Malcolm)
are complete monitoring platforms; [Suricata](https://suricata.io/) detects known
attack signatures. ThreatFusion aims to be smaller: one local app that combines
CTI (including Türkiye's SGB list) with explainable behavior checks. Whether it
is more useful than these tools has not been measured.

## Documentation

[User guide](docs/USER_GUIDE.md) · [Zeek setup](docs/ZEEK_SETUP.md) ·
[Installation](docs/INSTALL_LINUX.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Data sources](docs/DATA_SOURCES.md) · [Evidence](docs/README.md#evidence) ·
[Product plan](docs/dev/PRODUCT_PLAN.md)

## Development

Python 3.12, Streamlit, SQLite, pandas, Plotly. CI runs lint, tests, a privacy
audit of the repository, Windows compatibility tests, a container check and
first-run installs on Debian and Ubuntu.

This project is developed with extensive AI assistance (design, code, tests and
documentation); changes are reviewed and tested before they are merged.

## License

MIT. CTI feeds and datasets keep their own terms; see
[data sources](docs/DATA_SOURCES.md).
