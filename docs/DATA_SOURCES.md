# Data Sources, Attribution, and Redistribution Notes

This repository aggregates indicators and network/DNS telemetry for local investigation.
Treat all threat indicators as inert data only.

## Verified source endpoints used in code

| Source | Purpose | Endpoint / reference in repo |
| --- | --- | --- |
| ThreatFox (abuse.ch) | Malicious IOC feed collection | `src/threatfusion/collectors/threatfox.py` (full current export + recent API fallback) |
| URLhaus (abuse.ch) | Malware-distribution URL feed collection | `src/threatfusion/collectors/urlhaus.py` (full database dump) |
| SGB (T.C. Siber Güvenlik Başkanlığı) | Malicious address feed collection | `src/threatfusion/collectors/sgb.py` (`SGB_API_URL`) |
| Tranco | Benign-domain baseline input | `src/threatfusion/collectors/tranco.py` (`TrancoCollector`) |
| CESNET / DomainRadar 2024 | Real-traffic benign-domain evaluation corpus | DOI `10.5281/zenodo.14332167`; `scripts/sample_cesnet_benign_domains.py` |
| Local network/DNS telemetry (user-provided) | Runtime analysis input | CSV/TSV/TXT, Excel, Zeek, PCAP/PCAPNG, Suricata EVE, Pi-hole, AdGuard and dnstop ingestion modules |

## Attribution requirements

- Preserve source attribution when presenting aggregated findings.
- Do not imply ThreatFusion AI owns third-party feed content.
- Keep feed-specific source names in evidence/report output where available.

## Redistribution and licensing status

Verified from current official source documentation:

- The code contains feed endpoints and ingestion logic; it does **not** bundle a
  copy of the live ThreatFox, URLhaus, SGB, or Tranco datasets.
- ThreatFox and URLhaus are abuse.ch platforms governed by the abuse.ch Terms of
  Use and Fair Use Principles. The community APIs are intended for authenticated
  non-profit/fair-use access; commercial or for-profit use may require a
  Spamhaus subscription. See:
  - https://abuse.ch/terms-of-use/
  - https://threatfox.abuse.ch/api/
  - https://urlhaus.abuse.ch/api/
- PhishTank was removed on 2026-10-09 (DEC-089). It no longer issues new
  application keys, and since 2026-10-07 its keyless public URL redirected
  (HTTP 302) to a `cdn.phishtank.com` path answering HTTP 404 with an image.
  Its collector, key field and status card are gone; the next refresh deletes
  any PhishTank rows from older local caches.
- The SGB API documentation explicitly describes automated integration of its
  malicious-address intelligence into security products/systems, but this
  repository does not rely on that statement as a broad redistribution license.
  See: https://siberguvenlik.gov.tr/api/
- Tranco publishes reproducible downloadable rankings assembled from multiple
  upstream providers whose stated licenses differ. ThreatFusion therefore does
  not treat the combined ranking as a repository asset to redistribute. See:
  https://tranco-list.eu/
- The CESNET/DomainRadar 2024 dataset is published under CC BY 4.0. ThreatFusion
  stores attribution and locally sampled evaluation inputs only; no CESNET
  corpus is committed to the repository.

Public-demo policy:

- do not publish raw third-party feed dumps or the developer's live CTI cache
- generate the hosted demo cache with
  `scripts/generate_public_demo_cti_cache.py`
- the synthetic public-demo cache contains only reserved documentation values,
  not ThreatFox, URLhaus, SGB, Tranco, or CESNET records
- keep source attribution when presenting results derived from locally fetched
  third-party data

This is a conservative release boundary, not a legal conclusion about
every possible redistribution scenario.

## Telemetry privacy notes

- User-uploaded network/DNS telemetry is analyzed locally/in-memory by default.
- Public release preparation must not include private telemetry exports, local analyst history, or secrets.

## Local CTI cache lifecycle

A successful refresh no longer deletes indicators that disappeared from the
latest source snapshot. The cache keeps them as inactive lifecycle history and
records when an indicator was first cached and last observed in a successful
refresh. Runtime matching loads active indicators only by default.

This lifecycle state describes ThreatFusion's local cache observations. It must
not be confused with a feed's own IOC `first_seen` / `last_seen` metadata.

SGB collection is bounded by a caller-controlled maximum page count and stops
earlier when the API reports that all rows were collected or returns an empty
page. A scheduled refresh refuses to replace the previous SGB snapshot when the
configured page bound is reached before the source end.

ThreatFox refreshes use its full current export rather than only the 1-7 day
recent-IOC API window. URLhaus refreshes use its full malware URL dump. This
prevents Quick lookup coverage from shrinking to only recently added IOCs.

Quick lookup does not load the complete active CTI dataset into Python. The
SQLite cache stores normalized lookup keys and indexed URL hostnames so a
single URL/domain query retrieves only relevant candidate indicators.



## CESNET benign-corpus attribution

The long-tail benign evaluation helper references the 2024 DomainRadar dataset:

- Hranický et al., *A Dataset of Information (DNS, IP, WHOIS/RDAP, TLS, GeoIP) for a Large Corpus of Benign, Phishing, and Malware Domain Names 2024*
- DOI: `10.5281/zenodo.14332167`
- subset: `benign_cesnet.json`
- published license: CC BY 4.0

The CESNET subset was derived from real academic-network traffic and filtered
by the dataset authors. ThreatFusion uses it only as a benign-labeled
domain-string evaluation corpus. It is not represented as raw DNS telemetry or
as a production query-frequency distribution.
