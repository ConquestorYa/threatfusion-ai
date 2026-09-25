# Data Sources, Attribution, and Redistribution Notes

This repository aggregates indicators and DNS telemetry for educational analysis.
Treat all threat indicators as inert data only.

## Verified source endpoints used in code

| Source | Purpose | Endpoint / reference in repo |
| --- | --- | --- |
| ThreatFox (abuse.ch) | Malicious IOC feed collection | `src/threatfusion/collectors/threatfox.py` (`THREATFOX_API_URL`) |
| URLhaus (abuse.ch) | Malicious URL feed collection | `src/threatfusion/collectors/urlhaus.py` (`URLHAUS_EXPORT_URL`) |
| SGB (T.C. Siber Güvenlik Başkanlığı) | Malicious address feed collection | `src/threatfusion/collectors/sgb.py` (`SGB_API_URL`) |
| Tranco | Benign-domain baseline input | `src/threatfusion/collectors/tranco.py` (`TrancoCollector`) |
| Local DNS telemetry (user-provided) | Runtime analysis input | CSV/Zeek/Pi-hole/AdGuard ingestion modules |

## Attribution requirements

- Preserve source attribution when presenting aggregated findings.
- Do not imply ThreatFusion AI owns third-party feed content.
- Keep feed-specific source names in evidence/report output where available.

## Redistribution and licensing status

Verified in this repository:

- The code contains feed endpoints and ingestion logic.
- The code does **not** include a bundled copy of full third-party feed datasets.

Not yet verified in this repository (requires owner/legal review):

- exact redistribution permissions for each feed's raw IOC data
- any attribution text requirements for public redistribution of derived datasets
- any usage constraints for commercial/public-hosted reuse

Until verified:

- treat third-party feed data as externally governed content
- avoid publishing raw feed dumps from this project
- publish only minimal, attribution-preserving, portfolio-safe derived examples

## Telemetry privacy notes

- User-uploaded DNS telemetry is analyzed locally/in-memory by default.
- Public release preparation must not include private telemetry exports, local analyst history, or secrets.
