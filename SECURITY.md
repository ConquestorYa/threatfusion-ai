# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in ThreatFusion AI, please report it privately by opening a GitHub Security Advisory draft in this repository:

- Repository -> **Security** -> **Advisories** -> **Report a vulnerability**

If GitHub Security Advisories are unavailable, open a private issue with the repository owner and avoid posting exploit details publicly until triage is complete.

Please include:

- affected component/file
- reproduction steps
- expected vs actual behavior
- potential impact
- any suggested remediation

## Response Expectations

- Initial acknowledgement target: **within 7 days**
- Triage/update target: **within 14 days**
- Fix timeline: depends on severity, complexity, and maintainer availability

## Scope

In scope:

- vulnerabilities in repository source code, scripts, or container packaging
- security-impacting issues in data parsing, storage, export, or deployment defaults

Out of scope:

- requests to run active scans against third-party systems
- reports requiring access to private telemetry that cannot be shared safely

## Safe Handling Expectations

To protect users and maintainers:

- do not include secrets, API keys, or private telemetry in reports
- treat threat URLs/domains/IPs/hashes as inert text data only
- avoid public disclosure until maintainers confirm remediation or mitigation guidance
