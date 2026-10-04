# Security Policy

## Reporting a Vulnerability

If you discover a potential security issue in ThreatFusion AI, please report it privately by opening a GitHub Security Advisory draft in this repository:

- Repository -> **Security** -> **Advisories** -> **Report a vulnerability**

If private vulnerability reporting is unavailable, contact the repository owner through a private channel listed on their GitHub profile. If no private channel is available, do not post secrets, private telemetry, or exploit details in a public issue.

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

CTI credentials must belong to the user running the application. There is no
bundled developer key or shared fallback. The Linux first-run profile keeps
keys out of installation metadata and the Streamlit child environment. The
default demo requires no key; missing keys skip the corresponding keyed feed.
Refresh diagnostics omit raw exception text and authenticated URLs. `.env`,
Streamlit `secrets.toml` and private-key files must remain local; the release
audit rejects them in both tracked files and reachable Git history. Private
CTI/dataset/model/telemetry files must not be distributed.

To protect users and maintainers:

- do not include secrets, API keys, or private telemetry in reports
- treat threat URLs/domains/IPs/hashes as inert text data only
- avoid public disclosure until maintainers confirm remediation or mitigation guidance
