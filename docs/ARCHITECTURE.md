# Architecture

ThreatFusion AI is a local-first educational cyber threat-analysis platform that combines public CTI, user-provided telemetry, deterministic matching, an auxiliary domain ML model, behavior signals, and analyst context.

The runtime is intentionally passive: suspicious URLs and domains are treated as data and are not visited or resolved during analysis.

Expected connection context is a separate presentation/export layer after
detection. A bounded local JSON declaration must match exact endpoints, complete
session evidence, validity and traffic limits; scoped CTI overrides it. It does
not mutate runtime findings, thresholds or persisted history. The UI hides
matching expected groups only through a reversible view filter. All groups stay
in schema-v2 connection exports, with rule configuration/IDs omitted. See
[expected connection contracts](EXPECTED_CONNECTIONS.md).

Connection policy v2 retains additional S2/S3/RSTO/RSTR payload evidence with
existing long/timing gates, while preserving SF/S1 confirmed-session semantics
for analyst declarations. Additive report columns expose payload eligibility,
reset/incomplete endings and failed/half-open attempts; raw record/state schemas
remain compatible. See [coverage and reserved evaluation](TCP_TERMINATION.md).

## System overview

An optional local Linux collector provides a second ingestion path: completed
Zeek TSV/gzip archives → bounded typed SQLite evidence/checkpoints → existing
separate connection and TCP/UDP DNS device analysis with the user's cached CTI → schema-v2 aliased atomic
snapshot → local Collected connections fragment. Source and state are private,
one sensor per state; ingestion does not visit destinations or collect CTI feeds.
The web process reads the bounded snapshot and, on explicit full-download request,
its exact hash-verified private gzip generation; it does not read raw logs or
SQLite evidence. Large connection snapshots disclose omissions and full-retained
counts. ML is disabled on this path. See
[collector limits and lifetime](TELEMETRY_COLLECTOR.md).
Private state schema 2 upgrades after a schema-1 backup. DNS reconciliation uses
UID/transaction/time and full-row hash conflicts; it does not join hostnames to
flows. DNS snapshots cap prioritized groups independently and disclose omissions.
See [DNS collection](DNS_COLLECTION.md).

~~~mermaid
flowchart LR
    subgraph SOURCES["CTI Sources"]
        TF[ThreatFox]
        UH[URLhaus]
        PT[PhishTank]
        SGB[SGB]
    end

    subgraph TELEMETRY["Telemetry Inputs"]
        T1[CSV / TSV / TXT]
        T2[XLSX / XLS]
        T3[Zeek dns.log]
        T4[Zeek conn.log]
        T5[PCAP / PCAPNG]
        T6[Suricata EVE]
        T7[Pi-hole FTL]
        T8[AdGuard Home]
        T9[dnstop]
    end

    TF --> NORM[IOC normalization]
    UH --> NORM
    PT --> NORM
    SGB --> NORM
    NORM --> CACHE[(SQLite CTI cache)]

    T1 --> INGEST[Auto-detect ingestion]
    T2 --> INGEST
    T3 --> INGEST
    T4 --> INGEST
    T5 --> INGEST
    T6 --> INGEST
    T7 --> INGEST
    T8 --> INGEST
    T9 --> INGEST

    CACHE --> RUNTIME[Runtime analysis]
    INGEST --> RUNTIME
    MODEL[Frozen trusted ML artifact] --> RUNTIME

    RUNTIME --> MATCH[IOC evidence]
    RUNTIME --> ML[Domain ML score]
    RUNTIME --> BEHAVIOR[Behavior context]

    MATCH --> HYBRID[Explainable hybrid assessment]
    ML --> HYBRID
    BEHAVIOR --> HYBRID

    HYBRID --> UI[Streamlit analyst workspace]
    HYBRID --> EXPORT[Privacy-safe JSON / CSV]
    HYBRID -. explicit local save .-> HISTORY[(Aggregate analysis history)]
~~~

## Trust and evidence model

ThreatFusion separates evidence by strength.

### 1. Deterministic known-indicator evidence

The strongest runtime evidence is an exact known IOC relationship.

Examples:

- exact domain IOC against the normalized query domain;
- exact URL IOC in Quick Lookup;
- exact IP IOC in Quick Lookup;
- response-IP or IPv6-network evidence when telemetry contains response infrastructure.

Known-domain evidence can produce a <code>known_threat</code> verdict. Contextual infrastructure evidence does not automatically prove the queried domain is malicious.

### 2. Contextual CTI evidence

Examples:

- a queried hostname appears inside a malicious URL IOC;
- a DNS response IP matches a known malicious IP;
- an address falls inside a typed IPv6 network IOC.

These relationships are preserved and shown to the analyst, but they are intentionally weaker than an exact malicious-domain match.

### 3. ML signal

Eligible public domain names can be scored by a trusted local character n-gram TF-IDF + Logistic Regression artifact.

The score is:

- local;
- lexical;
- auxiliary;
- uncalibrated;
- subordinate to stronger deterministic evidence.

Invalid domains, IP literals, reverse-DNS names, local names and other ineligible targets are not forced through the domain-string model.

### 4. Behavior context

DNS telemetry can contribute explainable context such as:

- query volume;
- client spread;
- NXDOMAIN ratio;
- response-IP diversity/churn;
- query-type diversity;
- hostname shape;
- periodic timing.

Behavior rules can raise review priority, but they are not represented as malware proof.

## CTI subsystem

### Collectors

Implemented collectors:

- <code>collectors/threatfox.py</code>
- <code>collectors/urlhaus.py</code>
- <code>collectors/phishtank.py</code>
- <code>collectors/sgb.py</code>

All map supported values into the shared <code>IOCRecord</code> model.

### Cache

The SQLite cache stores:

- active IOC records;
- normalized lookup keys;
- indexed URL hostnames;
- source refresh metadata;
- inactive lifecycle history.

Quick Lookup uses indexed candidate retrieval instead of loading the entire CTI cache into Python.

### Refresh lifecycle

Feed refresh is separate from user analysis.

- ThreatFox / URLhaus / SGB can refresh when stale.
- PhishTank's public feed is limited to a 24-hour minimum refresh interval.
- failed or empty refreshes preserve the previous healthy snapshot;
- inactive lifecycle records are pruned after 90 days.

A separate maintenance scheduler is preferred in hosted deployments. A process-local background refresher exists as a low-cost fallback.

## Telemetry ingestion

The default dashboard path is automatic format detection.

Supported inputs:

- delimited CSV / TSV / TXT tables;
- XLSX / XLS workbooks;
- Zeek <code>dns.log</code>;
- Zeek <code>conn.log</code>;
- PCAP / PCAPNG / CAP;
- Suricata EVE JSON / JSONL;
- Pi-hole FTL SQLite;
- AdGuard Home query logs;
- dnstop-style domain summaries.

<code>.capinfos</code> is recognized as capture metadata and is not treated as packet telemetry.

### PCAP boundary

Packet-capture support extracts classic UDP/53 DNS observations. ThreatFusion does not claim to recover encrypted DoH/DoT domain names from captures.

### Zeek conn.log boundary

Connection logs do not contain DNS query names. ThreatFusion maps destination IP observations into passive CTI analysis targets. Any dataset-provided benign/malicious labels are ignored by the detector.

The standard TSV adapter also retains typed UID, endpoint ports, observation
direction, duration, payload-byte counts, state and capture-gap metadata.
`connections.py` groups originator/responder/protocol/responder-port separately,
excludes repeated/conflicting UIDs and exposes a conservative Review queue for
long bidirectional TCP or sustained successful connection timing. It does not
infer DNS hostnames, inbound/outbound direction, file transfers or malware.
The separate connection view/export defaults to report-local host aliases and
does not persist raw rows or connection IDs in aggregate history. See
`DETECTION_ROADMAP.md` for policy and measured coverage limits.

### Resource bounds

The Streamlit upload limit is 100 MB.

After parsing, upload/legacy runtime analysis enforces bounded workloads:

- maximum 100,000 events;
- maximum 25,000 unique analysis targets.

These bounds are independent of the browser upload limit.
Collector connection IP analysis uses the shared 100k retained-record bound
independently of the DNS 25k-name limit. Its connection snapshot holds 1,000
groups; full JSON.gz is bounded to 256 MiB expanded / 64 MiB compressed. See
[capacity contracts](CONNECTION_CAPACITY.md).

## Runtime analysis

The runtime orchestration layer combines:

1. parsed telemetry;
2. active CTI records;
3. a trusted local ML artifact;
4. DNS behavior aggregation;
5. hybrid assessment.

The pipeline performs no destination visits or DNS resolution.

Outputs include:

- normalized findings;
- IOC evidence;
- ML score/tier where eligible;
- behavior aggregates;
- explainable verdict reasons;
- related-activity context.

## Related activity

ThreatFusion does not claim campaign attribution.

Potential related-activity groups require shared local evidence such as:

- shared client observations;
- shared response infrastructure.

High-fan-out infrastructure is suppressed or penalized, and time/CTI metadata are supporting signals rather than pair-creation evidence.

The result is an analyst prioritization aid, not an attribution probability.

## Persistence and privacy

### Stored by default

- CTI cache and refresh metadata;
- trusted local model artifacts;
- optionally saved aggregate analysis history;
- optional analyst labels/notes;
- optional local suppression policy.

### Not stored by default

- raw uploaded telemetry rows;
- raw client-IP telemetry in analysis history;
- uploaded packet-capture bytes;
- raw telemetry exports.

Portable JSON/CSV reports omit raw client and response IP values.

Public mode disables shared history saving and browsing.

## Quick Lookup

Quick Lookup accepts a single:

- URL;
- domain;
- IPv4/IPv6 address.

It is passive and does not:

- open a URL;
- resolve a hostname;
- download page content.

The indexed CTI cache is checked first. The ML model is used only when the target host is an eligible domain name.

## ML development flow

~~~mermaid
flowchart LR
    CTI[Malicious-domain evidence] --> SNAP[Reproducible snapshot]
    BENIGN[Tranco / evaluated benign corpora] --> SNAP
    SNAP --> SPLIT[Train / validation / development test]
    SPLIT --> TFIDF[Character 2-6 TF-IDF]
    TFIDF --> LR[Balanced Logistic Regression]
    LR --> THR[Validation-selected FPR thresholds]
    THR --> ARTIFACT[Frozen artifact]
    ARTIFACT --> HOLDOUT[Fresh / temporal holdout evaluation]
~~~

Model experimentation and runtime inference are separated.

The current release position is documented in <code>ML_DATASET.md</code>. The
earlier character-only C=4 candidate has a completed historical temporal
holdout. A reconstructed lexical C=4 candidate was also evaluated on a new
untouched post-freeze holdout, but its false-positive rate was operationally
unusable, so it remains separate from the runtime default.

## Presentation layer

<code>streamlit_app.py</code> provides:

- system/CTI status;
- Quick Lookup;
- telemetry upload and auto-detection;
- priority triage;
- evidence-first investigation;
- source corroboration;
- related activity;
- analyst feedback and local suppression;
- analysis history in local mode;
- model-evaluation views;
- privacy-safe export.

## Deployment boundary

The project includes:

- non-root Docker packaging;
- public mode;
- environment-configurable runtime paths;
- sanitized demo/runtime builders;
- Streamlit health checks;
- scheduled CTI-refresh guidance.

The public interactive process should not require feed credentials when a prepared cache is supplied. A separate maintenance job is preferred.

See <code>DEPLOYMENT.md</code> for the complete hosting model.

## Main implementation modules

| Area | Key modules |
| --- | --- |
| IOC model / normalization | <code>models.py</code>, <code>normalization.py</code>, <code>correlation.py</code> |
| CTI collection / cache | <code>collectors/</code>, <code>cti_cache.py</code>, <code>cti_refresh.py</code> |
| Telemetry ingestion | <code>dns.py</code>, <code>dns_ingest.py</code>, <code>network_telemetry.py</code>, format-specific adapters |
| Matching | <code>matching.py</code>, <code>quick_lookup.py</code> |
| ML | <code>ml_*.py</code>, <code>ml_artifact.py</code> |
| Behavior / verdict | <code>dns_behavior.py</code>, <code>hybrid_assessment.py</code> |
| Runtime | <code>runtime_analysis.py</code> |
| Related activity | <code>campaign.py</code> |
| Persistence / reporting | history modules, <code>reporting.py</code>, <code>audit.py</code> |
| UI | <code>streamlit_app.py</code>, <code>ui_*.py</code> |
| Deployment | <code>deployment_bundle.py</code>, demo/runtime generation scripts |

## Design principle

> **Known IOC evidence is deterministic context. ML is an auxiliary unknown-domain signal. Behavior is explainable context. Analyst review remains part of the workflow.**
