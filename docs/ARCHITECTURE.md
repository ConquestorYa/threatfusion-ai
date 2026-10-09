# Architecture

ThreatFusion is a local, passive network investigation tool. It reads Zeek logs
and threat-intelligence (CTI) lists, and shows a queue of device → destination
groups with the reason each one may deserve attention. Suspicious destinations
are treated as data: they are never visited or resolved.

## Data flow

~~~mermaid
flowchart LR
    subgraph SENSOR["Your sensor"]
        ZEEK[Zeek: conn.log + dns.log<br/>rotated hourly]
    end
    subgraph CTI["CTI sources"]
        SGB[SGB]
        TF[ThreatFox]
        UH[URLhaus]
    end
    SGB & TF & UH -->|Setup & CTI updates| CACHE[(Local CTI cache<br/>SQLite)]
    ZEEK -->|completed files| COLLECTOR[Collector<br/>threatfusion-ai collect]
    CACHE --> COLLECTOR
    COLLECTOR --> STATE[(Private state<br/>24 h evidence)]
    STATE --> SNAPSHOT[Aliased snapshot<br/>JSON]
    SNAPSHOT --> UI[Web app<br/>Collected connections]
    UPLOAD[Uploaded file] --> ANALYSIS[One-time analysis] --> UI
    CACHE --> ANALYSIS
    CACHE --> LOOKUP[Quick lookup] --> UI
~~~

- The **collector** imports only closed Zeek files, deduplicates them with
  checkpoints, keeps a bounded evidence window in a private SQLite database and
  writes an atomic JSON snapshot after each change.
- The **web app** reads that snapshot, never the raw logs or the database. Real
  endpoint IPs are shown only on explicit request, from a separate private file.
- **CTI updates** run from the setup page (manually or every 6/12/24 h while the
  app runs). Each source updates independently; a failure keeps the old data.

## Evidence model

Evidence is kept separate by strength and is never merged into one score.

1. **Exact CTI match** (domain, URL or IP on a list): the strongest evidence;
   DNS groups become *Known threat*.
2. **CTI context** (an answer IP or a listed URL's hostname matches): shown, but
   weaker than an exact match.
3. **Behavior**: long sessions, regular repetition, failed-attempt patterns and
   DNS volume/timing signals. These raise *Review*; they are never presented as
   proof of malware. Rules: [user guide](USER_GUIDE.md#what-gets-flagged).
4. **ML score** (experimental, off by default): a lexical domain-name score,
   subordinate to CTI and behavior.

Every flagged group lists its reasons and its coverage limits (missing fields,
incomplete sessions, too few observations).

## Privacy and storage

| Stored | Not stored |
| --- | --- |
| CTI cache and refresh status | Packet contents (Zeek writes only connection and DNS metadata) |
| Collector state: typed connection/DNS records for the evidence window, checkpoints | Uploaded files and their raw rows |
| Snapshots with report-local aliases (`Host 1`, `Device 1`) | API keys, unless you choose to save them (owner-only file) |
| A private alias → IP mapping for local display | Anything outside your machine: there is no telemetry upload |

State directories are owner-only (0700, files 0600). The app binds to
127.0.0.1 and rejects requests whose Host is not local (DNS-rebinding guard).

## Main modules

| Area | Modules |
| --- | --- |
| CTI | `collectors/`, `cti_cache.py`, `cti_refresh.py`, `matching.py` |
| Collector | `telemetry_collector.py`, `collector_reports.py`, `collector_identity.py`, `log_preparation.py` |
| Detection | `connections.py`, `connection_attempts.py`, `device_triage.py`, `dns_behavior.py`, `hybrid_assessment.py` |
| Investigation views | `connection_timeline.py`, `dns_timeline.py`, `expected_connections.py` |
| Upload analysis | `dns_ingest.py`, `network_telemetry.py`, `runtime_analysis.py` and format adapters |
| Web app | `streamlit_app.py`, `ui_*.py`, `local_workspace.py`, `request_guard.py` |
| Installer | `scripts/install_linux.sh`, `scripts/bootstrap_linux.py`, `local_setup.py` |
| Experimental ML | `ml_*.py` ([evaluation history](evidence/ML_DATASET.md)) |

Design decisions and their reasons: [DECISIONS.md](dev/DECISIONS.md).
