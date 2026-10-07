<div align="center">

# 🛡️ ThreatFusion AI

### Local-first cyber threat intelligence, network telemetry triage, and explainable ML

<p>
  <strong>English README</strong>
  &nbsp;•&nbsp;
  <a href="README.tr.md"><strong>🇹🇷 Türkçe README — Buraya tıkla</strong></a>
</p>

<p>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white">
  <img alt="Streamlit" src="https://img.shields.io/badge/Streamlit-1.64-FF4B4B?logo=streamlit&logoColor=white">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-ML-F7931E?logo=scikitlearn&logoColor=white">
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-CTI%20Cache-003B57?logo=sqlite&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-success">
</p>

<p>
  <img alt="CI" src="https://github.com/ConquestorYa/threatfusion-ai/actions/workflows/ci.yml/badge.svg">
  <img alt="Status" src="https://img.shields.io/badge/Status-v0.1.0%20Release%20Candidate-blueviolet">
  <img alt="Privacy" src="https://img.shields.io/badge/Telemetry-local%20%2F%20in--memory-2ea44f">
  <img alt="Development style" src="https://img.shields.io/badge/Development-AI--assisted%20Vibe%20Coding-6f42c1">
</p>

<strong>ThreatFusion AI turns public threat intelligence and local telemetry into an analyst-focused investigation queue without visiting suspicious destinations.</strong>

</div>

---

## ✨ Why ThreatFusion AI?

Threat feeds are useful, but a feed alone does not answer the analyst's real question:

> **“Which threats actually appeared in my environment, and what deserves attention first?”**

ThreatFusion combines four evidence layers in one local workflow:

| Layer | Role |
| --- | --- |
| 🧭 **Threat Intelligence** | Deterministic matching against ThreatFox, URLhaus, PhishTank and SGB |
| 🧠 **Machine Learning** | Auxiliary lexical risk scoring for previously unseen domain names |
| 📡 **Telemetry Behavior** | DNS volume, NXDOMAIN, response-IP churn, timing and client-spread context |
| 🔎 **Analyst Context** | Explainable verdicts, prior review, suppression, history and related activity |

The project is intentionally built as an **educational / portfolio security-analysis prototype**. It is not presented as a production SIEM, EDR, or guaranteed malware detector.

### 🤖 Development approach: AI-assisted vibe coding

> **This project was developed with an AI-assisted “vibe coding” workflow.** AI tools were used extensively for rapid prototyping, implementation, refactoring, debugging, testing, and documentation. Generated changes were reviewed, tested, and refined before being merged.

---

## 🚀 At a glance

<table>
<tr>
<td width="50%">

### ⚡ Quick Lookup
Paste a **URL, domain, or IP** and check it against the local indexed CTI cache.

- passive only
- no page visit
- no DNS resolution
- exact URL / domain / IP evidence
- hostname context for malicious URLs
- domain ML only when the target is a valid domain

</td>
<td width="50%">

### 📂 Telemetry Analysis
Upload network or DNS telemetry and let ThreatFusion auto-detect the format.

- IOC correlation
- explainable hybrid verdicts
- domain ML scoring
- DNS behavior signals
- related-activity clustering
- privacy-safe report export

</td>
</tr>
<tr>
<td width="50%">

### 🗃️ Multi-source CTI
Local SQLite cache with source freshness, lifecycle history and indexed lookup.

- ThreatFox
- URLhaus
- PhishTank — verified & online
- T.C. Siber Güvenlik Başkanlığı (SGB)

</td>
<td width="50%">

### 🧪 Reproducible ML
Character n-gram TF-IDF + Logistic Regression with frozen artifacts and explicit FPR budgets.

- train / validation / test separation
- source-aware diagnostics
- fresh holdout workflow
- no automatic model promotion
- scores are not advertised as malware probabilities

</td>
</tr>
</table>

---

## 🖼️ Interface preview

> Screenshots are captured from the real Streamlit interface using the **synthetic public-demo runtime**. No live CTI credentials, private telemetry, or personal data are shown.

### ⚡ Passive Quick Lookup

<p align="center">
  <img src="docs/screenshots/quick-lookup.png" alt="ThreatFusion AI passive Quick Lookup showing a synthetic known-threat result" width="100%">
</p>

### 📡 Telemetry analysis overview

<p align="center">
  <img src="docs/screenshots/telemetry-overview.png" alt="ThreatFusion AI telemetry analysis priority findings and overview" width="100%">
</p>

### 🔎 Evidence-first domain investigation

<p align="center">
  <img src="docs/screenshots/investigation.png" alt="ThreatFusion AI evidence-first domain investigation workspace" width="100%">
</p>

---

## 🧩 Architecture

~~~mermaid
flowchart LR
    subgraph CTI["Threat Intelligence"]
        TF[ThreatFox]
        UH[URLhaus]
        PT[PhishTank]
        SGB[SGB]
    end

    subgraph INPUT["Telemetry"]
        CSV[CSV / TSV / TXT]
        XLS[Excel]
        ZEEK[Zeek dns.log / conn.log]
        PCAP[PCAP / PCAPNG]
        SURI[Suricata EVE]
        PI[Pi-hole]
        AG[AdGuard Home]
        DST[dnstop]
    end

    TF --> CACHE[(SQLite CTI Cache)]
    UH --> CACHE
    PT --> CACHE
    SGB --> CACHE

    CSV --> INGEST[Auto-detect + normalize]
    XLS --> INGEST
    ZEEK --> INGEST
    PCAP --> INGEST
    SURI --> INGEST
    PI --> INGEST
    AG --> INGEST
    DST --> INGEST

    CACHE --> ANALYZE[Runtime Analysis]
    INGEST --> ANALYZE
    MODEL[Frozen ML Artifact] --> ANALYZE

    ANALYZE --> IOC[IOC Evidence]
    ANALYZE --> ML[ML Signal]
    ANALYZE --> DNS[Behavior Signals]

    IOC --> VERDICT[Explainable Hybrid Verdict]
    ML --> VERDICT
    DNS --> VERDICT

    VERDICT --> UI[Streamlit Analyst Workspace]
    VERDICT --> REPORT[Privacy-safe JSON / CSV]
~~~

### Evidence precedence

ThreatFusion deliberately avoids treating every signal as equally strong.

1. **Exact known IOC evidence** is deterministic evidence.
2. **URL-hostname / response-IP matches** are contextual CTI evidence.
3. **ML** is an auxiliary signal for eligible domains not already known to CTI.
4. **Behavior heuristics** add context or trigger review; they are not malware proof.

This distinction is one of the project's main design principles.

---

## 📥 Supported telemetry

The dashboard defaults to **Auto-detect**.

| Input | Support | Notes |
| --- | :---: | --- |
| CSV / TSV / TXT | ✅ | delimiter, encoding and DNS columns inferred automatically |
| XLSX / XLS | ✅ | worksheet and common DNS columns detected automatically |
| Zeek <code>dns.log</code> | ✅ | standard <code>#fields</code> parsing |
| Zeek <code>conn.log</code> | ✅ | destination-IP CTI, typed connection metadata and conservative review; dataset labels are ignored |
| PCAP / PCAPNG / CAP | ✅ | classic UDP/53 DNS extraction |
| Suricata EVE JSON / JSONL | ✅ | DNS preferred, destination-IP fallback |
| Pi-hole FTL SQLite | ✅ | query database parsed in memory |
| AdGuard Home | ✅ | query-log JSON formats |
| dnstop text | ✅ | recognizable domain rows |
| <code>.capinfos</code> | ℹ️ | recognized as metadata; upload the original PCAP/PCAPNG instead |

**Upload limit:** 100 MB  
**Upload/runtime safety bounds:** 100,000 events and 25,000 unique analysis targets.
The completed-log collector separately supports diverse connection IPs within
its shared 100,000-record window. Large connection reports use a 1,000-group
snapshot with exact omissions and a verified private full JSON.gz export.
See [capacity and remaining limits](docs/CONNECTION_CAPACITY.md).
The [multi-day protocol](docs/MULTIDAY_COLLECTION.md) separately checks rotation,
retention, collector resource use and recovery using accelerated synthetic time.

Encrypted DNS such as DoH/DoT is not claimed to be recoverable from packet captures.

The **Device triage** tab separately evaluates observed clients and targets,
scopes CTI evidence to the matching client, and adds sustained DNS regularity to
a review queue without declaring malware. IP addresses are hidden by default;
the explicit device report uses report-local aliases. See the
[detection roadmap and evidence limits](docs/DETECTION_ROADMAP.md) and
[local lab controls](docs/LOCAL_LAB.md). Competitive RITA coverage is a development
goal, not a current accuracy or parity claim.

**Connection activity** adds duration, observation direction, byte totals and
successful TCP timing review from standard Zeek TSV. Long/periodic connections
can also be legitimate; this queue does not prove C2 or downloads. Both endpoint
IPs are hidden by default in its separate export. The CLI accepts
`--format zeek-conn --connection-json-output /path/outside/repo/review.json`.

Policy v2 also retains bidirectional payload from incomplete TCP closes and
reset endings, and separately shows failed/half-open attempt counts. Existing
duration/timing gates still apply. See [termination coverage and reserved
comparison](docs/TCP_TERMINATION.md); new real-source Review counts match baseline.

**Connection investigation** lets you select a group and inspect bounded UTC
connection-start timelines, Zeek states and known/unknown byte counts. Available
for uploads and the automatic collector; all findings remain in exports. See
[workflow, privacy limits and two live packet controls](docs/CONNECTION_INVESTIGATION.md).

**TCP attempt reviews** now groups failed attempts across ports/responders and
repeated failures within a sliding five-minute window. Benign inventory scans
and outages can also match. [Rules, live controls and remaining real-source
coverage gap](docs/TCP_ATTEMPT_REVIEW.md) explain the scope.

Optional [expected connection declarations](docs/EXPECTED_CONNECTIONS.md) separate
locally verified operational expectations from unexplained reviews. Exact
endpoints, traffic limits and expiry are required; CTI conflicts stay visible.
This context does not verify software identity or remove original evidence.

Linux installations can continuously import **completed** Zeek TSV connection
and TCP/UDP DNS logs with `threatfusion-ai collect --input-dir /absolute/path/to/zeek/logs`.
**Collected connections** refreshes locally; checkpoints survive restarts and
rotation/gzip copies are deduplicated. Active files wait for closure/rotation.
See [collector setup and limits](docs/TELEMETRY_COLLECTOR.md) and
[independent IoT-23 coverage results](docs/NETWORK_EVALUATION.md), including
missed scenarios. This path uses your existing CTI cache and no ML model.
The **Collected DNS observations** section adds an independent client/domain
queue, transaction-aware dedup/conflict coverage and bounded private exports.
Schema-1 state is backed up before upgrading; DNS queries do not prove downloads.
See [DNS workflow, migration and two new live controls](docs/DNS_COLLECTION.md).
Large completed logs can be prepared locally with `threatfusion-ai prepare-logs`.
Explicit incomplete-DNS quarantine preserves raw rows privately and shows coverage
counts; it does not increase the 100k retained-record limit. See
[safe preparation and current limits](docs/LOG_PREPARATION.md).
Select a device/domain for UTC query and response-code timelines; collection
reports scan/rejection status and preserves selections while mappings match.
See [investigation and rotation/recovery checks](docs/DNS_INVESTIGATION.md).
The [analyst review workflow](docs/ANALYST_REVIEW.md) adds bilingual selected-group
evidence and next checks, original/context counts before filters, and reversible
expected activity with CTI precedence. Complete synthetic replays verify context,
expiry and collector reconciliation; human effectiveness remains unmeasured.

The [review-workload comparison](docs/REVIEW_WORKLOAD.md) measures normal
updates, caching, shared resolvers and timing gaps against optional native RITA.
Normal traffic also enters review; two truncated official sources are explicitly
excluded. These measurements do not establish malware accuracy or RITA parity.

---

## 🧠 Machine-learning position

ThreatFusion uses a classical lexical model rather than treating AI as a black box:

**character 2–6 TF-IDF → balanced Logistic Regression → frozen operating thresholds**

The ML signal is designed for **previously unseen domain names** and is intentionally subordinate to deterministic CTI evidence.

Important limitations:

- model output is an **uncalibrated score**, not a malware probability;
- model promotion is never automatic;
- false-positive rate and recall are measured separately;
- the earlier character-only C=4 candidate has a completed historical post-freeze temporal evaluation;
- the reconstructed lexical C=4 candidate completed a post-freeze holdout but was not promoted because its false-positive rate was operationally unusable;
- a hard-negative augmented lexical candidate improved fresh-disjoint FPR, but remains auxiliary because that protocol is not strict temporal evidence;
- augmented runtime promotion is deferred until stronger untouched temporal evidence;
- the default path still targets the earlier artifact, which is absent in this checkout; the generated synthetic demo is a separate model;
- the project does not claim perfect detection.

Detailed methodology and evaluation history: **[docs/ML_DATASET.md](docs/ML_DATASET.md)**.

---

## 🔐 Privacy & safety by design

ThreatFusion treats suspicious indicators as **inert data**.

- uploaded telemetry is processed locally / in memory by default;
- raw uploaded rows are not stored in analysis history;
- raw client and response IP values are excluded from portable reports;
- Quick Lookup does not visit URLs, resolve hosts, or download content;
- public mode disables shared analysis-history browsing and saving;
- third-party CTI dumps are not committed to the repository;
- public demo packaging uses a sanitized runtime;
- feed-refresh failures preserve the last healthy local snapshot.

---

## 🔄 CTI refresh lifecycle

ThreatFusion separates interactive analysis from feed maintenance.

~~~text
ThreatFox / URLhaus / SGB  -> refresh when stale
PhishTank                  -> maximum once every 24 hours
failed / empty refresh     -> previous healthy snapshot preserved
inactive lifecycle rows    -> pruned after 90 days
~~~

Manual refresh:

~~~powershell
$env:THREATFOX_AUTH_KEY="..."
$env:URLHAUS_AUTH_KEY="..."
python scripts\refresh_cti_cache.py --force
~~~

For hosted deployments, use a separate scheduler / maintenance job if periodic CTI refresh is required. The Streamlit web process itself does not refresh feeds.

---

## 🐧 Linux — one command, local first

Run this as your normal user in a Linux terminal. Python, Git and sudo are not required.
Linux **x86_64 with glibc 2.28+**, Bash, curl or wget, HTTPS certificates, tar,
coreutils and flock are required; Debian 12 and Ubuntu 24.04 are tested.
Allow approximately 2 GB of free disk space and an internet connection for installation.

```bash
bash -c 'set -e; f=$(mktemp /tmp/threatfusion-install.XXXXXXXX); trap "rm -f -- \"$f\"" EXIT; u=https://raw.githubusercontent.com/ConquestorYa/threatfusion-ai/main/scripts/install_linux.sh; if command -v curl >/dev/null; then curl --proto "=https" --proto-redir "=https" -fsSL --retry 3 --connect-timeout 20 --max-time 300 "$u" -o "$f"; elif command -v wget >/dev/null; then wget --https-only --timeout=30 --tries=3 -qO "$f" "$u"; else echo "curl veya wget gerekli" >&2; exit 1; fi; bash "$f" "$@"' --
```

The command installs private **Python 3.12.14**, 49 hashed runtime dependencies,
source code, an applications-menu shortcut and the `threatfusion-ai` command.
It opens **http://127.0.0.1:8501** (or the next free port) in real CTI mode,
with **ML disabled**. The sidebar's **Local setup & CTI updates** panel lets you
enter your own API keys, update feeds and enable optional 6/12/24-hour updates.
SGB and public PhishTank can be attempted without keys; ThreatFox/URLhaus need
your own keys. The first cache is empty until you request collection.

Reopen from the applications menu or a new terminal:

```bash
threatfusion-ai
threatfusion-ai status
threatfusion-ai stop
```

Ctrl+C or the web panel's stop button also stops the server/scheduler. Closing
only the browser tab leaves it running. Automatic refresh runs only while the
app is running and catches up on restart. Keys stay session-only unless you
explicitly save them in a private 0600 plaintext file. Demo is optional via
`threatfusion-ai --mode demo`; its synthetic model is not measured performance.
See [Linux installation](docs/INSTALL_LINUX.md) for privacy, source access,
upgrades and the fallback full launcher path. Your developer data is not copied.

The command installs the current `main` revision. The local installer does not
create or resume a hosted service.

---

## 🖥️ Windows quick start — clean machine

These steps are written for a fresh **Windows 10/11** machine using **PowerShell** and **Python 3.12**.

### 1. Install Git and Python 3.12

Open PowerShell and install the prerequisites:

~~~powershell
winget install --id Git.Git -e --source winget
winget install --id Python.Python.3.12 -e --source winget
~~~

Close PowerShell, open it again, then verify both commands are available:

~~~powershell
git --version
py -3.12 --version
~~~

> If `winget` is not available, install **Git for Windows** and **Python 3.12 (64-bit)** manually from their official websites, then reopen PowerShell. When using the Python installer, keep the Python Launcher enabled.

### 2. Clone ThreatFusion AI

~~~powershell
cd $HOME
git clone https://github.com/ConquestorYa/threatfusion-ai.git
cd threatfusion-ai
~~~

### 3. Create the virtual environment and install dependencies

The commands below intentionally do **not** use `Activate.ps1`, so a default Windows PowerShell execution policy will not block the installation.

~~~powershell
py -3.12 -m venv .venv

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
~~~

Optional installation check:

~~~powershell
.\.venv\Scripts\python.exe -c "import threatfusion, streamlit; print('ThreatFusion install OK')"
~~~

### 4. First run — safe synthetic demo

Generate the local demo database and demo ML artifact:

~~~powershell
.\.venv\Scripts\python.exe scripts\generate_public_demo_runtime.py --output-dir runtime
~~~

Configure the current PowerShell session. The SHA-256 value is read automatically from the artifact generated by the previous command:

~~~powershell
$env:THREATFUSION_PUBLIC_MODE="1"
$env:THREATFUSION_DB_PATH="runtime\threatfusion.sqlite"
$env:THREATFUSION_MODEL_DIR="runtime\models\development-001"
$env:THREATFUSION_MODEL_SHA256=(Get-Content "runtime\models\development-001\artifact.sha256" -Raw).Trim()
~~~

Start the web interface:

~~~powershell
.\.venv\Scripts\python.exe -m streamlit run streamlit_app.py --server.address=127.0.0.1
~~~

Streamlit normally opens the application automatically. If it does not, open **http://localhost:8501** in your browser. Stop the server with **Ctrl+C**.

The generated runtime contains **synthetic documentation-only CTI and a demo-only ML artifact**. It is designed to demonstrate the interface safely and must not be used for model-performance claims.

### 5. Starting the demo again later

For a Linux/private checkout with a CTI cache but no trusted original model,
explicitly disable ML:

```bash
THREATFUSION_CTI_ONLY=1 .venv/bin/python -m streamlit run streamlit_app.py --server.address=127.0.0.1
```

CTI and DNS behavior remain available; ML and model-dependent history are
disabled. This does not promote an experimental model. An optional synthetic
public-demo container is defined by
[`Dockerfile.public-demo`](Dockerfile.public-demo); no hosting configuration is
maintained. See the [deployment guide](docs/DEPLOYMENT.md) for limits and verification.

You do **not** need to reinstall anything. Open PowerShell, return to the repository, set the runtime variables again, and start Streamlit:

~~~powershell
cd $HOME\threatfusion-ai

$env:THREATFUSION_PUBLIC_MODE="1"
$env:THREATFUSION_DB_PATH="runtime\threatfusion.sqlite"
$env:THREATFUSION_MODEL_DIR="runtime\models\development-001"
$env:THREATFUSION_MODEL_SHA256=(Get-Content "runtime\models\development-001\artifact.sha256" -Raw).Trim()

.\.venv\Scripts\python.exe -m streamlit run streamlit_app.py --server.address=127.0.0.1
~~~

If you intentionally want to regenerate the synthetic runtime, use:

~~~powershell
.\.venv\Scripts\python.exe scripts\generate_public_demo_runtime.py --output-dir runtime --overwrite
~~~

### 6. Update the CTI database manually

The Streamlit web app no longer performs network refreshes during startup. This keeps startup simple and immediate.

ThreatFox and URLhaus use their API/auth keys from environment variables. Keep those keys outside Git:

~~~powershell
$env:THREATFOX_AUTH_KEY="YOUR_THREATFOX_KEY"
$env:URLHAUS_AUTH_KEY="YOUR_URLHAUS_KEY"
$env:PHISHTANK_APP_KEY="..."  # optional; recommended for automated downloads
~~~

Update the same CTI database used by the app with one command:

~~~powershell
.\.venv\Scripts\python.exe update_cti_database.py
~~~

The updater forces the configured ThreatFox, URLhaus, and SGB sources to refresh. PhishTank still respects its fixed 24-hour public-feed minimum. Missing ThreatFox/URLhaus keys are skipped instead of preventing SGB/PhishTank updates, and a failed source keeps its previous healthy cache.

Then start the site separately:

~~~powershell
.\.venv\Scripts\python.exe -m streamlit run streamlit_app.py --server.address=127.0.0.1
~~~

Starting Streamlit does **not** update the database or wait for external CTI services. Run `update_cti_database.py` whenever you want fresh CTI data.

### Windows troubleshooting

- **`py` is not recognized:** close and reopen PowerShell after installing Python. If it is still missing, reinstall Python 3.12 with the Python Launcher enabled.
- **`git` is not recognized:** close and reopen PowerShell after installing Git.
- **`runtime` already exists:** keep the existing runtime, or regenerate it with `--overwrite`.
- **Port 8501 is already in use:** start Streamlit with `--server.port 8502` appended to the final command.


---

## 🧰 Tech stack

<p>
  <img alt="Python" src="https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white">
  <img alt="Streamlit" src="https://img.shields.io/badge/Streamlit-UI-FF4B4B?logo=streamlit&logoColor=white">
  <img alt="pandas" src="https://img.shields.io/badge/pandas-Data-150458?logo=pandas&logoColor=white">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-ML-F7931E?logo=scikitlearn&logoColor=white">
  <img alt="SQLite" src="https://img.shields.io/badge/SQLite-Storage-003B57?logo=sqlite&logoColor=white">
  <img alt="Plotly" src="https://img.shields.io/badge/Plotly-Visualization-3F4F75?logo=plotly&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Container-2496ED?logo=docker&logoColor=white">
  <img alt="GitHub Actions" src="https://img.shields.io/badge/GitHub%20Actions-CI-2088FF?logo=githubactions&logoColor=white">
</p>

---

## ✅ Quality gates

GitHub Actions verifies the project on every relevant push / pull request:

- **Ubuntu:** Ruff, pytest + coverage, public-release audit, <code>pip-audit</code>
- **Windows / Python 3.12:** full pytest compatibility
- **Docker:** image build, public-mode startup and Streamlit health check

---

## 🗂️ Project structure

~~~text
threatfusion-ai/
├── src/threatfusion/        # Core package
│   ├── collectors/          # CTI collectors
│   ├── ...                  # Matching, ML, behavior, persistence, UI helpers
├── scripts/                 # Refresh, evaluation, demo and release utilities
├── tests/                   # Unit + integration + Streamlit regression tests
├── docs/                    # Architecture, data sources, ML and deployment docs
├── streamlit_app.py         # Analyst web workspace
├── Dockerfile               # Non-root container
└── pyproject.toml           # Package metadata
~~~

---

## 📚 Documentation

| Document | Purpose |
| --- | --- |
| **[Product plan & AI continuation](docs/PRODUCT_PLAN.md)** | Target product, implemented features, current checkpoint and ordered roadmap |
| **[Project context](docs/PROJECT_CONTEXT.md)** | Current state and dated engineering history |
| **[Release handoff](docs/RELEASE_HANDOFF.md)** | Latest completed work, checks and remaining limitations |
| **[Documentation hub](docs/README.md)** | Start here for all technical docs |
| **[Architecture](docs/ARCHITECTURE.md)** | Data flow, components and trust boundaries |
| **[Data sources](docs/DATA_SOURCES.md)** | Attribution, source scope and redistribution notes |
| **[ML dataset & evaluation](docs/ML_DATASET.md)** | Model methodology and evaluation history |
| **[Deployment](docs/DEPLOYMENT.md)** | Public mode, Docker, refresh jobs and hosting |
| **[Release notes](docs/RELEASE_NOTES_v0.1.0.md)** | v0.1.0 release-candidate scope |

---

## 🎯 Project status

**Active local development: a network investigation workbench with a web
analyst workspace and Linux automation.** Manual acceptance, operational
confidence and independent evidence precede wider detection and SIEM integration.

Use the [product plan](docs/PRODUCT_PLAN.md) for the current feature inventory,
ordered roadmap and instructions for continuing with another AI. Quick Lookup
supports the telemetry workflow. RITA parity and production readiness remain
unmeasured. ML promotion is deferred; CTI-only use remains available.

No public site or hosted preview is authorized. A verified GitHub source update
does not authorize deployment, and hosting is not required for local release.

---

## 🧭 Scope boundaries

ThreatFusion AI is **not**:

- a production SIEM;
- an EDR;
- an automated incident-response system;
- a guarantee that a destination is malicious or benign;
- a replacement for analyst review.

The goal is to demonstrate **multi-source CTI engineering, safe telemetry ingestion, explainable ML-assisted triage, reproducible evaluation, privacy-conscious design, and release-quality software practices** in one coherent project.

---

## 📄 License

ThreatFusion AI source code is licensed under the **MIT License**.

Third-party threat feeds and datasets remain subject to their own terms. See **[docs/DATA_SOURCES.md](docs/DATA_SOURCES.md)**.

---

<div align="center">

### ThreatFusion AI

**CTI evidence first. ML as an auxiliary signal. Analyst context always visible.**

<a href="README.tr.md">🇹🇷 Türkçe README</a>
&nbsp;•&nbsp;
<a href="docs/README.md">📚 Documentation</a>

</div>
