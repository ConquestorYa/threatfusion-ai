# Linux local installation

The one command in the [English README](../README.md) or
[Turkish README](../README.tr.md) installs Python, dependencies, the application,
an applications-menu shortcut and the `threatfusion-ai` terminal command.
It runs as your normal user: no sudo, system Python changes, Git, compiler,
Docker or cloud account are required. The browser interface binds only to
**127.0.0.1**. This does not create or resume a public website.

## Supported systems

**Linux x86_64, glibc 2.28+**, tested on clean Debian 12 and Ubuntu 24.04 images
without Python or Git. ARM, Alpine/musl, Windows and macOS are not supported by
this installer. The OS must provide Bash, curl or wget, working HTTPS CA
certificates, tar, coreutils and util-linux (`flock`, `getconf`). Installation
requires internet access to GitHub/PyPI and approximately 2 GB free space, plus
space for downloaded CTI. On a headless machine append `--no-browser`.

## First use: real intelligence, your own keys

New installations open in **real CTI mode with ML disabled**. The cache is
initially empty; an empty cache or a missing match does not establish safety.
The **Local setup & CTI updates** panel in the sidebar opens on first use:

1. Enter your own ThreatFox and URLhaus API keys if you have them. PhishTank's
   key is optional. SGB and public PhishTank can be attempted without keys.
2. Choose **Apply keys**. By default keys stay in the current browser session.
3. Click **Update CTI now**. Each source updates independently. Failures retain
   its previous cache; the panel shows skipped sources, failures and safe counts.
4. Run Quick Lookup or upload telemetry. After a cache update, run the analysis
   again: previously displayed results are snapshots.

Source access and availability are not guaranteed. In particular, a public
PhishTank download may be blocked upstream. The application does not visit IOC
destinations. Downloading permitted feeds does not grant redistribution rights;
see [DATA_SOURCES.md](DATA_SOURCES.md).

**Save keys on this computer** is optional and unchecked by default. It writes
an owner-only **0600 plaintext** `credentials.json` inside the private **0700**
installation directory. This is access-controlled storage, not encryption.
Saved keys are never populated back into browser password fields, added to
command arguments, logged, exported, copied to GitHub or included in Docker
images. **Forget saved and session keys** removes this application's saved file
and the current browser session's key selection. Other open browser sessions
have their own memory; close those tabs to discard their session selections.
No developer key, `.env`, Streamlit secret or private development cache is used
as a fallback. Existing standalone developer CLI environment options remain
separate from the managed installation.

## Automatic updates

Updates are manual until you enable **Automatic updates while the app is
running** and save an interval: **6, 12 or 24 hours**. The launcher supervises
this scheduler independently of browser reruns/tabs. It uses **only saved keys
and public sources**, not another browser session's unsaved credentials.

- Collection starts when due, including on the next app start after missed time.
- Fresh sources are skipped; PhishTank has a minimum 24-hour refresh cadence.
- Attempts are recorded even on failure to avoid tight retry loops while offline.
- Manual, CLI and automatic refresh share a nonblocking process lock.
- Closing a browser tab leaves the local server/scheduler running. Stopping the
  app stops both. No cron, login autostart or system background service is added;
  nothing is downloaded while the app is stopped.

The settings and status files contain configuration/aggregate counts, not API
keys or uploaded telemetry. CTI caches remain local and are never bundled in
repository releases. Synthetic demo data and real CTI use separate databases.

## Reopen and stop

Choose **ThreatFusion AI** in the desktop applications menu, or open a new
terminal and run:

```bash
threatfusion-ai
```

The shortcut opens a terminal supervising the local app and then your browser.
It does not reinstall dependencies or need internet to use the existing cache.
The selected operating mode is remembered. Supported management commands:

```bash
threatfusion-ai status    # running state and localhost URL
threatfusion-ai refresh   # real CTI using saved keys/public sources
threatfusion-ai stop      # stop this installation's server and scheduler
```

You can also use **Stop local application** in the web panel, Ctrl+C, or close
the supervising terminal. Ctrl+C/SIGTERM/SIGHUP clean up child processes. A
private Unix socket controls only this installation; stale PID files are not
used to kill processes. Duplicate launches are refused without affecting an
existing server or a port occupied by another application.

The full launcher path is always available, including in an already open
terminal whose PATH has not refreshed:

```bash
"${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai/start"
```

The installer registers `~/.local/bin/threatfusion-ai` and an XDG `.desktop`
entry. When needed it appends a marked PATH line to the user's profile and
Bash/Zsh startup file (or a Fish conf.d file); existing content is preserved.
Unrelated commands, desktop entries and symlinked startup files are not replaced.
If an existing unrelated shortcut blocks registration, use the printed full
launcher path. `--no-integrations` skips command/menu/shell registration.

## Runtime model and demo

Real CTI operation does **not** substitute the synthetic demo model for a
measured detector or promote the experimental augmented candidate. A trusted
production ML artifact is not distributed in the installer. See
[ML_DATASET.md](ML_DATASET.md) for the original missing artifact, fresh-disjoint
results and strict-temporal limitation.

Use the operating-mode selector to choose **Synthetic demo** for offline
interface exploration, or:

```bash
threatfusion-ai --mode demo
```

The demo generates four reserved example indicators and a checksum-pinned,
synthetic-only model. Try `known-threat.example`. Its score is not measured
malware detection performance. Switching modes clears stale UI results and
preserves both databases. Returning to real mode disables ML again.

## Installation details and upgrades

Default location: `${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai`.
Private Python **3.12.14**, uv **0.12.23** (fixed archive checksum), 49 hashed
runtime wheels, immutable source releases and runtime data live there.
The original development checkout, virtual environment, models and data are
not modified. Source archive traversal/links/special files and excessive sizes
are rejected. Inherited Python/package-manager overrides are cleared.

Rerun the original installation command to install the latest `main` source;
existing CTI, settings and optional saved credentials are preserved. Run this
upgrade after stopping the current installation. Offline restarts keep the
installed source identity; they do not silently download code updates.

Append options to the README command after its final `--`:

```text
--prepare-only                 # install/check, without starting the server
--no-browser                   # print localhost URL, no browser opening
--no-integrations              # no desktop/terminal/shell changes
--install-dir "/absolute/path"  # dedicated user-owned installation
--mode demo                    # explicitly request synthetic first use
--port 18501                   # fixed unprivileged loopback port; fail if busy
--ref <full-commit-sha>         # fixed source revision
```

`--refresh-cti` with `--mode cti-only` requests a launch-time refresh using saved
keys/public sources. The normal interactive panel is recommended. Launcher
flags also include `--mode`, `--port`, `--prepare-only` and `--no-browser`.
Installation-only flags `--ref`, `--source-dir` and `--no-integrations` are not
normal launcher options. `--source-dir` is for developers/CI only.

The first run picks a free port from 8501–8600 and checks health before opening
the browser. A failed source refresh never promotes an ML artifact or tunes a
threshold. History/telemetry stay session-local in this managed profile; the
`THREATFUSION_PUBLIC_MODE` privacy flag does not imply public network exposure.

## Automatic Zeek connections

In real CTI mode, use a separate terminal:

```bash
threatfusion-ai collect --input-dir /absolute/path/to/zeek/logs
```

The local **Collected connections** page refreshes from private state.
Completed TSV logs/archives are imported once; open logs wait for closure.
Ctrl+C stops collection; repeating the command resumes without duplicates.
The web app and collector have separate lifetimes. No background system service
is installed. Rules, limits and standalone operation are documented in
[TELEMETRY_COLLECTOR.md](TELEMETRY_COLLECTOR.md).

Uploaded telemetry remains session-local. Opting into this collector persists
typed connection evidence privately in the installation's `collector/` directory,
with bounded retention. Nothing is uploaded or added to shared analyst history.

## Troubleshooting

- Command missing in the current terminal: open a new terminal or use the full
  launcher path. An unrelated existing command is deliberately preserved.
- Source skipped: enter your own key and Apply; save it only if automatic/CLI
  collection should use it. No key is necessary to explore the synthetic demo.
- Refresh failed: check network/source access and key validity. Existing cache
  survives source failure; status never prints raw key-bearing HTTP errors.
- Permission error: managed files must belong to your user and be private.
  Do not loosen credentials to 0644 or run the installation as root.
- Already running: use `threatfusion-ai status` for the URL or stop it first.
- Busy fixed port: select another `--port`; the application never kills its owner.
