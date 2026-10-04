# Linux first installation

The one-command installer in the [English README](../README.md) and
[Turkish README](../README.tr.md) prepares Python, dependencies, source and a
synthetic runtime, then opens a loopback-only web interface. It runs as your
normal user: no sudo, system Python changes, Git, compiler, shell activation,
Docker or cloud account are required.

## Supported systems

This first version supports **Linux x86_64, glibc 2.28 or newer**. The complete
flow is tested on fresh **Debian 12** and **Ubuntu 24.04** images containing no
Python or Git. Other compatible desktop distributions may work; ARM, Alpine/
musl, macOS and Windows are not supported by this installer.

The OS must already provide Bash, curl **or** wget, working HTTPS CA
certificates, tar, coreutils (`sha256sum`, `mktemp`, `install`) and util-linux
(`flock`, `getconf`). These are OS prerequisites, not Python dependencies. The
installer checks them and reports an actionable error rather than silently
using sudo. An internet connection to GitHub and PyPI is required for a fresh
installation. Approximately 2 GB free space is recommended; real CTI can need
additional space. No browser is installed: an existing desktop browser opens
after the server is healthy. On a headless machine, use `--no-browser`.

## What happens

1. The copy-paste command downloads the complete bootstrap to a unique temporary
   file before executing it. Failed downloads are not executed.
2. uv **0.12.23** is fetched from its official GitHub release with a fixed archive
   SHA-256. uv installs a private managed **Python 3.12.14** without adding a
   global executable or changing PATH.
3. The selected repository ref is resolved once to an immutable commit. The
   helper and source archive use that same identity. Archive traversal, links,
   special files and excessive entry/size counts are rejected before extraction.
4. `requirements-linux.lock` installs all 49 pinned runtime packages using
   required hashes and binary wheels from PyPI. Compatibility and imports are
   checked. uv/package-manager override variables are cleared during bootstrap.
5. Separate synthetic CTI and demo ML files are generated locally. A model pin
   outside the model bundle is checked on every start. Damaged existing files
   are refused, not silently regenerated or overwritten.
6. Streamlit binds **127.0.0.1** only. The default free port is selected from
   8501–8600; `--port` selects a specific unprivileged port and fails if busy.
   Health is checked before opening the browser. Ctrl+C/SIGTERM stop child
   processes; a second launcher cannot start the same installation concurrently.

Default storage is `${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai`, with
private directory/file permissions. Tools, Python, cached downloads, immutable
source releases, hashed virtual environments and runtime data live there.
`installation.json` records source path, private Python and selected mode; it
contains no API keys. The existing development checkout and its `.venv`/`data`
are not modified. Alternate locations must be absolute, dedicated directories;
unrecognized nonempty directories are refused.

## Restart and installer options

```bash
"${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai/start"
```

The saved launcher uses its installed source and private interpreter; it needs
no internet to restart demo or already cached CTI. The last selected mode is
remembered. Re-running the original install command checks dependencies and
can fetch a newer revision of the selected branch; it preserves existing CTI
and demo data. It is a foreground app, not an automatic login/system service.

The copy-paste command ends in `--`; append options after it. Examples:

```text
--prepare-only                    # install and validate; do not run the server
--no-browser                      # run server; print local URL
--install-dir "/absolute/path"     # dedicated user-owned installation
--port 18501                      # fixed local port; no killing a port owner
--ref <full-commit-sha>            # explicitly install an immutable source revision
```

The launcher supports `--mode`, `--refresh-cti`, `--port`, `--prepare-only` and
`--no-browser`. Installation options `--ref` and `--source-dir` are not launcher
options. `--source-dir` is for developers/CI only; the normal user command
downloads source and requires no checkout.

## Real CTI is an explicit second step

The default **demo** is deliberately synthetic, with a demo-only model and four
example IOC records. Try `known-threat.example`. It does not claim measured ML
performance and never collects external CTI automatically.

To collect real intelligence into a separate initially empty SQLite cache:

```bash
"${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai/start" --mode cti-only --refresh-cti
```

In **CTI-only** mode ML is disabled. It does not select a developer/experimental
artifact and does not change the deferred runtime-promotion decision. Switching
between modes preserves both datasets. A missing match is not evidence that a
target is safe. Shared persistent analyst history is disabled in this first-run
profile; telemetry analysis remains session-local. The existing
`THREATFUSION_PUBLIC_MODE` flag is reused for this privacy policy, not network
exposure: the server is still loopback-only.

ThreatFox and URLhaus require your own `THREATFOX_AUTH_KEY` and
`URLHAUS_AUTH_KEY`. Missing keys are clearly reported and those feeds are skipped.
PhishTank (optionally `PHISHTANK_APP_KEY`) and SGB are attempted; upstream access
restrictions can prevent a refresh. Each feed is refreshed independently, with
existing cache preserved on source failure. Output omits credential-bearing
URLs/details. No IOC destination is visited. Refresh must be requested again
for later updates; the app does not silently schedule collection.

To enter keys without placing their values in shell history:

```bash
read -rsp 'ThreatFox key: ' THREATFOX_AUTH_KEY; printf '\n'; export THREATFOX_AUTH_KEY
read -rsp 'URLhaus key: ' URLHAUS_AUTH_KEY; printf '\n'; export URLHAUS_AUTH_KEY
"${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai/start" --mode cti-only --refresh-cti
unset THREATFOX_AUTH_KEY URLHAUS_AUTH_KEY
```

The installer does not persist credentials and removes feed keys from the
Streamlit child environment. CTI caches, model binaries, domain snapshots,
CESNET samples, holdout files and private telemetry remain local. Downloading
your own feed data does not grant redistribution rights; see
[DATA_SOURCES.md](DATA_SOURCES.md). Fresh-disjoint aggregate results and the
strict-temporal limitation remain documented in [ML_DATASET.md](ML_DATASET.md).

There is no bundled developer key or shared fallback credential. Each caller
must supply their own credentials in their own environment. `.env`, Streamlit
`secrets.toml` and private-key files are ignored and rejected by the release
audit, including Git history. Refresh failures expose safe diagnostics rather
than raw HTTP/parser messages that might contain authenticated URLs or private
values; this applies to the standalone refresh CLI as well as the local launcher.

## Troubleshooting and reproducibility

- **No network / failed download:** fix access to GitHub/PyPI and rerun the
  same command. Download/hash/package failures stop setup. Do not disable TLS
  verification. Previously generated runtime data is preserved.
- **Unsupported OS, architecture or glibc:** use a supported Linux system;
  system Python is not a fallback for this pinned installer.
- **Busy installation:** stop its existing foreground terminal with Ctrl+C,
  then restart. No installer kills another running application.
- **Damaged model/pin or unfamiliar directory:** setup fails and preserves it.
  Choose a new dedicated `--install-dir` for a fresh installation; inspect the
  old files separately.
- **Browser missing:** the app still prints its local URL. On a remote/headless
  machine the loopback interface is on that machine; this flow opens no tunnel.
- **CTI-only shows no data:** explicitly refresh, check API-key availability and
  source status; an empty cache is never presented as a current global database.

To update dependencies deliberately, regenerate the lock from the runtime
requirements, review version/hash changes and rerun clean-install CI:

```bash
uv pip compile requirements-runtime.txt --python-version 3.12.14 \
  --python-platform x86_64-manylinux_2_28 --only-binary :all: --generate-hashes \
  --no-annotate --no-header --output-file requirements-linux.lock
```

CI installs twice on both supported test distributions, then verifies Python
and packages, immutable demo files, real Streamlit WebSocket rendering, a busy
port, loopback binding, duplicate-launch exclusion, CTI/demo data separation
and Ctrl+C/SIGTERM cleanup. These tests use generated `.example` fixtures, not
the developer cache, live feed credentials or private telemetry.

The installer is currently published on `local-development/linux-first-run`.
The hosting-connected `main` branch remains unchanged while external deployment
automation is unverified. Publishing this source branch does not create a site.
