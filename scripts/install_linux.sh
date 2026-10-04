#!/usr/bin/env bash
# User-scoped Linux bootstrap. No sudo, system Python edits, Git or pip needed.
set -Eeuo pipefail
umask 077

INSTALL_UV_VERSION=0.12.23
INSTALL_UV_SHA256=1cff8783850e794470aadb73f54b749542a511fc57b0ce6468b64bd3852e0ade
PYTHON_VERSION=3.12.14
SOURCE_REF=main
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/threatfusion-ai"
SOURCE_DIR=""
MODE=""
PORT=""
PREPARE_ONLY=0
NO_BROWSER=0
REFRESH_CTI=0

usage() {
    cat <<'EOF'
ThreatFusion AI — Linux local installer
  --install-dir PATH    Dedicated installation directory (no sudo)
  --mode demo|cti-only   Synthetic demo by default; real CTI has no ML
  --refresh-cti         Explicitly fetch feeds in cti-only mode
  --port NUMBER         Local port; default finds a free port from 8501
  --prepare-only        Install/check everything without starting the server
  --no-browser          Print the localhost URL without opening a browser
  --ref REF             Repository branch or immutable commit to install
  --source-dir PATH     Developer/test option: use a local checkout
  --help                Show this help
Stop the foreground application with Ctrl+C. Existing data is preserved.
EOF
}
fail() { printf 'Kurulum durduruldu / Setup stopped: %s\n' "$1" >&2; exit 1; }
need_value() { [[ $# -ge 2 && -n "$2" ]] || fail "$1 requires a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir) need_value "$@"; INSTALL_DIR=$2; shift 2 ;;
        --source-dir) need_value "$@"; SOURCE_DIR=$2; shift 2 ;;
        --ref) need_value "$@"; SOURCE_REF=$2; shift 2 ;;
        --mode) need_value "$@"; MODE=$2; shift 2 ;;
        --port) need_value "$@"; PORT=$2; shift 2 ;;
        --prepare-only) PREPARE_ONLY=1; shift ;;
        --no-browser) NO_BROWSER=1; shift ;;
        --refresh-cti) REFRESH_CTI=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Unknown option: $1" ;;
    esac
done
[[ -z "$MODE" || "$MODE" == demo || "$MODE" == cti-only ]] || fail 'Use --mode demo or --mode cti-only'
[[ "$REFRESH_CTI" == 0 || "$MODE" == cti-only ]] || fail '--refresh-cti requires --mode cti-only'
[[ -z "$PORT" || "$PORT" =~ ^[0-9]+$ ]] || fail 'Port must be a number'
if [[ -n "$PORT" ]]; then
    [[ ${#PORT} -le 5 ]] || fail 'Port must be between 1024 and 65535'
    [[ $((10#$PORT)) -ge 1024 && $((10#$PORT)) -le 65535 ]] || fail 'Port must be between 1024 and 65535'
fi
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'This version supports Linux x86_64 only'
[[ $EUID -ne 0 ]] || fail 'Run as your normal user, without sudo'
for tool in tar sha256sum flock getconf mktemp; do
    command -v "$tool" >/dev/null || fail "Missing operating-system tool: $tool"
done
libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'A glibc-based Linux distribution is required (Alpine/musl unsupported)'
libc_version=${libc#glibc }
IFS=. read -r libc_major libc_minor _ <<< "$libc_version"
[[ "$libc_major" -gt 2 || ( "$libc_major" -eq 2 && "$libc_minor" -ge 28 ) ]] || fail 'glibc 2.28 or newer is required'
if command -v curl >/dev/null; then
    download() { curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 20 --max-time 300 --retry 3 "$1" -o "$2"; }
elif command -v wget >/dev/null; then
    download() { wget --https-only --timeout=30 --tries=3 -q -O "$2" "$1"; }
else
    fail 'curl or wget and working HTTPS certificates are required'
fi
[[ "$INSTALL_DIR" == /* && ! -L "$INSTALL_DIR" ]] || fail 'Use an absolute, non-symlink dedicated install directory'
if [[ -d "$INSTALL_DIR" && ! -f "$INSTALL_DIR/.threatfusion-install" ]]; then
    [[ -z $(ls -A "$INSTALL_DIR") ]] || fail 'Existing directory is not a ThreatFusion installation; choose another --install-dir'
fi
if [[ -f "$INSTALL_DIR/.threatfusion-install" ]]; then
    [[ $(cat "$INSTALL_DIR/.threatfusion-install") == 1 ]] || fail 'Unknown installation marker; existing files preserved'
fi
mkdir -p "$INSTALL_DIR"
[[ -O "$INSTALL_DIR" ]] || fail 'Installation directory must belong to your user'
chmod 700 "$INSTALL_DIR"
printf '1\n' > "$INSTALL_DIR/.threatfusion-install"
exec 9> "$INSTALL_DIR/.bootstrap.lock"
flock -n 9 || fail 'Another bootstrap is running; wait for it to finish'
temporary=$(mktemp -d "$INSTALL_DIR/.bootstrap-XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
trap 'printf "Setup interrupted; rerun the same command to resume.\n" >&2; exit 130' INT TERM
trap 'printf "Setup failed (line %s). Check network/disk access and rerun; existing data was preserved.\n" "$LINENO" >&2' ERR

# Ignore package-manager overrides: downloads use the official registries with TLS.
for variable in ${!UV_@} ${!PIP_@}; do unset "$variable"; done
unset PYTHONHOME PYTHONPATH VIRTUAL_ENV CONDA_PREFIX
export UV_PYTHON_INSTALL_DIR="$INSTALL_DIR/python"
export UV_CACHE_DIR="$INSTALL_DIR/cache"
export UV_NO_CONFIG=1 UV_NO_PROGRESS=1 PYTHONDONTWRITEBYTECODE=1
uv_dir="$INSTALL_DIR/tools/uv-$INSTALL_UV_VERSION"
uv="$uv_dir/uv"
printf '[1/4] uv %s ve özel Python %s hazırlanıyor…\n' "$INSTALL_UV_VERSION" "$PYTHON_VERSION"
if [[ ! -x "$uv" ]]; then
    download "https://github.com/astral-sh/uv/releases/download/$INSTALL_UV_VERSION/uv-x86_64-unknown-linux-musl.tar.gz" "$temporary/uv.tar.gz"
    printf '%s  %s\n' "$INSTALL_UV_SHA256" "$temporary/uv.tar.gz" | sha256sum --check --status || fail 'uv archive checksum mismatch'
    tar -xzf "$temporary/uv.tar.gz" -C "$temporary" uv-x86_64-unknown-linux-musl/uv
    mkdir -p "$uv_dir"
    install -m 700 "$temporary/uv-x86_64-unknown-linux-musl/uv" "$uv"
fi
uv_identity=$("$uv" --version)
[[ "$uv_identity" == "uv $INSTALL_UV_VERSION" || "$uv_identity" == "uv $INSTALL_UV_VERSION "* ]] || fail 'Unexpected cached uv version'
"$uv" python install "$PYTHON_VERSION" --no-bin --managed-python
python=$("$uv" python find "$PYTHON_VERSION" --managed-python)
if [[ -n "$SOURCE_DIR" ]]; then
    [[ -f "$SOURCE_DIR/scripts/bootstrap_linux.py" ]] || fail 'Local source checkout is missing bootstrap_linux.py'
    helper="$SOURCE_DIR/scripts/bootstrap_linux.py"
    source_args=(--source-dir "$SOURCE_DIR")
else
    # Resolve once to an immutable commit; bootstrap and source use that same SHA.
    "$python" - "$SOURCE_REF" "$temporary" <<'PY'
import json, re, sys, urllib.parse, urllib.request
from pathlib import Path
ref, temporary = sys.argv[1:]
url = 'https://api.github.com/repos/ConquestorYa/threatfusion-ai/commits/' + urllib.parse.quote(ref, safe='')
with urllib.request.urlopen(url, timeout=30) as response:
    sha = json.load(response)['sha']
if not re.fullmatch(r'[0-9a-f]{40}', sha):
    raise SystemExit('Invalid source identity')
url = f'https://raw.githubusercontent.com/ConquestorYa/threatfusion-ai/{sha}/scripts/bootstrap_linux.py'
with urllib.request.urlopen(url, timeout=30) as response:
    content = response.read(512_001)
if len(content) > 512_000:
    raise SystemExit('Bootstrap file exceeds size limit')
Path(temporary, 'bootstrap_linux.py').write_bytes(content)
Path(temporary, 'source.sha').write_text(sha)
PY
    helper="$temporary/bootstrap_linux.py"
    source_args=(--source-sha "$(cat "$temporary/source.sha")")
fi
args=(--install-dir "$INSTALL_DIR" --uv "$uv" "${source_args[@]}")
[[ -z "$MODE" ]] || args+=(--mode "$MODE")
[[ -z "$PORT" ]] || args+=(--port "$PORT")
[[ "$PREPARE_ONLY" == 0 ]] || args+=(--prepare-only)
[[ "$NO_BROWSER" == 0 ]] || args+=(--no-browser)
[[ "$REFRESH_CTI" == 0 ]] || args+=(--refresh-cti)
flock -u 9
exec 9>&-
"$python" "$helper" "${args[@]}"
