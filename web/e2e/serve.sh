#!/usr/bin/env bash
# Browser-test server: a fresh synthetic collector state on every run, served
# by the real API on loopback only. Used by playwright.config.ts.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
python="$repo/.venv/bin/python"
[ -x "$python" ] || python="$(command -v python3)"
root="$(mktemp -d)/state"
trap 'rm -rf "$(dirname "$root")"' EXIT
"$python" "$repo/scripts/demo_review_snapshot.py" "$root" >/dev/null
export THREATFUSION_COLLECTOR_STATE_DIR="$root/collector"
export THREATFUSION_DB_PATH="$root/cti.sqlite"
export THREATFUSION_CTI_ONLY=1  # the default installation mode
export THREATFUSION_STREAMLIT_URL="http://127.0.0.1:8599"
cd "$repo"
"$python" -m threatfusion.api --port "${E2E_PORT:-8611}" --static-dir "$repo/web/dist"
