#!/usr/bin/env bash
# Browser-test server: a fresh synthetic managed installation on every run
# (documentation addresses, synthetic CTI, CTI-only mode, no network access),
# served by the real API on loopback only. Used by playwright.config.ts.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
python="${E2E_PYTHON:-$repo/.venv/bin/python}"
[ -x "$python" ] || python="$(command -v python3)"
root="$(mktemp -d)/install"
trap 'rm -rf "$(dirname "$root")"' EXIT
"$python" "$repo/scripts/demo_review_snapshot.py" --managed --behavior-model "$root" >/dev/null
export THREATFUSION_LOCAL_INSTALL_DIR="$root"
export THREATFUSION_LOCAL_LOOPBACK=1
cd "$repo"
"$python" -m threatfusion.api --port "${E2E_PORT:-8611}" --static-dir "$repo/web/dist"
