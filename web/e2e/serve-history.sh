#!/usr/bin/env bash
# Browser-test server for Analysis history: the developer configuration
# (THREATFUSION_CTI_ONLY=0) with the synthetic demo domain artifact, a fresh
# synthetic CTI cache and collector state (documentation addresses, .test
# names), history enabled, loopback only. Used by playwright.config.ts.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
python="${E2E_PYTHON:-$repo/.venv/bin/python}"
[ -x "$python" ] || python="$(command -v python3)"
root="$(mktemp -d)/dev"
trap 'rm -rf "$(dirname "$root")"' EXIT
"$python" "$repo/scripts/demo_review_snapshot.py" --history-model "$root" >/dev/null
export THREATFUSION_CTI_ONLY=0
export THREATFUSION_PUBLIC_MODE=0
export THREATFUSION_HISTORY_ENABLED=1
export THREATFUSION_MODEL_DIR="$root/models/demo-synthetic"
export THREATFUSION_DB_PATH="$root/cti.sqlite"
export THREATFUSION_COLLECTOR_STATE_DIR="$root/collector"
export THREATFUSION_EVALUATION_REPORT="$root/no-final-report.json"
unset THREATFUSION_LOCAL_INSTALL_DIR THREATFUSION_LOCAL_LOOPBACK
cd "$repo"
"$python" -m threatfusion.api --port "${E2E_PORT:-8612}" --static-dir "$repo/web/dist"
