#!/usr/bin/env bash
# Demo: a fresh synthetic managed installation (documentation addresses,
# synthetic CTI, CTI-only mode), the real collector keeping it fresh, the
# React workspace and Streamlit — all on 127.0.0.1 only. Ctrl+C stops all.
#
#   scripts/demo_web.sh            # React http://127.0.0.1:8600, Streamlit http://127.0.0.1:8501
#
# Needs .venv (requirements.txt) and a built page (cd web && npm ci && npm run build).
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
py="$repo/.venv/bin/python"
api_port="${API_PORT:-8600}"
streamlit_port="${STREAMLIT_PORT:-8501}"
[ -f "$repo/web/dist/index.html" ] || { echo "Build the page first: cd web && npm ci && npm run build" >&2; exit 1; }
work="$(mktemp -d)"
root="$work/install"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT INT TERM

"$py" "$repo/scripts/demo_review_snapshot.py" --managed "$root"
export THREATFUSION_LOCAL_INSTALL_DIR="$root" THREATFUSION_LOCAL_LOOPBACK=1
export THREATFUSION_STREAMLIT_URL="http://127.0.0.1:$streamlit_port"

"$repo/.venv/bin/threatfusion-collect" --input-dir "$root/input" --state-dir "$root/collector" \
  --db "$root/runtime/cti/threatfusion.sqlite" --poll-seconds 10 --no-notify >/dev/null &
pids+=($!)
(cd "$repo" && "$py" -m threatfusion.api --port "$api_port") &
pids+=($!)
(cd "$repo" && "$repo/.venv/bin/streamlit" run streamlit_app.py --server.address=127.0.0.1 \
  --server.port="$streamlit_port" --server.headless=true --browser.gatherUsageStats=false >/dev/null) &
pids+=($!)

echo "React workspace: http://127.0.0.1:$api_port"
echo "Streamlit:       http://127.0.0.1:$streamlit_port"
echo "Synthetic data only. Ctrl+C stops everything and deletes $work."
wait
