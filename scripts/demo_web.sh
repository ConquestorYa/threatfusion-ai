#!/usr/bin/env bash
# Demo: a fresh synthetic managed installation (documentation addresses,
# synthetic CTI, CTI-only mode), the real collector keeping it fresh, the
# React workspace — all on 127.0.0.1 only. Ctrl+C stops all.
#
#   scripts/demo_web.sh            # React http://127.0.0.1:8600
#
# Needs .venv (requirements.txt); the built page web/dist is committed (DEC-108).
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
py="$repo/.venv/bin/python"
api_port="${API_PORT:-8600}"
[ -f "$repo/web/dist/index.html" ] || { echo "Build the page first: cd web && npm ci && npm run build" >&2; exit 1; }
work="$(mktemp -d)"
root="$work/install"
pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT INT TERM

# --behavior-model: a synthetic, untrained behavior model so Experimental ML and
# Model evaluation appear (presentation asset, DEC-105).
"$py" "$repo/scripts/demo_review_snapshot.py" --managed --behavior-model "$root"
export THREATFUSION_LOCAL_INSTALL_DIR="$root" THREATFUSION_LOCAL_LOOPBACK=1

"$repo/.venv/bin/threatfusion-collect" --input-dir "$root/input" --state-dir "$root/collector" \
  --db "$root/runtime/cti/threatfusion.sqlite" --poll-seconds 10 --no-notify >/dev/null &
pids+=($!)
(cd "$repo" && "$py" -m threatfusion.api --port "$api_port") &
pids+=($!)

echo "React workspace: http://127.0.0.1:$api_port"
echo "Upload samples (Analyze telemetry): $repo/data/samples/demo/{dns.log,conn.log,dns_queries.csv}"
echo "Synthetic data only. Ctrl+C stops everything and deletes $work."
wait
