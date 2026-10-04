#!/usr/bin/env bash
# Isolated comparison CLI, not an installation into the host operating system.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
COMPOSE="$ROOT/rita-lab-compose.yml"
IMAGE=ghcr.io/activecm/rita@sha256:a2bb0ef6185e33780dbc3ce7d86e38ac7a65c98e729e17510fe29717eb34b76a
case "${1:-help}" in
  start) exec docker compose -f "$COMPOSE" up -d --wait ;;
  stop) exec docker compose -f "$COMPOSE" stop ;;
  status) exec docker compose -f "$COMPOSE" ps ;;
esac
if [[ ! -f "$ROOT/config.hjson" || ! -f "$ROOT/rita-env" || ! -f "$ROOT/http_extensions_list.csv" || ! -d "$ROOT/threat_intel_feeds" ]]; then
  echo 'Lab-only RITA config files are missing; see docs/LOCAL_LAB.md.' >&2; exit 1
fi
docker compose -f "$COMPOSE" up -d --wait >&2
ARGS=(--rm --network tf-rita-analysis --cap-drop ALL --security-opt no-new-privileges
  --env DB_ADDRESS=tf-rita-lab-clickhouse-1:9000 --env CLICKHOUSE_USERNAME=default
  --env CLICKHOUSE_PASSWORD= --env CONFIG_DIR=/etc/rita --env LOGGING_ENABLED=false --env LOG_LEVEL=2
  --mount "type=bind,source=$ROOT/rita-env,target=/.env,readonly"
  --mount "type=bind,source=$ROOT/config.hjson,target=/config.hjson,readonly"
  --mount "type=bind,source=$ROOT/http_extensions_list.csv,target=/etc/rita/http_extensions_list.csv,readonly"
  --mount "type=bind,source=$ROOT/threat_intel_feeds,target=/etc/rita/threat_intel_feeds,readonly")
# Native RITA import flags are retained, and only the selected Zeek directory
# is exposed read-only to the container. No Docker socket or home mount.
for argument in "$@"; do
  if [[ "$argument" == --logs=* ]]; then
    LOG_DIR=$(realpath -- "${argument#--logs=}")
    [[ -d "$LOG_DIR" ]] || { echo 'Import expects a directory.' >&2; exit 1; }
    ARGS+=(--mount "type=bind,source=$LOG_DIR,target=$LOG_DIR,readonly")
  fi
done
if [[ -t 0 && -t 1 ]]; then ARGS+=(-it); fi
exec docker run "${ARGS[@]}" "$IMAGE" "$@"
