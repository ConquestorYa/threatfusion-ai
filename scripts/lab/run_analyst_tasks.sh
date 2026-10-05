#!/usr/bin/env bash
# Existing private lab guest only. Offline packet files are never transmitted.
set -euo pipefail
umask 077
ROOT="$HOME/threatfusion-lab/results/analyst-guidance-v1"
IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
for CASE in development reserved; do
  RUN="$ROOT/$CASE"
  [[ -f "$RUN/scenario.pcap" && ! -L "$RUN/scenario.pcap" && ! -e "$RUN/zeek" ]] || exit 2
  mkdir -m 700 "$RUN/zeek"
  STATUS=0
  docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL \
    --security-opt no-new-privileges --read-only --memory 1g --pids-limit 128 \
    --entrypoint /bin/sh -v "$RUN/scenario.pcap:/input.pcap:ro" \
    -v "$RUN/zeek:/output" -w /output "$IMAGE" \
    -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -r /input.pcap' > "$RUN/zeek.stdout" 2> "$RUN/zeek.stderr" || STATUS=$?
  printf '%s\n' "$STATUS" > "$RUN/zeek.exit"
  printf '%s\n' "$IMAGE" > "$RUN/image.txt"
  [[ "$STATUS" == 0 ]] || exit "$STATUS"
done
