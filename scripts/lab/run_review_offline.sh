#!/usr/bin/env bash
# Run only inside the existing private lab guest; never replay onto a network.
set -euo pipefail
umask 077
cd "$HOME/threatfusion-lab"
CASE=${1:?Expected development, reserved, somfy-02, somfy-03 or trojan-42}
case "$CASE" in development|reserved|somfy-02|somfy-03|trojan-42) ;; *) exit 2 ;; esac
RUN="$PWD/results/review-workload-v1/$CASE"
[[ -f "$RUN/scenario.pcap" && ! -L "$RUN/scenario.pcap" && ! -e "$RUN/zeek" ]] || exit 2
mkdir -m 700 "$RUN/zeek"
IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
sha256sum "$RUN/scenario.pcap" > "$RUN/pre-analysis.sha256"
# Input/output are the only mounts; checksums stay enabled, no packet sending.
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges --read-only --memory 1g --pids-limit 128 \
  --entrypoint /bin/sh -v "$RUN/scenario.pcap:/input.pcap:ro" \
  -v "$RUN/zeek:/output" -w /output "$IMAGE" \
  -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -r /input.pcap' > "$RUN/zeek.stdout" 2> "$RUN/zeek.stderr"
printf '%s\n' "$IMAGE" > "$RUN/image.txt"
DB="review_v1_${CASE//-/_}"
RITA="$PWD/rita-review-runtime/rita_lab.sh"
# Fresh database names and no --rebuild: existing experiments are preserved.
EXISTS=$(docker exec tf-rita-lab-clickhouse-1 clickhouse-client --query \
  "SELECT count() FROM system.databases WHERE name = '$DB'")
[[ "$EXISTS" == 0 ]] || { echo 'Database already exists; preserve it.' >&2; exit 2; }
bash "$RITA" import --database="$DB" --logs="$RUN/zeek" > "$RUN/rita-import.stdout" 2> "$RUN/rita-import.stderr"
bash "$RITA" view --stdout --limit=100000 "$DB" > "$RUN/rita.csv" 2> "$RUN/rita-view.stderr"
sha256sum "$RUN/zeek/conn.log" "$RUN/rita.csv" > "$RUN/post-analysis.sha256"
echo "Offline analysis completed: $CASE"
