#!/usr/bin/env bash
# Existing isolated guest only; no packet sending, public ports or malware execution.
set -euo pipefail
umask 077
ROOT="$HOME/threatfusion-lab/results/independent-replay-v1"
RITA_ROOT="$HOME/threatfusion-lab/rita-independent-runtime"
IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
for CASE in normal-20 normal-21 malware-3 malware-8; do
  RUN="$ROOT/$CASE"
  COMPLETE=$(python3 - "$RUN/acquisition.json" <<'PY'
import json,pathlib,sys
path=pathlib.Path(sys.argv[1]);qualification=path.with_name('format-qualification.json')
print(json.loads((qualification if qualification.exists() else path).read_text())['status'])
PY
)
  [[ "$COMPLETE" == complete ]] || continue
  [[ -f "$RUN/scenario.pcap" && ! -L "$RUN/scenario.pcap" && ! -e "$RUN/zeek" ]] || exit 2
  python3 - "$RUN" "$RITA_ROOT" <<'PY'
import hashlib,json,pathlib,sys
run,rita=map(pathlib.Path,sys.argv[1:])
names=['rita_lab.sh','config.hjson','rita-env','rita-lab-compose.yml','http_extensions_list.csv']
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while block:=f.read(1024*1024):h.update(block)
    return h.hexdigest()
data={'pcap_sha256':digest(run/'scenario.pcap'),
      'rita_files':{n:hashlib.sha256((rita/n).read_bytes()).hexdigest() for n in names}}
with (run/'pre-analysis.json').open('x') as f:json.dump(data,f,indent=2);f.write('\n')
PY
  mkdir -m 700 "$RUN/zeek"
  STATUS=0
  docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL \
    --security-opt no-new-privileges --read-only --memory 1g --pids-limit 128 \
    --entrypoint /bin/sh -v "$RUN/scenario.pcap:/input.pcap:ro" \
    -v "$RUN/zeek:/output" -w /output "$IMAGE" \
    -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -r /input.pcap' > "$RUN/zeek.stdout" 2> "$RUN/zeek.stderr" || STATUS=$?
  printf '%s\n' "$STATUS" > "$RUN/zeek.exit"
  printf '%s\n' "$IMAGE" > "$RUN/image.txt"
  NATIVE=125
  if [[ "$STATUS" == 0 ]]; then
    DB="independent_v1_${CASE//-/_}"
    EXISTS=$(docker exec tf-rita-lab-clickhouse-1 clickhouse-client --query \
      "SELECT count() FROM system.databases WHERE name = '$DB'")
    [[ "$EXISTS" == 0 ]] || { echo 'Existing database: preserve previous experiment.' >&2; exit 2; }
    NATIVE=0
    bash "$RITA_ROOT/rita_lab.sh" import --database="$DB" --logs="$RUN/zeek" > "$RUN/rita-import.stdout" 2> "$RUN/rita-import.stderr" || NATIVE=$?
    if [[ "$NATIVE" == 0 ]]; then
      bash "$RITA_ROOT/rita_lab.sh" view --stdout --limit=100000 "$DB" > "$RUN/rita.csv" 2> "$RUN/rita-view.stderr" || NATIVE=$?
    fi
  fi
  printf '%s\n' "$NATIVE" > "$RUN/rita.exit"
  python3 - "$RUN" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);names=['zeek/conn.log','zeek/dns.log','rita.csv']
with (root/'native-output-hashes.json').open('x') as f:
    json.dump({n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names if (root/n).is_file()},f,indent=2);f.write('\n')
PY
  echo "Completed $CASE: Zeek=$STATUS RITA=$NATIVE"
done
