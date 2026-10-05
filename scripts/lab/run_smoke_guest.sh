#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/threatfusion-lab"
RUN="results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN/zeek"
chmod 755 "$RUN" "$RUN/zeek"
NET=tf-lab-smoke
SERVER=tf-lab-smoke-server
CAPTURE=
NET_CREATED=0
SERVER_CREATED=0
cleanup() {
  if [[ -n "$CAPTURE" ]]; then
    sudo kill -INT "$CAPTURE" 2>/dev/null || true
    wait "$CAPTURE" 2>/dev/null || true
  fi
  if [[ "$SERVER_CREATED" == 1 ]]; then docker rm -f "$SERVER" >/dev/null 2>&1 || true; fi
  if [[ "$NET_CREATED" == 1 ]]; then docker network rm "$NET" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
# Refuse to reuse any unrelated resources with colliding names.
if docker network inspect "$NET" >/dev/null 2>&1; then
  echo 'Smoke network already exists; inspect it before retrying.' >&2; exit 1
fi
if docker container inspect "$SERVER" >/dev/null 2>&1; then
  echo 'Smoke server already exists; inspect it before retrying.' >&2; exit 1
fi
PYTHON_IMAGE=python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ZEEK_IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
for image in "$PYTHON_IMAGE" "$ZEEK_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then docker pull "$image"; fi
done
printf '%s\n%s\n' "$PYTHON_IMAGE" "$ZEEK_IMAGE" > "$RUN/images.txt"
docker network create --internal --subnet 172.30.80.0/24 --opt com.docker.network.bridge.name=br-tflab "$NET" >/dev/null
NET_CREATED=1
docker run -d --name "$SERVER" --network "$NET" --ip 172.30.80.53 --cap-drop ALL --security-opt no-new-privileges --read-only -v "$PWD/dns_http_server.py:/server.py:ro" "$PYTHON_IMAGE" python /server.py >/dev/null
SERVER_CREATED=1
# Capture only the dedicated guest bridge, not the host/guest Internet interface.
sudo tcpdump -i br-tflab -U -s 0 -w "$PWD/$RUN/smoke.pcap" 'udp port 53 or tcp port 8000' > "$RUN/capture.txt" 2>&1 &
CAPTURE=$!
sleep 2
for suffix in 11 12 13; do
  docker run --rm --network "$NET" --ip "172.30.80.$suffix" --cap-drop ALL --security-opt no-new-privileges --read-only -v "$PWD/dns_http_client.py:/client.py:ro" "$PYTHON_IMAGE" python /client.py
done
sleep 2
sudo kill -INT "$CAPTURE"
wait "$CAPTURE" || true
CAPTURE=
sudo chown "$(id -u):$(id -g)" "$RUN/smoke.pcap"
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh -v "$PWD/$RUN:/input:ro" -v "$PWD/$RUN/zeek:/output" -w /output "$ZEEK_IMAGE" -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -C -r /input/smoke.pcap'
python3 - "$RUN" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
def read_log(name):
    fields = None
    rows = []
    for line in (path / 'zeek' / name).read_text().splitlines():
        if line.startswith('#fields\t'):
            fields = line.split('\t')[1:]
        elif line and not line.startswith('#'):
            assert fields
            rows.append(dict(zip(fields, line.split('\t'), strict=True)))
    return rows
dns = read_log('dns.log')
http = read_log('http.log')
assert len(dns) == 3, dns
assert {row['id.orig_h'] for row in dns} == {'172.30.80.11', '172.30.80.12', '172.30.80.13'}
assert all(row['query'] == 'normal.test' and row['answers'] == '172.30.80.53' and row['rcode_name'] == 'NOERROR' for row in dns)
assert len(http) == 3 and all(row['status_code'] == '200' for row in http)
summary = {'scope': 'synthetic DNS/HTTP capture and ingestion smoke only', 'dns_queries': len(dns), 'http_requests': len(http), 'clients': 3, 'zeek_checksum_verification_disabled': True}
(path / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary))
PY
printf '%s\n' "$RUN" > latest-result
