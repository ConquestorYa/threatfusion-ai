#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/threatfusion-lab"
RUN="results/periodic-live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN/zeek"
NET=tf-lab-periodic
PYTHON_IMAGE=python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ZEEK_IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
NAMES=(tf-periodic-dns tf-periodic-web tf-periodic-update tf-periodic-heartbeat tf-periodic-browser-client tf-periodic-updater-client tf-periodic-heartbeat-client)
for name in "${NAMES[@]}"; do
  if docker container inspect "$name" >/dev/null 2>&1; then echo "Existing container: $name" >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo 'Existing test network; refusing reuse.' >&2; exit 1; fi
for image in "$PYTHON_IMAGE" "$ZEEK_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then docker pull "$image"; fi
done
CREATED=()
NET_CREATED=0
CAPTURE=
cleanup() {
  if [[ -n "$CAPTURE" ]]; then sudo kill -INT "$CAPTURE" 2>/dev/null || true; wait "$CAPTURE" 2>/dev/null || true; fi
  for name in "${CREATED[@]}"; do docker rm -f "$name" >/dev/null 2>&1 || true; done
  if [[ "$NET_CREATED" == 1 ]]; then docker network rm "$NET" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
docker network create --internal --subnet 198.18.0.0/16 --opt com.docker.network.bridge.name=br-tfperiodic "$NET" >/dev/null
NET_CREATED=1
BASE=(--network "$NET" --cap-drop ALL --security-opt no-new-privileges --read-only -v "$PWD/periodic_scenario.py:/scenario.py:ro")
for entry in 'tf-periodic-dns:53:dns' 'tf-periodic-web:10:http' 'tf-periodic-update:20:http' 'tf-periodic-heartbeat:30:http'; do
  IFS=: read -r name suffix kind <<< "$entry"
  docker run -d --name "$name" --ip "198.18.2.$suffix" "${BASE[@]}" "$PYTHON_IMAGE" python /scenario.py serve --kind "$kind" >/dev/null
  CREATED+=("$name")
done
sleep 2
python3 periodic_scenario.py plan --mode live --output "$RUN/manifest.json"
sudo -n tcpdump -i br-tfperiodic -U -s 0 -w "$PWD/$RUN/scenario.pcap" 'udp port 53 or tcp port 8000' > "$RUN/capture.txt" 2>&1 &
CAPTURE=$!
sleep 1
for entry in 'browser:11' 'updater:12' 'heartbeat:13'; do
  IFS=: read -r role suffix <<< "$entry"
  name="tf-periodic-$role-client"
  docker run -d --name "$name" --ip "198.18.1.$suffix" "${BASE[@]}" -v "$PWD/$RUN/manifest.json:/manifest.json:ro" "$PYTHON_IMAGE" python /scenario.py client --manifest /manifest.json --role "$role" >/dev/null
  CREATED+=("$name")
done
echo 'Live test started: 60 seconds; use docker ps / docker logs to observe clients.'
for role in browser updater heartbeat; do
  name="tf-periodic-$role-client"
  code=$(docker wait "$name")
  docker logs "$name" > "$RUN/$role.jsonl" 2>&1
  if [[ "$code" != 0 ]]; then echo "Client failed: $role (see local log)" >&2; exit 1; fi
done
sleep 1
sudo kill -INT "$CAPTURE"
wait "$CAPTURE" || true
CAPTURE=
sudo chown "$(id -u):$(id -g)" "$RUN/scenario.pcap"
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh -v "$PWD/$RUN:/input:ro" -v "$PWD/$RUN/zeek:/output" -w /output "$ZEEK_IMAGE" -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -C -r /input/scenario.pcap'
printf '%s\n' "$PYTHON_IMAGE" "$ZEEK_IMAGE" > "$RUN/images.txt"
printf '%s\n' "$RUN" > latest-periodic-live
echo "Live capture completed: $RUN"
