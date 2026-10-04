#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/threatfusion-lab"
RUN="results/cached-live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN/zeek"
NET=tf-lab-cached
PYTHON_IMAGE=python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ZEEK_IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
NAMES=(tf-cached-dns tf-cached-web tf-cached-update tf-cached-heartbeat tf-cached-browser-client tf-cached-updater-client tf-cached-heartbeat-client)
for name in "${NAMES[@]}"; do
  if docker container inspect "$name" >/dev/null 2>&1; then echo 'Existing cached workload container; refusing reuse.' >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo 'Existing cached workload network; refusing reuse.' >&2; exit 1; fi
for image in "$PYTHON_IMAGE" "$ZEEK_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then docker pull "$image"; fi
done
CREATED=()
NET_CREATED=0
CAPTURE=
OWNER="$RUN:$$"
cleanup() {
  if [[ -n "$CAPTURE" ]]; then sudo kill -INT "$CAPTURE" 2>/dev/null || true; wait "$CAPTURE" 2>/dev/null || true; fi
  for name in "${CREATED[@]}"; do
    if [[ $(docker inspect --format '{{ index .Config.Labels "org.threatfusion.lab.run" }}' "$name" 2>/dev/null) == "$OWNER" ]]; then
      docker rm -f "$name" >/dev/null 2>&1 || true
    fi
  done
  if [[ "$NET_CREATED" == 1 ]]; then docker network rm "$NET" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
docker network create --internal --subnet 198.18.0.0/16 --opt com.docker.network.bridge.name=br-tfcached "$NET" >/dev/null
NET_CREATED=1
BASE=(--network "$NET" --cap-drop ALL --security-opt no-new-privileges --read-only
  --label "org.threatfusion.lab.run=$OWNER"
  -v "$PWD/cached_workload.py:/scenario.py:ro" -v "$PWD/periodic_scenario.py:/periodic_scenario.py:ro")
for entry in 'tf-cached-dns:53:dns' 'tf-cached-web:10:http' 'tf-cached-update:20:http' 'tf-cached-heartbeat:30:http'; do
  IFS=: read -r name suffix kind <<< "$entry"
  CREATED+=("$name")
  docker run -d --name "$name" --ip "198.18.2.$suffix" "${BASE[@]}" "$PYTHON_IMAGE" python /scenario.py serve --kind "$kind" >/dev/null
done
sleep 2
python3 cached_workload.py plan --output "$RUN/manifest.json"
sudo -n tcpdump -i br-tfcached -U -s 0 -w "$PWD/$RUN/scenario.pcap" 'udp port 53 or tcp port 8000' > "$RUN/capture.txt" 2>&1 &
CAPTURE=$!
sleep 1
for entry in 'browser:11' 'updater:12' 'heartbeat:13'; do
  IFS=: read -r role suffix <<< "$entry"
  name="tf-cached-$role-client"
  CREATED+=("$name")
  docker run -d --name "$name" --ip "198.18.1.$suffix" "${BASE[@]}" -v "$PWD/$RUN/manifest.json:/manifest.json:ro" "$PYTHON_IMAGE" python /scenario.py client --manifest /manifest.json --role "$role" >/dev/null
done
echo 'Cached workload started: 60 seconds; isolated synthetic traffic only.'
for role in browser updater heartbeat; do
  name="tf-cached-$role-client"
  code=$(docker wait "$name")
  docker logs "$name" > "$RUN/$role.jsonl" 2>&1
  if [[ "$code" != 0 ]]; then echo 'Workload client failed; see local log.' >&2; exit 1; fi
done
sleep 1
sudo kill -INT "$CAPTURE"
wait "$CAPTURE" || true
CAPTURE=
sudo chown "$(id -u):$(id -g)" "$RUN/scenario.pcap"
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh -v "$PWD/$RUN:/input:ro" -v "$PWD/$RUN/zeek:/output" -w /output "$ZEEK_IMAGE" -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -C -r /input/scenario.pcap'
printf '%s\n' "$PYTHON_IMAGE" "$ZEEK_IMAGE" > "$RUN/images.txt"
printf '%s\n' "$RUN" > latest-cached-live
echo "Cached live capture completed: $RUN"
