#!/usr/bin/env bash
set -euo pipefail
umask 077
# Run only inside the isolated lab guest; no host sensor or published port.
cd "$HOME/threatfusion-lab"
RUN="results/dns-collector-live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN/zeek"
NET=tf-lab-dns-collector
PYTHON_IMAGE=python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ZEEK_IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
NAMES=(tf-dns-collector-server tf-dns-collector-udp tf-dns-collector-tcp)
for name in "${NAMES[@]}"; do
  if docker container inspect "$name" >/dev/null 2>&1; then echo 'Existing DNS fixture container; refusing reuse.' >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo 'Existing DNS fixture network; refusing reuse.' >&2; exit 1; fi
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
python3 dns_collector_workload.py plan > "$RUN/manifest.json"
sha256sum dns_collector_workload.py run_dns_collector_live.sh "$RUN/manifest.json" > "$RUN/pre-capture.sha256"
docker network create --internal --subnet 198.19.71.0/24 --opt com.docker.network.bridge.name=br-tfdns "$NET" >/dev/null
NET_CREATED=1
BASE=(--network "$NET" --cap-drop ALL --security-opt no-new-privileges --read-only
  --label "org.threatfusion.lab.run=$OWNER" -v "$PWD/dns_collector_workload.py:/scenario.py:ro")
CREATED+=(tf-dns-collector-server)
docker run -d --name tf-dns-collector-server --ip 198.19.71.53 "${BASE[@]}" "$PYTHON_IMAGE" python /scenario.py serve >/dev/null
sleep 2
sudo -n tcpdump -i br-tfdns -U -s 0 -w "$PWD/$RUN/scenario.pcap" 'port 53 and (udp or tcp)' > "$RUN/capture.txt" 2>&1 &
CAPTURE=$!
sleep 1
number=11
for protocol in udp tcp; do
  name="tf-dns-collector-$protocol"
  CREATED+=("$name")
  docker run -d --name "$name" --ip "198.19.71.$number" "${BASE[@]}" "$PYTHON_IMAGE" python /scenario.py client --protocol "$protocol" >/dev/null
  number=$((number+1))
done
for protocol in udp tcp; do
  code=$(docker wait "tf-dns-collector-$protocol")
  docker logs "tf-dns-collector-$protocol" > "$RUN/$protocol.txt" 2>&1
  if [[ "$code" != 0 ]]; then echo 'DNS fixture client failed; see private log.' >&2; exit 1; fi
done
sleep 1
sudo kill -INT "$CAPTURE"
wait "$CAPTURE" || true
CAPTURE=
sudo chown "$(id -u):$(id -g)" "$RUN/scenario.pcap"
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh -v "$PWD/$RUN:/input:ro" -v "$PWD/$RUN/zeek:/output" -w /output "$ZEEK_IMAGE" -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -C -r /input/scenario.pcap'
printf '%s\n' "$PYTHON_IMAGE" "$ZEEK_IMAGE" > "$RUN/images.txt"
printf '%s\n' "$RUN" > latest-dns-collector-live
echo "DNS collector capture completed: $RUN"
