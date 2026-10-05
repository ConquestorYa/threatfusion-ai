#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$HOME/threatfusion-lab"
SECONDS_REQUESTED=${1:-1200}
python3 rotation_workload.py plan --seconds "$SECONDS_REQUESTED" >/dev/null
RUN="results/rotation-live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN/zeek"
# Root keeps NET_RAW effective; only its dedicated group-writable output is mounted.
# The enclosing results/run directory stays private to the lab user.
chmod 770 "$RUN/zeek"
NET=tf-lab-rotation
PYTHON_IMAGE=python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ZEEK_IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
NAMES=(tf-rotation-server tf-rotation-sensor tf-rotation-udp tf-rotation-tcp)
for name in "${NAMES[@]}"; do
  if docker inspect "$name" >/dev/null 2>&1; then echo 'Existing rotation container; refusing reuse.' >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo 'Existing rotation network; refusing reuse.' >&2; exit 1; fi
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
for image in "$PYTHON_IMAGE" "$ZEEK_IMAGE"; do
  if ! docker image inspect "$image" >/dev/null 2>&1; then docker pull "$image"; fi
done
python3 rotation_workload.py plan --seconds "$SECONDS_REQUESTED" > "$RUN/manifest.json"
printf '%s\n' 'redef Log::default_rotation_interval = 30secs;' > "$RUN/rotation.zeek"
chmod 640 "$RUN/rotation.zeek"
sha256sum rotation_workload.py dns_collector_workload.py run_rotation_live.sh "$RUN/rotation.zeek" "$RUN/manifest.json" > "$RUN/pre-capture.sha256"
docker network create --internal --subnet 198.19.71.0/24 --opt com.docker.network.bridge.name=br-tfrotate "$NET" >/dev/null
NET_CREATED=1
BASE=(--network "$NET" --cap-drop ALL --security-opt no-new-privileges --read-only
  --label "org.threatfusion.lab.run=$OWNER" -v "$PWD/dns_collector_workload.py:/dns_fixture.py:ro")
CREATED+=(tf-rotation-server)
docker run -d --name tf-rotation-server --ip 198.19.71.53 "${BASE[@]}" "$PYTHON_IMAGE" python /dns_fixture.py serve >/dev/null
sleep 2
sudo -n tcpdump -i br-tfrotate -U -s 0 -w "$PWD/$RUN/scenario.pcap" 'port 53 and (udp or tcp)' > "$RUN/capture.txt" 2>&1 &
CAPTURE=$!
CREATED+=(tf-rotation-sensor)
docker run -d --name tf-rotation-sensor --network host --user "0:$(id -g)" --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges --read-only --label "org.threatfusion.lab.run=$OWNER" --entrypoint /bin/sh -v "$PWD/$RUN/zeek:/output" -v "$PWD/$RUN/rotation.zeek:/rotation.zeek:ro" -w /output "$ZEEK_IMAGE" -c 'umask 007; unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -C -i br-tfrotate -f "port 53" /rotation.zeek' >/dev/null
sleep 2
if [[ $(docker inspect --format '{{.State.Running}}' tf-rotation-sensor) != true ]]; then
  docker logs tf-rotation-sensor > "$RUN/sensor.txt" 2>&1
  echo 'Live sensor startup failed; see private sensor log.' >&2
  exit 1
fi
printf '%s\n' "$RUN" > latest-rotation-live
number=11
for protocol in udp tcp; do
  name="tf-rotation-$protocol"
  CREATED+=("$name")
  docker run -d --name "$name" --ip "198.19.71.$number" "${BASE[@]}" -v "$PWD/rotation_workload.py:/scenario.py:ro" "$PYTHON_IMAGE" python /scenario.py client --protocol "$protocol" --seconds "$SECONDS_REQUESTED" >/dev/null
  number=$((number+1))
done
for protocol in udp tcp; do
  code=$(docker wait "tf-rotation-$protocol")
  docker logs "tf-rotation-$protocol" > "$RUN/$protocol.txt" 2>&1
  if [[ "$code" != 0 ]]; then echo 'Rotation client failed; see private log.' >&2; exit 1; fi
done
docker kill --signal INT tf-rotation-sensor >/dev/null
code=$(docker wait tf-rotation-sensor)
docker logs tf-rotation-sensor > "$RUN/sensor.txt" 2>&1
if [[ "$code" != 0 ]]; then echo 'Sensor shutdown failed; see private log.' >&2; exit 1; fi
sudo kill -INT "$CAPTURE"
wait "$CAPTURE" || true
CAPTURE=
sudo chown "$(id -u):$(id -g)" "$RUN/scenario.pcap"
sudo chown -R "$(id -u):$(id -g)" "$RUN/zeek"
chmod 700 "$RUN/zeek"
printf '%s\n' "$PYTHON_IMAGE" "$ZEEK_IMAGE" > "$RUN/images.txt"
echo "Rotation capture completed: $RUN"
