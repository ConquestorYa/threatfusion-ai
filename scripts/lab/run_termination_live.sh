#!/usr/bin/env bash
set -euo pipefail
umask 077
# Run ONLY inside the disposable lab guest, never on the user's real network.
cd "$HOME/threatfusion-lab"
RUN="results/termination-live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$RUN/zeek"
NET=tf-lab-termination
PYTHON_IMAGE=python@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3
ZEEK_IMAGE=activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5
NAMES=(tf-termination-server tf-termination-client)
for name in "${NAMES[@]}"; do
  if docker container inspect "$name" >/dev/null 2>&1; then echo 'Existing termination workload container; refusing reuse.' >&2; exit 1; fi
done
if docker network inspect "$NET" >/dev/null 2>&1; then echo 'Existing termination network; refusing reuse.' >&2; exit 1; fi
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
python3 termination_workload.py plan > "$RUN/manifest.json"
sha256sum termination_workload.py run_termination_live.sh "$RUN/manifest.json" > "$RUN/pre-capture.sha256"
docker network create --internal --subnet 198.19.0.0/16 --opt com.docker.network.bridge.name=br-tfterm "$NET" >/dev/null
NET_CREATED=1
BASE=(--network "$NET" --cap-drop ALL --security-opt no-new-privileges --read-only
  --label "org.threatfusion.lab.run=$OWNER" -v "$PWD/termination_workload.py:/scenario.py:ro")
CREATED+=(tf-termination-server)
docker run -d --name tf-termination-server --ip 198.19.2.10 "${BASE[@]}" "$PYTHON_IMAGE" python /scenario.py serve >/dev/null
sleep 2
sudo -n tcpdump -i br-tfterm -U -s 0 -w "$PWD/$RUN/scenario.pcap" 'tcp portrange 18001-18006' > "$RUN/capture.txt" 2>&1 &
CAPTURE=$!
sleep 1
CREATED+=(tf-termination-client)
docker run -d --name tf-termination-client --ip 198.19.1.11 "${BASE[@]}" "$PYTHON_IMAGE" python /scenario.py client >/dev/null
COMPLETE=0
for _ in {1..25}; do
  if docker logs tf-termination-client 2>/dev/null | grep -qx 'complete'; then COMPLETE=1; break; fi
  if [[ $(docker inspect --format '{{.State.Running}}' tf-termination-client) != true ]]; then break; fi
  sleep 1
done
docker logs tf-termination-client > "$RUN/client.txt" 2>&1
docker logs tf-termination-server > "$RUN/server.txt" 2>&1
if [[ "$COMPLETE" != 1 ]]; then echo 'Termination client failed; see local logs.' >&2; exit 1; fi
sleep 1
sudo kill -INT "$CAPTURE"
wait "$CAPTURE" || true
CAPTURE=
sudo chown "$(id -u):$(id -g)" "$RUN/scenario.pcap"
docker run --rm --network none --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges --entrypoint /bin/sh -v "$PWD/$RUN:/input:ro" -v "$PWD/$RUN/zeek:/output" -w /output "$ZEEK_IMAGE" -c 'unset ZEEKPATH; exec /usr/local/zeek/bin/zeek -C -r /input/scenario.pcap'
printf '%s\n' "$PYTHON_IMAGE" "$ZEEK_IMAGE" > "$RUN/images.txt"
printf '%s\n' "$RUN" > latest-termination-live
echo "Termination capture completed: $RUN"
