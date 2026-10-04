"""Isolated benign/cache controls and harmless heartbeat; standard library only."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import random
import socket
import struct
import time
from pathlib import Path

if __package__:
    from .periodic_scenario import DNS_IP, DOMAINS, answer_bytes, endpoint, make_manifest, query_bytes
else:
    from periodic_scenario import DNS_IP, DOMAINS, answer_bytes, endpoint, make_manifest, query_bytes

PROTOCOL = "cached-http-controls-v1"
SEED = 20261006


def plan() -> dict:
    manifest = make_manifest("live")
    rng = random.Random(SEED)
    manifest["protocol"] = PROTOCOL
    manifest["seed"] = SEED
    manifest["dns_cache_ttl_seconds"] = 300
    manifest["http_persistence"] = {"browser": True, "updater": False, "heartbeat": False}
    for event in manifest["events"]:
        event["path"] += ".txt"
        if event["role"] != "browser":
            event["at"] += rng.uniform(0, 0.25)
    manifest["events"].sort(key=lambda e: (e["at"], e["role"]))
    manifest["limitations"] = [
        "Isolated 60-second synthetic workload with real captured packets; not production traffic.",
        "Benign/simulated intent labels are not malware truth or detector inputs.",
        "DNS caches, HTTP persistence, variable browser payloads and polling jitter are controls.",
        "No TLS, encrypted DNS, actual malware, downloads or 24-hour collection.",
        "Capture is too short to evaluate sustained periodic or one-hour session detection.",
    ]
    return manifest


def write_plan(path: Path) -> None:
    with path.open("x") as file:
        json.dump(plan(), file, sort_keys=True, indent=2)
        file.write("\n")
    with path.with_suffix(".sha256").open("x") as file:
        file.write(hashlib.sha256(path.read_bytes()).hexdigest() + "\n")


def client(manifest: dict, role: str) -> None:
    cache = {}
    connections = {}
    dns_count = 0
    requests = 0
    try:
        for event in manifest["events"]:
            if event["role"] != role:
                continue
            time.sleep(max(0, event["at"] - time.time()))
            domain = event["domain"]
            if cache.get(domain, 0) <= time.monotonic():
                query = query_bytes(domain, dns_count + 1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(5)
                    sock.sendto(query, (DNS_IP, 53))
                    answer, peer = sock.recvfrom(4096)
                if peer[0] != DNS_IP or answer != answer_bytes(query):
                    raise ValueError("Unexpected synthetic DNS response")
                ttl = struct.unpack("!I", answer[-10:-6])[0]
                cache[domain] = time.monotonic() + ttl
                dns_count += 1
            ip = DOMAINS[domain]
            persistent = manifest["http_persistence"][role]
            conn = connections.setdefault(ip, http.client.HTTPConnection(ip, 8000, timeout=5)) if persistent else http.client.HTTPConnection(ip, 8000, timeout=5)
            try:
                conn.request("GET", event["path"], headers={
                    "Host": domain, "Connection": "keep-alive" if persistent else "close",
                })
                response = conn.getresponse()
                if response.status != 200 or not response.read().startswith(b"Synthetic local response"):
                    raise ValueError("Unexpected local HTTP response")
            finally:
                if not persistent:
                    conn.close()
            requests += 1
        print(json.dumps({"role": role, "http_requests": requests, "dns_queries": dns_count}), flush=True)
    finally:
        for conn in connections.values():
            conn.close()


def server(kind: str) -> None:
    if kind == "dns":
        endpoint("dns")
        return
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            size = 128 + sum(self.path.encode("ascii")) % 2000 if self.path.startswith("/page/") else 128
            body = b"Synthetic local response\n" + b"x" * size
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("plan")
    p.add_argument("--output", type=Path, required=True)
    c = commands.add_parser("client")
    c.add_argument("--manifest", type=Path, required=True)
    c.add_argument("--role", choices=("browser", "updater", "heartbeat"), required=True)
    s = commands.add_parser("serve")
    s.add_argument("--kind", choices=("dns", "http"), required=True)
    args = parser.parse_args()
    if args.command == "plan":
        write_plan(args.output)
    elif args.command == "client":
        client(json.loads(args.manifest.read_text()), args.role)
    else:
        server(args.kind)


if __name__ == "__main__":
    main()
