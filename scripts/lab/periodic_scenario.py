"""Frozen synthetic periodic-control protocol; never contacts real destinations.

Replay generation uses dpkt from the project's environment. Live client/server
modes use only Python's standard library, inside the isolated guest test net.
"""

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
from datetime import datetime, timezone
from pathlib import Path

PROTOCOL = "periodic-controls-v1"
SEED = 20261004
DNS_IP = "198.18.2.53"
ROLES = {
    "browser": ("198.18.1.11", "198.18.2.10", "normal", "benign"),
    "updater": ("198.18.1.12", "198.18.2.20", "update", "benign"),
    "heartbeat": (
        "198.18.1.13", "198.18.2.30", "heartbeat", "controlled_suspicious_simulation"
    ),
}
DOMAINS = {
    "portal.lab.test": "198.18.2.10",
    "docs.lab.test": "198.18.2.10",
    "news.lab.test": "198.18.2.10",
    "updates.lab.test": "198.18.2.20",
    "heartbeat.lab.test": "198.18.2.30",
}
BODY = b"Synthetic lab response; no commands or malware.\n"


def make_manifest(mode: str) -> dict:
    rng = random.Random(SEED)
    replay = mode == "replay"
    duration = 86400 if replay else 60
    interval = 300 if replay else 2
    start = (
        datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()
        if replay else int(time.time()) + 8
    )
    events = []
    times = sorted(rng.sample(range(1, duration - 1), 240 if replay else 18))
    for index, offset in enumerate(times):
        events.append({
            "role": "browser", "at": start + offset,
            "domain": rng.choice(list(DOMAINS)[:3]),
            "path": f"/page/{index % 7}",
        })
    for role, domain, path in [
        ("updater", "updates.lab.test", "/updates"),
        ("heartbeat", "heartbeat.lab.test", "/heartbeat"),
    ]:
        for offset in range(0, duration, interval):
            events.append({"role": role, "at": start + offset, "domain": domain, "path": path})
    events.sort(key=lambda event: (event["at"], event["role"]))
    return {
        "schema": 1, "protocol": PROTOCOL, "seed": SEED, "mode": mode,
        "start_epoch": start, "represented_window_seconds": duration,
        "periodic_interval_seconds": interval, "roles": ROLES,
        "event_counts": {role: sum(e["role"] == role for e in events) for role in ROLES},
        "events": events,
        "limitations": [
            "Labels describe the lab's intent, not proof of malware.",
            "Benign updates and suspicious simulation intentionally share periodic timing.",
            "DNS is queried explicitly for each request; real clients may cache DNS.",
            "Replay timestamps represent a synthetic day, not a 24-hour live capture.",
            "No CTI, ML, tunneling, encrypted DNS or long-connection evaluation.",
        ],
    }


def write_manifest(path: Path, mode: str) -> dict:
    manifest = make_manifest(mode)
    # Exclusive creation prevents overwriting inspected evaluation inputs.
    with path.open("x") as file:
        json.dump(manifest, file, sort_keys=True, indent=2)
        file.write("\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_suffix(".sha256").write_text(digest + "\n")
    return manifest


def query_bytes(domain: str, ident: int) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in domain.split(".")
    ) + b"\0" + struct.pack("!HH", 1, 1)


def answer_bytes(query: bytes) -> bytes:
    offset = 12
    labels = []
    while query[offset]:
        size = query[offset]
        if size > 63:
            raise ValueError("Compressed/malformed question not supported in lab")
        label = query[offset + 1:offset + 1 + size]
        if len(label) != size:
            raise ValueError("Truncated question")
        labels.append(label.decode("ascii"))
        offset += 1 + size
    end = offset + 5
    qtype, qclass = struct.unpack("!HH", query[offset + 1:end])
    ip = DOMAINS.get(".".join(labels).lower()) if (qtype, qclass) == (1, 1) else None
    header = query[:2] + struct.pack("!HHHHH", 0x8180 if ip else 0x8183, 1, int(bool(ip)), 0, 0)
    answer = b""
    if ip:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return header + query[12:end] + answer


def request_bytes(event: dict) -> bytes:
    return (
        f"GET {event['path']} HTTP/1.1\r\nHost: {event['domain']}\r\n"
        "User-Agent: ThreatFusion-Lab/1\r\nConnection: close\r\n\r\n"
    ).encode("ascii")


def response_bytes() -> bytes:
    return (
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(BODY)}\r\n"
        "Content-Type: text/plain\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + BODY


def generate_replay(path: Path, manifest: dict) -> None:
    import dpkt

    frames = []
    def packet(at, src, dst, transport, proto):
        ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=64, data=transport)
        ip.len = len(ip)
        frame = dpkt.ethernet.Ethernet(
            src=b"\x02\x00\x00\x00\x00\x01",
            dst=b"\x02\x00\x00\x00\x00\x02", type=0x0800, data=ip,
        )
        frames.append((at, bytes(frame)))

    for index, event in enumerate(manifest["events"]):
        at = event["at"]
        src, dst, _, _ = ROLES[event["role"]]
        port = 32000 + index
        query = query_bytes(event["domain"], index + 1)
        answer = answer_bytes(query)
        udp = dpkt.udp.UDP(sport=port, dport=53, data=query)
        udp.ulen = len(udp)
        packet(at, src, DNS_IP, udp, 17)
        udp = dpkt.udp.UDP(sport=53, dport=port, data=answer)
        udp.ulen = len(udp)
        packet(at + .001, DNS_IP, src, udp, 17)
        cseq, sseq = 100000 + index * 10000, 400000 + index * 10000
        request, response = request_bytes(event), response_bytes()
        syn, ack, push, fin = dpkt.tcp.TH_SYN, dpkt.tcp.TH_ACK, dpkt.tcp.TH_PUSH, dpkt.tcp.TH_FIN
        steps = [
            (0.01, True, cseq, 0, syn, b""),
            (0.02, False, sseq, cseq + 1, syn | ack, b""),
            (0.03, True, cseq + 1, sseq + 1, ack, b""),
            (0.04, True, cseq + 1, sseq + 1, push | ack, request),
            (0.05, False, sseq + 1, cseq + 1 + len(request), ack, b""),
            (0.06, False, sseq + 1, cseq + 1 + len(request), push | ack, response),
            (0.07, True, cseq + 1 + len(request), sseq + 1 + len(response), ack, b""),
            (0.08, True, cseq + 1 + len(request), sseq + 1 + len(response), fin | ack, b""),
            (0.09, False, sseq + 1 + len(response), cseq + 2 + len(request), fin | ack, b""),
            (0.10, True, cseq + 2 + len(request), sseq + 2 + len(response), ack, b""),
        ]
        for delay, forward, seq, acknowledgment, flags, payload in steps:
            tcp = dpkt.tcp.TCP(
                sport=port if forward else 8000, dport=8000 if forward else port,
                seq=seq, ack=acknowledgment, flags=flags, win=65535, data=payload,
            )
            tcp.off = 5
            packet(at + delay, src if forward else dst, dst if forward else src, tcp, 6)
    with path.open("xb") as file:
        writer = dpkt.pcap.Writer(file)
        for at, frame in sorted(frames, key=lambda entry: entry[0]):
            writer.writepkt(frame, ts=at)
        writer.close()


def live_client(manifest: dict, role: str) -> None:
    count = 0
    for event in manifest["events"]:
        if event["role"] != role:
            continue
        time.sleep(max(0, event["at"] - time.time()))
        query = query_bytes(event["domain"], count + 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(query, (DNS_IP, 53))
            response, peer = sock.recvfrom(4096)
            if peer[0] != DNS_IP or response != answer_bytes(query):
                raise ValueError("Unexpected synthetic DNS response")
        conn = http.client.HTTPConnection(DOMAINS[event["domain"]], 8000, timeout=5)
        try:
            conn.request("GET", event["path"], headers={"Host": event["domain"], "Connection": "close"})
            response = conn.getresponse()
            if response.status != 200 or response.read() != BODY:
                raise ValueError("Unexpected synthetic HTTP response")
        finally:
            conn.close()
        count += 1
        print(json.dumps({"role": role, "domain": event["domain"], "completed": count}), flush=True)


def endpoint(kind: str) -> None:
    if kind == "dns":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("0.0.0.0", 53))
            while True:
                query, peer = sock.recvfrom(4096)
                try:
                    response = answer_bytes(query)
                except (IndexError, UnicodeError, ValueError, struct.error):
                    continue
                sock.sendto(response, peer)
    else:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(BODY)))
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(BODY)
        http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--mode", choices=["replay", "live"], required=True)
    plan.add_argument("--output", type=Path, required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--output-dir", type=Path, required=True)
    client = commands.add_parser("client")
    client.add_argument("--manifest", type=Path, required=True)
    client.add_argument("--role", choices=ROLES, required=True)
    server = commands.add_parser("serve")
    server.add_argument("--kind", choices=["dns", "http"], required=True)
    args = parser.parse_args()
    if args.command == "plan":
        write_manifest(args.output, args.mode)
    elif args.command == "replay":
        args.output_dir.mkdir(parents=True, exist_ok=False)
        manifest = write_manifest(args.output_dir / "manifest.json", "replay")
        generate_replay(args.output_dir / "scenario.pcap", manifest)
        print(json.dumps({"mode": "synthetic_replay", "counts": manifest["event_counts"]}))
    elif args.command == "client":
        live_client(json.loads(args.manifest.read_text()), args.role)
    else:
        endpoint(args.kind)


if __name__ == "__main__":
    main()
