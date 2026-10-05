"""Declared two-hour synthetic review workload, with caching and shared resolvers."""

from __future__ import annotations

import argparse
import hashlib
import random
import socket
import struct
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.periodic_scenario import query_bytes

PROTOCOL = "review-workload-v1"
START = 1788220800  # 2026-09-01 UTC; represented time, never live duration.
DURATION = 7200
DNS_SERVER = "198.18.2.53"
SHARED_RESOLVER = "198.18.1.250"
PROFILES = (
    ("irregular-browser", "benign", "browser", 900),
    ("regular-updater", "benign", "regular", 900),
    ("jittered-updater", "benign", "jitter", 900),
    ("regular-heartbeat", "controlled_simulation", "regular", 900),
    ("wide-jitter-heartbeat", "controlled_simulation", "wide", 900),
    ("cached-polling", "benign", "regular", 120),
    ("shared-resolver-normal", "benign", "regular", 900),
    ("shared-resolver-simulation", "controlled_simulation", "regular", 900),
    ("benign-outage", "benign", "failure", 900),
    ("sparse-attempt-simulation", "controlled_simulation", "failure", 900),
    ("normal-long-stream", "benign", "stream", 900),
    ("simulated-long-stream", "controlled_simulation", "stream", 900),
)


def manifest(seed):
    rng = random.Random(seed)
    roles, events = {}, []
    for index, (name, intent, schedule, ttl) in enumerate(PROFILES):
        client, server = f"198.18.1.{101 + index}", f"198.18.2.{101 + index}"
        shared = name.startswith("shared-resolver")
        roles[name] = {
            "client": client,
            "server": server,
            "intent": intent,
            "schedule": schedule,
            "ttl_seconds": ttl,
            "dns_origin": SHARED_RESOLVER if shared else client,
            "domain": "shared.lab.test" if shared else "poll.lab.test",
        }
        if schedule == "browser":
            offsets = sorted(rng.sample(range(1, DURATION - 1), 80))
        elif schedule == "failure":
            offsets = list(range(0, DURATION, 600))
        else:
            offsets, at = [], 0
            jitter = {"jitter": 30, "wide": 90}.get(schedule, 0)
            while at < DURATION:
                offsets.append(at)
                at += 120 + rng.randint(-jitter, jitter)
        expires = -1
        for offset in offsets:
            # Each endpoint's DNS cache is independent; shared resolver origins
            # intentionally remain indistinguishable in the DNS-only product view.
            dns = offset >= expires
            if dns:
                expires = offset + ttl
            events.append({"role": name, "at": START + offset, "dns": dns})
    return {
        "protocol": PROTOCOL,
        "seed": seed,
        "represented_seconds": DURATION,
        "roles": roles,
        "events": sorted(events, key=lambda e: (e["at"], e["role"])),
        "limitations": [
            "Synthetic replay, not a two-hour live capture or independent malware truth.",
            "Benign and simulated roles intentionally overlap observable behavior.",
            "No ML, CTI, expected declarations, DNS tunneling or endpoint software identity.",
            "Shared DNS resolver observations cannot identify individual originating endpoints.",
        ],
    }


def generate(path, plan):
    import dpkt

    frames, streams = [], {}

    def packet(at, source, target, transport, protocol):
        ip = dpkt.ip.IP(
            src=socket.inet_aton(source),
            dst=socket.inet_aton(target),
            p=protocol,
            ttl=64,
            data=transport,
        )
        ip.len = len(ip)
        frame = dpkt.ethernet.Ethernet(
            src=b"\x02\0\0\0\0\x01", dst=b"\x02\0\0\0\0\x02", type=0x0800, data=ip
        )
        frames.append((at, bytes(frame)))

    for index, event in enumerate(plan["events"]):
        role = plan["roles"][event["role"]]
        at, source, target = event["at"], role["client"], role["server"]
        port = 32000 + index
        failed = role["schedule"] == "failure"
        if event["dns"]:
            query = query_bytes(role["domain"], index + 1)
            header = query[:2] + struct.pack(
                "!HHHHH", 0x8182 if failed else 0x8180, 1, 0 if failed else 1, 0, 0
            )
            answer = header + query[12:]
            if not failed:
                answer += (
                    b"\xc0\x0c"
                    + struct.pack("!HHIH", 1, 1, role["ttl_seconds"], 4)
                    + socket.inet_aton(target)
                )
            for delta, forward, data in ((0, True, query), (0.001, False, answer)):
                udp = dpkt.udp.UDP(
                    sport=port if forward else 53,
                    dport=53 if forward else port,
                    data=data,
                )
                udp.ulen = len(udp)
                packet(
                    at + delta,
                    role["dns_origin"] if forward else DNS_SERVER,
                    DNS_SERVER if forward else role["dns_origin"],
                    udp,
                    17,
                )
        request = (
            f"GET /observe HTTP/1.1\r\nHost: {role['domain']}\r\n"
            "User-Agent: Synthetic-Lab/1\r\n\r\n"
        ).encode()
        body = b"Harmless synthetic response.\n" * (
            1 + index % 3 if role["schedule"] == "browser" else 1
        )
        response = (
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
        )
        syn, ack, push, fin = (
            dpkt.tcp.TH_SYN,
            dpkt.tcp.TH_ACK,
            dpkt.tcp.TH_PUSH,
            dpkt.tcp.TH_FIN,
        )
        persistent = role["schedule"] == "stream"
        new = not persistent or event["role"] not in streams
        if new:
            cseq, sseq = 100000 + index * 10000, 400000 + index * 10000
        else:
            port, cseq, sseq, _ = streams[event["role"]]
        steps = []
        if new:
            steps.append((0.01, True, cseq, 0, syn, b""))
            if not failed:
                steps.extend(
                    [
                        (0.02, False, sseq, cseq + 1, syn | ack, b""),
                        (0.03, True, cseq + 1, sseq + 1, ack, b""),
                    ]
                )
                cseq, sseq = cseq + 1, sseq + 1
        if not failed:
            steps.extend(
                [
                    (0.04, True, cseq, sseq, push | ack, request),
                    (0.05, False, sseq, cseq + len(request), ack, b""),
                    (0.06, False, sseq, cseq + len(request), push | ack, response),
                    (0.07, True, cseq + len(request), sseq + len(response), ack, b""),
                ]
            )
            cseq, sseq = cseq + len(request), sseq + len(response)
            if not persistent:
                steps.extend(
                    [
                        (0.08, True, cseq, sseq, fin | ack, b""),
                        (0.09, False, sseq, cseq + 1, fin | ack, b""),
                        (0.10, True, cseq + 1, sseq + 1, ack, b""),
                    ]
                )
        for delta, forward, seq, acknowledgment, flags, payload in steps:
            tcp = dpkt.tcp.TCP(
                sport=port if forward else 8000,
                dport=8000 if forward else port,
                seq=seq,
                ack=acknowledgment,
                flags=flags,
                win=65535,
                data=payload,
            )
            tcp.off = 5
            packet(
                at + delta,
                source if forward else target,
                target if forward else source,
                tcp,
                6,
            )
        if persistent:
            streams[event["role"]] = port, cseq, sseq, at
    for name, (port, cseq, sseq, at) in streams.items():
        role = plan["roles"][name]
        for delta, forward, seq, acknowledgment, flags in (
            (0.08, True, cseq, sseq, fin | ack),
            (0.09, False, sseq, cseq + 1, fin | ack),
            (0.10, True, cseq + 1, sseq + 1, ack),
        ):
            tcp = dpkt.tcp.TCP(
                sport=port if forward else 8000,
                dport=8000 if forward else port,
                seq=seq,
                ack=acknowledgment,
                flags=flags,
                win=65535,
            )
            tcp.off = 5
            packet(
                at + delta,
                role["client"] if forward else role["server"],
                role["server"] if forward else role["client"],
                tcp,
                6,
            )
    with path.open("xb") as file:
        writer = dpkt.pcap.Writer(file)
        for at, frame in sorted(frames):
            writer.writepkt(frame, ts=at)
        writer.close()
    path.chmod(0o600)


def create(root, seed):
    root = private_root(root)
    plan = manifest(seed)
    write_new(root / "manifest.json", plan)
    generate(root / "scenario.pcap", plan)
    write_new(
        root / "input-hashes.json",
        {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("manifest.json", "scenario.pcap")
        },
    )
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    create(args.root, args.seed)
