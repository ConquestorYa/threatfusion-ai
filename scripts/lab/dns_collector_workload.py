"""Harmless .test-only UDP and persistent TCP DNS fixture; never forwards queries."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time

REQUESTS = (
    ["normal.test"] * 4
    + ["missing.test"] * 3
    + ["outage.test"] * 3
    + ["silent.test"] * 2
)


def plan():
    return {
        "protocol": "dns-collector-live-v1",
        "requests_per_transport": 12,
        "transports": ["udp", "tcp"],
        "success": 8,
        "nxdomain": 6,
        "servfail": 6,
        "unanswered": 4,
        "expected_dns_records": 24,
        "expected_connection_records": 2,
        "expected_dns_review_groups": 0,
        "scope": "Two synthetic clients; one reused UDP socket and one persistent TCP connection; .test names only.",
    }


def query(name, ident, qtype):
    labels = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
    )
    return (
        struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
        + labels
        + b"\0"
        + struct.pack("!HH", qtype, 1)
    )


def response(data):
    if len(data) < 17 or len(data) > 4096:
        raise ValueError("Invalid fixture query")
    offset, labels = 12, []
    while data[offset]:
        length = data[offset]
        if length > 63:
            raise ValueError("Unsupported fixture label")
        labels.append(data[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
    qtype, qclass = struct.unpack("!HH", data[offset + 1 : offset + 5])
    name = ".".join(labels)
    if name not in REQUESTS or qtype not in (1, 28) or qclass != 1:
        raise ValueError("Only declared fixture queries are allowed")
    if name == "silent.test":
        return None
    code = {"normal.test": 0, "missing.test": 3, "outage.test": 2}[name]
    answer = b""
    if code == 0:
        packed = socket.inet_pton(
            socket.AF_INET if qtype == 1 else socket.AF_INET6,
            "198.19.71.53" if qtype == 1 else "2001:db8:71::53",
        )
        answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(packed)) + packed
    return (
        data[:2]
        + struct.pack("!HHHHH", 0x8180 + code, 1, int(code == 0), 0, 0)
        + data[12 : offset + 5]
        + answer
    )


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("Fixture TCP socket closed")
        data.extend(chunk)
    return bytes(data)


def serve():
    def udp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("0.0.0.0", 53))
            while True:
                data, peer = sock.recvfrom(4096)
                answer = response(data)
                if answer is not None:
                    sock.sendto(answer, peer)

    def connection(sock):
        with sock:
            try:
                while True:
                    (size,) = struct.unpack("!H", read_exact(sock, 2))
                    if size > 4096:
                        raise ValueError("Oversized fixture DNS message")
                    answer = response(read_exact(sock, size))
                    if answer is not None:
                        sock.sendall(struct.pack("!H", len(answer)) + answer)
            except (EOFError, OSError, ValueError):
                return

    threading.Thread(target=udp, daemon=True).start()
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 53))
        server.listen()
        while True:
            sock, _ = server.accept()
            threading.Thread(target=connection, args=(sock,), daemon=True).start()


def client(protocol):
    with socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    ) as sock:
        sock.settimeout(0.75)
        sock.connect(("198.19.71.53", 53))
        for ident, name in enumerate(REQUESTS):
            data = query(name, 30000 + ident, 1 if ident % 2 == 0 else 28)
            sock.sendall(
                data if protocol == "udp" else struct.pack("!H", len(data)) + data
            )
            try:
                answer = (
                    sock.recv(4096)
                    if protocol == "udp"
                    else read_exact(sock, struct.unpack("!H", read_exact(sock, 2))[0])
                )
            except socket.timeout:
                if name != "silent.test":
                    raise
            else:
                assert name != "silent.test" and answer[:2] == data[:2]
                expected = {"normal.test": 0, "missing.test": 3, "outage.test": 2}[name]
                assert answer[3] & 15 == expected
            time.sleep(0.05)
    print(json.dumps({"protocol": protocol, "requests": len(REQUESTS)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "serve", "client"))
    parser.add_argument("--protocol", choices=("udp", "tcp"), default="udp")
    args = parser.parse_args()
    if args.action == "plan":
        print(json.dumps(plan(), indent=2))
    elif args.action == "serve":
        serve()
    else:
        client(args.protocol)
