"""Harmless TCP attempt controls on a guest-only Docker network."""

from __future__ import annotations

import argparse
import json
import random
import socket
import threading
import time

PROTOCOL = "tcp-attempt-live-v1"
ROLES = ("vertical", "horizontal", "outage", "healthy")
SERVERS = tuple(f"198.19.2.{i}" for i in range(10, 34))
COUNTS = {"vertical": 24, "horizontal": 24, "outage": 36, "healthy": 36}


def plan():
    rng = random.Random(20261123)
    events = {}
    for role in ROLES:
        entries = [
            {
                "host": SERVERS[i]
                if role == "horizontal"
                else SERVERS[1]
                if role == "outage"
                else SERVERS[0],
                "port": 20000 + i
                if role == "vertical"
                else 19001
                if role == "horizontal"
                else 19002
                if role == "outage"
                else 19000,
                "pause_seconds": rng.uniform(0.02, 0.06),
            }
            for i in range(COUNTS[role])
        ]
        rng.shuffle(entries)
        events[role] = entries
    return {
        "protocol": PROTOCOL,
        "seed": 20261123,
        "events": events,
        "expected_states": {"REJ": 84, "SF": 36},
        "expected_attempt_patterns": 3,
        "limitations": [
            "Synthetic live packets on an isolated guest Docker bridge, not field traffic.",
            "The outage role is deliberately benign but produces review work.",
            "No TLS, real malware, ML, CTI or production efficacy measurement.",
        ],
    }


def exchange(sock):
    with sock:
        sock.settimeout(5)
        if sock.recv(1) != b"q":
            raise ValueError("Unexpected local request")
        sock.sendall(b"a")
        if sock.recv(1) != b"":
            raise ValueError("Expected local client FIN")
        sock.shutdown(socket.SHUT_WR)


def serve():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 19000))
        server.listen(32)
        print("ready", flush=True)
        while True:
            sock, _ = server.accept()
            threading.Thread(target=exchange, args=(sock,), daemon=True).start()


def client(manifest, role):
    for event in manifest["events"][role]:
        try:
            with socket.socket() as sock:
                sock.settimeout(5)
                sock.connect((event["host"], event["port"]))
                if role != "healthy":
                    raise ValueError("Expected a closed local control port")
                sock.sendall(b"q")
                if sock.recv(1) != b"a":
                    raise ValueError("Unexpected local response")
                sock.shutdown(socket.SHUT_WR)
                if sock.recv(1) != b"":
                    raise ValueError("Expected orderly close")
        except ConnectionRefusedError:
            if role == "healthy":
                raise
        time.sleep(event["pause_seconds"])
    print(
        json.dumps(
            {"role": role, "attempts": len(manifest["events"][role]), "complete": True}
        ),
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "serve", "client"))
    parser.add_argument("--role", choices=ROLES)
    args = parser.parse_args()
    if args.command == "plan":
        print(json.dumps(plan(), sort_keys=True, indent=2))
    elif args.command == "serve":
        serve()
    else:
        if args.role is None:
            parser.error("Client role is required")
        client(plan(), args.role)


if __name__ == "__main__":
    main()
