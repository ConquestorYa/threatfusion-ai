"""Harmless real TCP termination controls, for the isolated guest Docker lab."""
from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time

PROTOCOL = "tcp-termination-live-v1"
SERVER_IP = "198.19.2.10"
MODES = ("SF", "RSTO", "RSTR", "S2", "S3", "REJ")
ATTEMPTS = 12
PORT_BASE = 18001
REQUEST = b"local-request-01"
RESPONSE = b"local-response01"


def receive(sock, expected):
    data = b""
    while len(data) < len(expected):
        part = sock.recv(len(expected) - len(data))
        if not part:
            raise ValueError("Incomplete local exchange")
        data += part
    if data != expected:
        raise ValueError("Unexpected local exchange")


def reset(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def exchange(sock, mode):
    with sock:
        sock.settimeout(10)
        receive(sock, REQUEST)
        sock.sendall(RESPONSE)
        if mode == "RSTR":
            receive(sock, b"done")
            reset(sock)
        elif mode == "S3":
            sock.shutdown(socket.SHUT_WR)
            time.sleep(60)  # Responder FIN only inside capture window.
        elif mode == "S2":
            if sock.recv(1) != b"":
                raise ValueError("Expected originator FIN")
            time.sleep(60)  # Originator FIN only inside capture window.
        elif mode == "RSTO":
            try:
                sock.recv(1)
            except ConnectionResetError:
                pass
        else:
            if sock.recv(1) != b"":
                raise ValueError("Expected orderly close")
            sock.shutdown(socket.SHUT_WR)


def listener(mode, port):
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(32)
        while True:
            sock, _ = server.accept()
            threading.Thread(target=exchange, args=(sock, mode), daemon=True).start()


def serve():
    for index, mode in enumerate(MODES[:-1]):
        threading.Thread(target=listener, args=(mode, PORT_BASE + index), daemon=True).start()
    print("ready", flush=True)
    threading.Event().wait()


def client():
    held = []
    for index, mode in enumerate(MODES):
        for _ in range(ATTEMPTS):
            sock = socket.socket()
            sock.settimeout(5)
            try:
                sock.connect((SERVER_IP, PORT_BASE + index))
                if mode == "REJ":
                    raise ValueError("Expected a closed local test port")
                sock.sendall(REQUEST)
                receive(sock, RESPONSE)
                if mode == "RSTO":
                    reset(sock)
                elif mode == "RSTR":
                    sock.sendall(b"done")
                    try:
                        sock.recv(1)
                    except ConnectionResetError:
                        pass
                    else:
                        raise ValueError("Expected responder reset")
                    sock.close()
                elif mode == "S2":
                    sock.shutdown(socket.SHUT_WR)
                    held.append(sock)
                elif mode == "S3":
                    if sock.recv(1) != b"":
                        raise ValueError("Expected responder FIN")
                    held.append(sock)
                else:
                    sock.shutdown(socket.SHUT_WR)
                    if sock.recv(1) != b"":
                        raise ValueError("Expected orderly responder close")
                    sock.close()
            except ConnectionRefusedError:
                sock.close()
                if mode != "REJ":
                    raise
            time.sleep(0.1)
        print(json.dumps({"mode": mode, "attempts": ATTEMPTS}), flush=True)
    print("complete", flush=True)
    time.sleep(60)  # Capture stops before held sockets close.


def plan():
    return {"protocol": PROTOCOL, "attempts_per_mode": ATTEMPTS,
            "ports": {mode: PORT_BASE + i for i, mode in enumerate(MODES)},
            "expected_states": {mode: ATTEMPTS for mode in MODES},
            "expected_review_groups": 0,
            "limitations": ["Short synthetic isolated capture; not malware truth or field efficacy.",
                            "No one-hour duration or 30-minute periodicity gate is exercised.",
                            "S2/S3 are deliberately incomplete when the capture stops."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "serve", "client"))
    args = parser.parse_args()
    if args.command == "plan":
        print(json.dumps(plan(), indent=2, sort_keys=True))
    elif args.command == "serve":
        serve()
    else:
        client()


if __name__ == "__main__":
    main()
