"""Synthetic .test-only DNS and HTTP server; no forwarding to real DNS."""
import http.server
import socket
import struct
import threading


def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        data, peer = sock.recvfrom(4096)
        if len(data) < 17:
            continue
        offset = 12
        labels = []
        try:
            while data[offset]:
                length = data[offset]
                if length > 63:
                    raise ValueError("Unsupported DNS label")
                labels.append(data[offset + 1:offset + 1 + length].decode("ascii"))
                offset += 1 + length
            end = offset + 5
            qtype, qclass = struct.unpack("!HH", data[offset + 1:end])
        except (IndexError, UnicodeError, ValueError, struct.error):
            continue
        ok = ".".join(labels).lower() == "normal.test" and (qtype, qclass) == (1, 1)
        flags = 0x8180 if ok else 0x8183
        header = data[:2] + struct.pack("!HHHHH", flags, 1, int(ok), 0, 0)
        answer = b""
        if ok:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("172.30.80.53")
        sock.sendto(header + data[12:end] + answer, peer)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ThreatFusion synthetic lab - normal traffic only\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    threading.Thread(target=dns_server, daemon=True).start()
    http.server.HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
