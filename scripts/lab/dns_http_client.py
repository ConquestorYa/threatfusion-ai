"""One synthetic DNS query, then a local HTTP request, with strict assertions."""
import socket
import struct
import urllib.request

def main():
    query = struct.pack("!HHHHHH", 12345, 0x0100, 1, 0, 0, 0)
    query += b"\x06normal\x04test\x00" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, ("172.30.80.53", 53))
        response, peer = sock.recvfrom(4096)
        assert peer[0] == "172.30.80.53"
        assert response[:2] == query[:2]
        assert struct.unpack("!H", response[2:4])[0] & 0xF == 0
        assert response[-4:] == socket.inet_aton("172.30.80.53")
    with urllib.request.urlopen("http://172.30.80.53:8000/normal", timeout=5) as result:
        assert result.status == 200
        assert b"synthetic lab" in result.read()
    print("DNS and local HTTP succeeded")


if __name__ == "__main__":
    main()
