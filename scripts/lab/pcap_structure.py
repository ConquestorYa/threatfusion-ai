"""Bounded, complete capture qualification for offline lab inputs.

PCAPNG support is deliberately limited to Ethernet 1.0 sections with timestamped
Enhanced Packet Blocks. Other packet/unknown blocks fail closed, never disappear
from the packet count. See draft-ietf-opsawg-pcapng-06 sections 3 and 4.
"""
from __future__ import annotations

import struct

from scripts.lab.evaluate_review_workload import validate_pcap

SHB = b"\x0a\x0d\x0d\x0a"
MAX_BLOCK = 16 * 1024 * 1024 + 65536


def options(data, endian, *, interface=False):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("Truncated PCAPNG option header")
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            if length or offset != len(data):
                raise ValueError("Invalid PCAPNG option terminator")
            return
        padded = (length + 3) & ~3
        if offset + padded > len(data):
            raise ValueError("Truncated PCAPNG option value")
        if interface and ((code == 9 and length != 1) or (code == 14 and length != 8)):
            raise ValueError("Invalid PCAPNG timestamp option")
        offset += padded
    if data:
        raise ValueError("Missing PCAPNG option terminator")


def validate_capture(path, *, max_bytes):
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError("Capture exceeds declared acquisition bound")
    with path.open("rb") as file:
        if file.read(4) != SHB:
            return validate_pcap(path, max_bytes=max_bytes)
        file.seek(0)
        endian, interfaces, packets, section_end = None, [], 0, None
        while header := file.read(8):
            start = file.tell() - len(header)
            if len(header) != 8:
                raise ValueError("Truncated PCAPNG block header")
            section = header[:4] == SHB
            if section:
                if section_end is not None and start != section_end:
                    raise ValueError("PCAPNG section length mismatch")
                magic = file.read(4)
                endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(magic)
                if endian is None:
                    raise ValueError("Invalid PCAPNG byte-order magic")
            elif endian is None:
                raise ValueError("PCAPNG missing section header")
            kind, length = struct.unpack(endian + "II", header)
            if length < (28 if section else 12) or length % 4 or length > MAX_BLOCK:
                raise ValueError("Invalid or unbounded PCAPNG block length")
            if start + length > size or (not section and section_end is not None and start + length > section_end):
                raise ValueError("Truncated PCAPNG block or section overrun")
            rest = file.read(length - (12 if section else 8))
            if len(rest) != length - (12 if section else 8):
                raise ValueError("Truncated PCAPNG block")
            if struct.unpack(endian + "I", rest[-4:])[0] != length:
                raise ValueError("PCAPNG block footer mismatch")
            body = (magic if section else b"") + rest[:-4]
            if section:
                major, minor, declared = struct.unpack_from(endian + "HHq", body, 4)
                if (major, minor) != (1, 0) or declared < -1:
                    raise ValueError("Unsupported PCAPNG section version/length")
                section_end = None if declared == -1 else start + length + declared
                if section_end is not None and section_end > size:
                    raise ValueError("Truncated PCAPNG declared section")
                interfaces = []
                options(body[16:], endian)
            elif kind == 1:
                if len(body) < 8:
                    raise ValueError("Truncated PCAPNG interface")
                link, _, snaplen = struct.unpack_from(endian + "HHI", body)
                if link != 1 or snaplen > 16 * 1024 * 1024 or len(interfaces) >= 1024:
                    raise ValueError("Unsupported PCAPNG interface/link type")
                interfaces.append(snaplen or 16 * 1024 * 1024)
                options(body[8:], endian, interface=True)
            elif kind == 6:
                if len(body) < 20:
                    raise ValueError("Truncated PCAPNG packet header")
                interface, _, _, captured, original = struct.unpack_from(endian + "IIIII", body)
                if interface >= len(interfaces) or captured > interfaces[interface] or captured > original:
                    raise ValueError("Invalid PCAPNG packet interface/length")
                padded = (captured + 3) & ~3
                if 20 + padded > len(body):
                    raise ValueError("Truncated PCAPNG packet data")
                options(body[20 + padded:], endian)
                packets += 1
            elif kind in (4, 5):
                # Non-packet metadata: framing checked; Zeek interprets input.
                pass
            else:
                raise ValueError("Unsupported PCAPNG block; no packet skipping")
        if section_end is not None and file.tell() != section_end:
            raise ValueError("PCAPNG section length mismatch")
    return packets
