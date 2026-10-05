"""Complete block/packet qualification; no dependence on detector outcomes."""
import struct

import pytest

from scripts.lab.pcap_structure import MAX_BLOCK, validate_capture


def block(kind, body, endian="<"):
    length = 12 + len(body)
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def section(endian="<", declared=-1):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, declared), endian)


def interface(endian="<", snaplen=65535, extra=b""):
    return block(1, struct.pack(endian + "HHI", 1, 0, snaplen) + extra, endian)


def packet(endian="<", index=0, captured=2, original=2, data=b"xx\0\0"):
    return block(6, struct.pack(endian + "IIIII", index, 0, 1, captured, original) + data, endian)


def validate(tmp_path, raw):
    path = tmp_path / "input.pcap"
    path.write_bytes(raw)
    return validate_capture(path, max_bytes=512 * 1024 * 1024)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_complete_pcapng_endian_sections_options_and_packet_padding(tmp_path, endian):
    opts = struct.pack(endian + "HH", 9, 1) + b"\x06\0\0\0" + b"\0" * 4
    tail = interface(endian, extra=opts) + packet(endian)
    assert validate(tmp_path, section(endian, len(tail)) + tail) == 1
    assert validate(tmp_path, section(endian) + tail + section() + interface() + packet()) == 2


@pytest.mark.parametrize("mutate,match", [
    (lambda raw: raw[:-1], "Truncated"),
    (lambda raw: raw + b"xx", "Truncated"),
    (lambda raw: raw[:-4] + b"\0" * 4, "footer"),
    (lambda raw: section() + packet(), "interface"),
    (lambda raw: section() + interface() + packet(index=1), "interface"),
    (lambda raw: section() + interface() + packet(captured=3), "length"),
    (lambda raw: section() + interface(snaplen=1) + packet(), "length"),
    (lambda raw: section() + interface() + packet(captured=6, original=6), "packet data"),
    (lambda raw: section(declared=1) + interface() + packet(), "overrun"),
    (lambda raw: section(declared=10000) + interface() + packet(), "Truncated"),
    (lambda raw: section(declared=-2), "version/length"),
    (lambda raw: section() + interface() + block(3, b"\0" * 4), "Unsupported"),
    (lambda raw: section() + interface() + block(0xFFFFFFFF, b""), "Unsupported"),
    (lambda raw: section() + struct.pack("<II", 6, MAX_BLOCK + 4), "unbounded"),
    (lambda raw: section() + interface(extra=struct.pack("<HH", 9, 2) + b"\0" * 8), "timestamp"),
    (lambda raw: section() + interface(extra=struct.pack("<HH", 1, 8)), "option value"),
    (lambda raw: section() + interface(extra=struct.pack("<HH", 1, 0)), "terminator"),
])
def test_pcapng_rejects_whole_capture_on_structure_or_unsupported_packet_block(tmp_path, mutate, match):
    raw = section() + interface() + packet()
    with pytest.raises(ValueError, match=match):
        validate(tmp_path, mutate(raw))


def test_pcapng_declared_size_bound_applies_before_block_read(tmp_path):
    path = tmp_path / "input.pcapng"
    path.write_bytes(section() + interface() + packet())
    with pytest.raises(ValueError, match="bound"):
        validate_capture(path, max_bytes=24)
