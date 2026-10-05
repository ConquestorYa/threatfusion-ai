import hashlib
import socket
import struct
from collections import Counter

import dpkt
import pytest

from scripts.lab.analyze_periodic import read_rita
from scripts.lab.periodic_scenario import (
    DOMAINS,
    ROLES,
    answer_bytes,
    generate_replay,
    make_manifest,
    query_bytes,
    write_manifest,
)
from scripts.lab.prepare_rita_lab import prepare


def test_benign_and_suspicious_periodic_controls_have_identical_timing():
    manifest = make_manifest("replay")
    assert manifest == make_manifest("replay")
    times = {role: [e["at"] for e in manifest["events"] if e["role"] == role] for role in ROLES}
    assert times["updater"] == times["heartbeat"]
    assert len(times["updater"]) == 288
    assert manifest["roles"]["updater"][3] == "benign"
    assert manifest["roles"]["heartbeat"][3] == "controlled_suspicious_simulation"
    assert len(set(b - a for a, b in zip(times["browser"], times["browser"][1:]))) > 10


def test_replay_packets_have_valid_checksums_and_expected_wire_events(tmp_path):
    manifest = make_manifest("replay")
    path = tmp_path / "scenario.pcap"
    generate_replay(path, manifest)
    dns_counts = Counter()
    requests = 0
    timestamps = []
    with path.open("rb") as file:
        for timestamp, frame in dpkt.pcap.Reader(file):
            timestamps.append(timestamp)
            ip = dpkt.ethernet.Ethernet(frame).data
            assert dpkt.in_cksum(ip.pack_hdr()) == 0
            transport = bytes(ip.data)
            pseudo = struct.pack("!4s4sBBH", ip.src, ip.dst, 0, ip.p, len(transport))
            assert dpkt.in_cksum(pseudo + transport) == 0
            if isinstance(ip.data, dpkt.udp.UDP) and ip.data.dport == 53:
                dns = dpkt.dns.DNS(ip.data.data)
                assert dns.qd[0].name in DOMAINS
                dns_counts[(socket.inet_ntoa(ip.src), dns.qd[0].name)] += 1
            elif isinstance(ip.data, dpkt.tcp.TCP) and ip.data.dport == 8000 and ip.data.data:
                request = dpkt.http.Request(ip.data.data)
                assert request.headers["host"] in DOMAINS
                assert request.method == "GET"
                requests += 1
    expected = Counter((ROLES[event["role"]][0], event["domain"]) for event in manifest["events"])
    assert dns_counts == expected
    assert requests == 816
    assert timestamps == sorted(timestamps)
    assert timestamps[-1] - timestamps[0] > 23 * 3600
    second = tmp_path / "second.pcap"
    generate_replay(second, manifest)
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()


def test_frozen_manifest_is_not_overwritten(tmp_path):
    path = tmp_path / "manifest.json"
    write_manifest(path, "replay")
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        write_manifest(path, "replay")
    assert path.read_bytes() == original


def test_lab_dns_answers_only_known_synthetic_domains():
    for domain, expected in DOMAINS.items():
        response = dpkt.dns.DNS(answer_bytes(query_bytes(domain, 1)))
        assert response.rcode == dpkt.dns.DNS_RCODE_NOERR
        assert socket.inet_ntoa(response.an[0].ip) == expected
    response = dpkt.dns.DNS(answer_bytes(query_bytes("outside.example", 2)))
    assert response.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN
    assert not response.an


def test_native_rita_csv_banner_is_not_treated_as_a_data_row(tmp_path):
    path = tmp_path / "rita.csv"
    path.write_text('Viewing database: fixture\nSeverity,Source IP,FQDN,Beacon Score,Modifiers\nCritical,198.18.1.13,heartbeat.lab.test,1,"rare_signature:lab"\n')
    rows = read_rita(path)
    assert len(rows) == 1
    assert rows[0]["Beacon Score"] == "1"
    path.write_text("not a RITA CSV\n")
    with pytest.raises(ValueError, match="schema"):
        read_rita(path)


def test_rita_preparation_rejects_bad_archive_before_extracting(tmp_path):
    archive = tmp_path / "untrusted.tar.gz"
    archive.write_bytes(b"not the pinned upstream release")
    output = tmp_path / "runtime"
    with pytest.raises(ValueError, match="SHA-256"):
        prepare(output, archive)
    assert not output.exists()
    output.mkdir()
    sentinel = output / "private.txt"
    sentinel.write_text("preserve existing directory")
    with pytest.raises(FileExistsError):
        prepare(output, archive)
    assert sentinel.read_text() == "preserve existing directory"
