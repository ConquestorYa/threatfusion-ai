from __future__ import annotations

from datetime import timedelta

import pytest

from scripts.lab.evaluate_dns_collector import NOW, log
from threatfusion import telemetry_collector as module
from threatfusion.dns import DNSEvent
from threatfusion.dns_names import is_local_name, names_by_address, names_sharing_addresses
from threatfusion.hybrid_assessment import HybridVerdict, assess_dns_domains
from threatfusion.ui_collector import read_snapshot


@pytest.mark.parametrize("name", [
    "_googlecast._tcp.local", "host._dosvc._tcp.local.", "4.0.3.9.ip6.arpa",
    "1.2.0.192.in-addr.arpa", "router.home.arpa", "printer", "nas.lan",
])
def test_local_names(name):
    assert is_local_name(name)


@pytest.mark.parametrize("name", ["cdn.example.test", "local.example.test", "arpa.example.test", ""])
def test_public_names(name):
    assert not is_local_name(name)


def test_address_and_shared_names():
    events = [
        DNSEvent("origin.test", response_ip="198.51.100.9", response_ips=("198.51.100.10",)),
        DNSEvent("origin.test", response_ip="198.51.100.9"),
        DNSEvent("edge.cdn.test", response_ip="198.51.100.10"),
        DNSEvent("other.test", response_ip="203.0.113.5"),
    ]
    assert names_by_address(events)["198.51.100.9"] == ("origin.test",)
    assert names_by_address(events)["198.51.100.10"] == ("edge.cdn.test", "origin.test")
    shared = names_sharing_addresses(events)
    assert shared["edge.cdn.test"] == ("origin.test",)
    assert shared["other.test"] == ()


def test_shared_names_skip_addresses_answered_for_very_many_names():
    events = [DNSEvent(f"n{i}.test", response_ip="198.51.100.1") for i in range(60)]
    assert names_sharing_addresses(events)["n1.test"] == ()


def test_local_name_volume_does_not_reach_review():
    start = NOW - timedelta(hours=2)
    events = [
        DNSEvent(name, timestamp=start + timedelta(seconds=90 * i), client_ip="192.0.2.11",
                 query_type="PTR", response_ip=f"192.0.2.{i % 5 + 20}")
        for name in ("_googlecast._tcp.local", "updates.example.test") for i in range(60)
    ]
    verdicts = {a.domain: a for a in assess_dns_domains(events, [])}
    assert verdicts["_googlecast._tcp.local"].verdict is HybridVerdict.LOW
    assert "local_network_name" in verdicts["_googlecast._tcp.local"].reasons
    assert verdicts["updates.example.test"].verdict is HybridVerdict.REVIEW


def test_collected_rows_show_dns_names_for_connections_and_shared_addresses(tmp_path):
    source, state = tmp_path / "input", tmp_path / "private"
    source.mkdir()
    ts = int(NOW.timestamp()) - 5000
    dns_rows = [
        [ts, "Cd1", "192.0.2.11", 40000, "192.0.2.53", 53, "udp", 1, "origin.test", "A", "NOERROR",
         "edge.cdn.test,198.51.100.9"],
        [ts + 1, "Cd2", "192.0.2.11", 40001, "192.0.2.53", 53, "udp", 2, "edge.cdn.test", "A", "NOERROR",
         "198.51.100.9"],
    ]
    (source / "dns.log").write_text(log(dns_rows))
    fields = "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state missed_bytes".split()
    values = [ts + 2, "Cc1", "192.0.2.11", 40002, "198.51.100.9", 443, "tcp", 4000, 100, 200, "SF", 0]
    (source / "conn.log").write_text(
        "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(fields) + "\n"
        + "\t".join(map(str, values)) + "\n#close\t2026-10-05-03-00-00\n")
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    snapshot = read_snapshot(state)
    (row,) = snapshot["findings"]
    assert row["Queue priority"] == "Review"
    assert row["DNS names"] == "edge.cdn.test, origin.test"
    dns = {r["Target"]: r for r in snapshot["dns"]["report"]["findings"]}
    assert dns["edge.cdn.test"]["Same addresses as"] == "origin.test"
