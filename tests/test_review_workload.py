import copy
import hashlib
import json
import os
import socket
import struct
from collections import Counter
from datetime import datetime, timezone

import dpkt
import pytest

from scripts.lab.evaluate_review_workload import (
    PLAN_SHA,
    role_metrics,
    validate_pcap,
    validate_synthetic,
    verify_hashes,
)
from scripts.lab import prepare_review_workload
from scripts.lab.review_workload import SHARED_RESOLVER, generate, manifest
from threatfusion.connections import ConnectionRecord
from threatfusion.dns import DNSEvent
from threatfusion.runtime_analysis import analyze_dns_events


def observed(plan):
    dns, http, connections = [], [], []
    streamed = set()
    for i, e in enumerate(plan["events"]):
        r = plan["roles"][e["role"]]
        failed = r["schedule"] == "failure"
        ts = datetime.fromtimestamp(e["at"], timezone.utc)
        if e["dns"]:
            dns.append(
                DNSEvent(
                    r["domain"],
                    ts,
                    r["dns_origin"],
                    "A",
                    None if failed else r["server"],
                    "SERVFAIL" if failed else "NOERROR",
                )
            )
        if not failed:
            http.append(
                {
                    "id.orig_h": r["client"],
                    "host": r["domain"],
                    "uri": "/observe",
                    "status_code": "200",
                }
            )
        if r["schedule"] == "stream":
            if e["role"] in streamed:
                continue
            streamed.add(e["role"])
        connections.append(
            ConnectionRecord(
                f"C{i}",
                ts,
                r["client"],
                r["server"],
                32000 + i,
                8000,
                "tcp",
                7080 if r["schedule"] == "stream" else 0.09,
                0 if failed else 100,
                0 if failed else 200,
                "S0" if failed else "SF",
                0,
            )
        )
    return dns, http, connections


def test_deterministic_seeded_inputs_preserve_cache_and_shared_resolver():
    plan = manifest(20261061)
    assert plan == manifest(20261061)
    assert plan != manifest(20261161)
    counts = Counter(e["role"] for e in plan["events"] if e["dns"])
    requests = Counter(e["role"] for e in plan["events"])
    assert counts["regular-updater"] < requests["regular-updater"]
    assert counts["cached-polling"] == requests["cached-polling"]
    assert {
        r["dns_origin"]
        for n, r in plan["roles"].items()
        if n.startswith("shared-resolver")
    } == {SHARED_RESOLVER}

    def regular(name):
        return [e["at"] for e in plan["events"] if e["role"] == name]

    assert regular("regular-updater") == regular("regular-heartbeat")


def test_packets_verify_checksums_dns_cache_stream_identity_and_no_intent_payload(
    tmp_path,
):
    plan = manifest(20261061)
    path = tmp_path / "input.pcap"
    generate(path, plan)
    queries, requests, starts = Counter(), Counter(), Counter()
    frames = 0
    with path.open("rb") as file:
        for _, frame in dpkt.pcap.Reader(file):
            frames += 1
            ip = dpkt.ethernet.Ethernet(frame).data
            transport = bytes(ip.data)
            assert dpkt.in_cksum(ip.pack_hdr()) == 0
            assert (
                dpkt.in_cksum(
                    struct.pack("!4s4sBBH", ip.src, ip.dst, 0, ip.p, len(transport))
                    + transport
                )
                == 0
            )
            source = socket.inet_ntoa(ip.src)
            if ip.p == 17 and ip.data.dport == 53:
                queries[source] += 1
            if ip.p == 6 and ip.data.dport == 8000:
                if ip.data.flags == dpkt.tcp.TH_SYN:
                    starts[source] += 1
                if ip.data.data:
                    assert all(n.encode() not in ip.data.data for n in plan["roles"])
                    requests[source] += 1
    assert validate_pcap(path) == frames
    for name, role in plan["roles"].items():
        events = [e for e in plan["events"] if e["role"] == name]
        assert requests[role["client"]] == (
            0 if role["schedule"] == "failure" else len(events)
        )
        assert starts[role["client"]] == (
            1 if role["schedule"] == "stream" else len(events)
        )
    assert sum(queries.values()) == sum(e["dns"] for e in plan["events"])
    other = tmp_path / "again.pcap"
    generate(other, plan)
    assert path.read_bytes() == other.read_bytes()
    with pytest.raises(FileExistsError):
        generate(path, plan)


@pytest.mark.parametrize("cut", [1, 10, 24, 25, 100])
def test_structural_gate_rejects_truncation_instead_of_accepting_prefix(tmp_path, cut):
    path = tmp_path / "input.pcap"
    generate(path, manifest(20261061))
    path.write_bytes(path.read_bytes()[:-cut])
    with pytest.raises(ValueError, match="Truncated"):
        validate_pcap(path)


def test_reconciliation_rejects_missing_events_answers_and_short_stream():
    plan = manifest(20261061)
    dns, http, conn = observed(plan)
    validate_synthetic(plan, dns, http, conn)
    with pytest.raises(ValueError, match="DNS counts"):
        validate_synthetic(plan, dns[:-1], http, conn)
    bad = copy.deepcopy(dns)
    bad[0].response_ip = "192.0.2.9"
    with pytest.raises(ValueError, match="DNS answers"):
        validate_synthetic(plan, bad, http, conn)
    with pytest.raises(ValueError, match="HTTP"):
        validate_synthetic(plan, dns, http[:-1], conn)
    from dataclasses import replace

    bad_conn = [
        replace(r, duration_seconds=1) if r.duration_seconds == 7080 else r
        for r in conn
    ]
    with pytest.raises(ValueError, match="Long stream"):
        validate_synthetic(plan, dns, http, bad_conn)


def test_metrics_keep_shared_resolver_separate_and_show_observable_intent_overlap():
    plan = manifest(20261061)
    dns, _, conn = observed(plan)
    fallback = [
        DNSEvent(
            r.responder_ip, r.timestamp, r.originator_ip, response_ip=r.responder_ip
        )
        for r in conn
    ]
    connection = analyze_dns_events(fallback, (), None, connections=conn)
    dns_result = analyze_dns_events(dns, (), None)
    result = role_metrics(plan, connection, dns_result, [])
    roles = {r["role"]: r for r in result["roles"]}
    assert (
        roles["regular-updater"]["tcp_review_groups"]
        == roles["regular-heartbeat"]["tcp_review_groups"]
        == 1
    )
    assert (
        roles["regular-updater"]["dns_endpoint_review_groups"]
        == roles["regular-heartbeat"]["dns_endpoint_review_groups"]
        == 0
    )
    assert all(
        roles[n]["dns_endpoint_groups"] == 0
        for n in roles
        if n.startswith("shared-resolver")
    )
    assert result["shared_resolver"]["groups"] == 1
    assert result["shared_resolver"]["underlying_endpoint_attribution"] is False
    assert "fpr" not in result and "recall" not in result


def test_input_verification_rejects_tampering_and_parent_escape(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text("frozen")
    expected = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()}
    verify_hashes(tmp_path, expected)
    path.write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        verify_hashes(tmp_path, expected)
    with pytest.raises(ValueError, match="escapes"):
        verify_hashes(tmp_path, {"../outside": "invalid"})


def test_published_method_reproduces_the_original_preanalysis_plan():
    text = json.dumps(prepare_review_workload.declared_plan(), indent=2) + "\n"
    assert hashlib.sha256(text.encode()).hexdigest() == PLAN_SHA


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix lab directory")
def test_prepare_is_offline_private_and_refuses_existing_evidence(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        prepare_review_workload,
        "urlopen",
        lambda *a, **kw: pytest.fail("Unexpected network access"),
    )
    root = prepare_review_workload.prepare(tmp_path / "experiment")
    assert root.stat().st_mode & 0o077 == 0
    assert (root / "plan.json").stat().st_mode & 0o077 == 0
    assert all(
        (root / phase / "scenario.pcap").exists()
        for phase in ("development", "reserved")
    )
    with pytest.raises(FileExistsError):
        prepare_review_workload.prepare(root)


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix lab directory")
def test_acquisition_rejects_redirect_before_reading_traffic(tmp_path, monkeypatch):
    root = prepare_review_workload.prepare(tmp_path / "experiment")

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def geturl(self):
            return "https://outside.example/traffic.pcap"

        def read(self, *args):
            pytest.fail("Redirected response body must not be read")

    monkeypatch.setattr(prepare_review_workload, "urlopen", lambda *a, **kw: Response())
    with pytest.raises(ValueError, match="allowed origin"):
        prepare_review_workload.acquire(root)
    assert not list(root.rglob("acquisition.json"))
    assert not (root / "somfy-02/scenario.pcap").exists()
