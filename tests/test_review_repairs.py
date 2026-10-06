"""Owned synthetic regressions for the pre-manual-test source review."""

from __future__ import annotations

import io
import json
import os
import socket
import sqlite3
from dataclasses import replace

import dpkt
import pytest

from scripts.lab.evaluate_dns_collector import NOW, cases, log
from threatfusion import cti_cache, cti_refresh, matching
from threatfusion.app_config import load_app_config
from threatfusion.collector_identity import IDENTITY_FILE, local_identity_view
from threatfusion.dashboard import domain_match_rows
from threatfusion.dns import DNSEvent, parse_dns_csv, response_ip_addresses
from threatfusion.dns_adguard import parse_adguard_query_log
from threatfusion.dns_collection import (
    build_dns_snapshot,
    transaction_payload,
    validate_dns_snapshot,
)
from threatfusion.dns_zeek import parse_zeek_dns_log, parse_zeek_dns_transactions
from threatfusion.models import IOCRecord, IOCType
from threatfusion.network_telemetry import (
    parse_pcap_dns_with_diagnostics,
    parse_suricata_eve_with_diagnostics,
)
from threatfusion.quick_lookup import analyze_quick_lookup_from_cache
from threatfusion.reporting import build_analysis_report, build_device_report
from threatfusion.runtime_analysis import analyze_dns_events
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot

BAD_IP = "203.0.113.9"
GOOD_IP = "198.51.100.1"
CLIENT = "192.0.2.10"
RESOLVER = "192.0.2.53"
IOC = IOCRecord(BAD_IP, IOCType.IPV4, "Synthetic")


def packet(*, reply=False, client=CLIENT, query_id=7, rcode=0, answers=()):
    dns = dpkt.dns.DNS(
        id=query_id,
        qr=int(reply),
        rcode=rcode,
        qd=[dpkt.dns.DNS.Q(name="multi.test", type=dpkt.dns.DNS_A)],
        an=[
            dpkt.dns.DNS.RR(
                name="multi.test", type=dpkt.dns.DNS_A, rdata=socket.inet_aton(ip)
            )
            for ip in answers
        ],
    )
    udp = dpkt.udp.UDP(
        sport=53 if reply else 40001, dport=40001 if reply else 53, data=bytes(dns)
    )
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(RESOLVER if reply else client),
        dst=socket.inet_aton(client if reply else RESOLVER),
        p=17,
        data=udp,
    )
    ip.len = len(ip)
    return bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x01" * 6, dst=b"\x02" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip
        )
    )


def capture(rows, *, pcapng=False):
    output = io.BytesIO()
    writer = (dpkt.pcapng.Writer if pcapng else dpkt.pcap.Writer)(output)
    for timestamp, data in rows:
        writer.writepkt(data, ts=timestamp)
    return output.getvalue()


@pytest.mark.parametrize("pcapng", [False, True])
@pytest.mark.parametrize("rcode,answers", [(0, (GOOD_IP, BAD_IP)), (3, ())])
def test_pcap_pairs_without_resolver_attribution_or_duplicate_queries(
    pcapng, rcode, answers
):
    parsed = parse_pcap_dns_with_diagnostics(
        capture(
            [(100, packet()), (101, packet(reply=True, rcode=rcode, answers=answers))],
            pcapng=pcapng,
        )
    )
    assert len(parsed.events) == 1
    event = parsed.events[0]
    assert event.client_ip == CLIENT and event.timestamp.timestamp() == 100
    assert event.response_code == str(rcode)
    assert set(response_ip_addresses(event)) == set(answers)
    assert (
        parsed.diagnostics.packet_dns_queries
        == parsed.diagnostics.packet_paired_queries
        == 1
    )
    assert parsed.diagnostics.packet_response_only == 0
    result = analyze_dns_events(parsed.events, [IOC], None)
    if answers:
        assert len(result.matches) == 1
        assert result.matches[0].matched_ip == BAD_IP
        assert result.device_findings[0].client_ip == CLIENT
        assert result.assessments[0].behavior.event_count == 1


def test_pcap_unanswered_and_orphan_are_explicit_and_never_cross_clients():
    parsed = parse_pcap_dns_with_diagnostics(
        capture(
            [
                (100, packet()),
                (101, packet(reply=True, client="192.0.2.11", answers=(BAD_IP,))),
            ]
        )
    )
    assert len(parsed.events) == 2
    assert parsed.events[0].response_code is None
    assert parsed.events[1].client_ip == "192.0.2.11"
    assert parsed.diagnostics.packet_response_only == 1


def test_pcap_late_id_reuse_does_not_join_old_transaction():
    parsed = parse_pcap_dns_with_diagnostics(
        capture(
            [
                (100, packet()),
                (221, packet(reply=True)),
                (222, packet()),
                (223, packet(reply=True, answers=(BAD_IP,))),
            ]
        )
    )
    assert len(parsed.events) == 3
    assert parsed.events[0].response_code is None
    assert parsed.events[2].response_ip == BAD_IP
    assert (
        parsed.diagnostics.packet_paired_queries
        == parsed.diagnostics.packet_response_only
        == 1
    )


@pytest.mark.parametrize("format_name", ["zeek", "adguard", "suricata", "csv"])
@pytest.mark.parametrize("answers", [(GOOD_IP, BAD_IP), (BAD_IP, GOOD_IP)])
def test_all_dns_answers_match_independently_of_order_without_extra_queries(
    format_name, answers
):
    if format_name == "zeek":
        events = parse_zeek_dns_log(
            "#fields\tts\tid.orig_h\tquery\tqtype_name\tanswers\n100\t"
            + CLIENT
            + "\tmulti.test\tA\t"
            + ",".join(answers)
            + "\n"
        )
    elif format_name == "adguard":
        events = parse_adguard_query_log(
            json.dumps(
                [
                    {
                        "question": {"host": "multi.test", "type": "A"},
                        "client": CLIENT,
                        "answer": [{"value": ip} for ip in answers],
                    }
                ]
            )
        )
    elif format_name == "suricata":
        events = parse_suricata_eve_with_diagnostics(
            json.dumps(
                {
                    "event_type": "dns",
                    "dest_ip": CLIENT,
                    "src_ip": RESOLVER,
                    "src_port": 53,
                    "dest_port": 40001,
                    "dns": {
                        "type": "answer",
                        "rrname": "multi.test",
                        "rrtype": "A",
                        "answers": [{"rdata": ip} for ip in answers],
                    },
                }
            )
        ).events
    else:
        events = parse_dns_csv(
            "query_name,client_ip,response_ip\nmulti.test,"
            + CLIENT
            + ',"'
            + ",".join(answers)
            + '"\n'
        )
    assert len(events) == 1
    assert set(response_ip_addresses(events[0])) == set(answers)
    result = analyze_dns_events(events, [IOC], None)
    assert len(result.matches) == 1
    assert result.assessments[0].behavior.event_count == 1
    assert result.assessments[0].behavior.unique_response_ip_count == 2


@pytest.mark.parametrize("value", ["1", "true", "null", '"text"'])
def test_adguard_scalar_is_actionable_validation_error(value):
    with pytest.raises(ValueError):
        parse_adguard_query_log(value)


@pytest.mark.parametrize("value", ["1", "[1]", "[[0]]", "[" * 2000 + "0" + "]" * 2000])
def test_suricata_non_event_json_is_actionable_validation_error(value):
    with pytest.raises(ValueError):
        parse_suricata_eve_with_diagnostics(value)


def test_literal_ip_targets_are_aliased_in_both_exports_and_counts_are_truthful():
    result = analyze_dns_events(
        [DNSEvent(BAD_IP, client_ip=CLIENT, response_ip=BAD_IP)], [IOC], None
    )
    report = build_analysis_report(result, model_name="cti-only")
    payload = json.loads(report.json_text)
    assert BAD_IP not in report.json_text + report.csv_text
    assert payload["summary"]["unique_domains"] == 0
    assert payload["summary"]["unique_targets"] == payload["summary"]["ip_targets"] == 1
    assert payload["findings"][0]["target_type"] == "ipv4"
    assert BAD_IP not in build_device_report(result)
    opted = json.loads(
        build_analysis_report(
            result, model_name="cti-only", include_target_ips=True
        ).json_text
    )
    assert (
        opted["findings"][0]["domain"] == BAD_IP
        and opted["privacy"]["response_ip_values_included"]
    )
    opted_device = json.loads(build_device_report(result, include_client_ips=True))
    assert (
        opted_device["findings"][0]["Target"] == BAD_IP
        and opted_device["privacy"]["response_ip_values_included"]
    )


def test_ipv6_cached_network_is_context_not_exact_threat(tmp_path):
    cache = tmp_path / "cti.sqlite"
    cti_cache.replace_source_records(
        cache,
        "Synthetic",
        [IOCRecord("2001:db8:abcd::/48", IOCType.IPV6_NETWORK, "Synthetic")],
    )
    result = analyze_quick_lookup_from_cache("2001:db8:abcd::123", cache, None)
    assert result.verdict.value == "review"
    assert [e.match_type for e in result.evidence] == ["response_ip_network"]
    assert (
        analyze_quick_lookup_from_cache("2001:db8:ffff::1", cache, None).verdict.value
        == "low"
    )


def test_idna_matching_and_details_use_same_normalization():
    result = analyze_dns_events(
        [DNSEvent("BÜCHER.test.")],
        [IOCRecord("xn--bcher-kva.test", IOCType.DOMAIN, "Synthetic")],
        None,
    )
    assert len(domain_match_rows(result, result.assessments[0].domain)) == 1


def test_match_fanout_and_work_limits_fail_instead_of_returning_truncated_evidence(
    monkeypatch,
):
    monkeypatch.setattr(matching, "MAX_IOC_MATCHES", 3)
    indicators = [
        IOCRecord(f"https://multi.test/{i}", IOCType.URL, "Synthetic") for i in range(4)
    ]
    with pytest.raises(ValueError, match="match.*limit"):
        matching.match_dns_events([DNSEvent("multi.test")], indicators)
    monkeypatch.setattr(matching, "MAX_MATCH_LOOKUPS", 2)
    with pytest.raises(ValueError, match="work budget"):
        matching.match_dns_events([DNSEvent("normal.test") for _ in range(3)], [IOC])


def test_old_dns_representation_is_disclosed_and_same_source_reimport_is_reconciled():
    row = list(cases(1)[0]["rows"][0])
    row[-1] = GOOD_IP + "," + BAD_IP
    transaction = parse_zeek_dns_transactions(log([row]))[0]
    new = transaction_payload(transaction)
    old = json.loads(new)
    old.pop("answer_coverage")
    old["event"].pop("response_ips")
    legacy = build_dns_snapshot([json.dumps(old)], [IOC], generated_at=NOW)
    assert legacy["coverage"]["legacy_first_answer_events"] == 1
    for payloads in ([json.dumps(old), new], [new, json.dumps(old)]):
        snapshot = build_dns_snapshot(payloads, [IOC], generated_at=NOW)
        validate_dns_snapshot(snapshot)
        assert snapshot["coverage"]["analyzed_events"] == 1
        assert snapshot["coverage"]["superseded_representations"] == 1
        assert snapshot["coverage"]["legacy_first_answer_events"] == 0
        assert snapshot["report"]["findings"][0]["Queue priority"] == "Review"
        assert snapshot["report"]["findings"][0]["Known CTI sources"] == "Synthetic"


@pytest.mark.skipif(os.name != "posix", reason="Private Linux collector")
def test_collector_private_identity_is_generation_bound_and_exports_stay_aliased(
    tmp_path,
):
    source = tmp_path / "input"
    source.mkdir()
    state = tmp_path / "private"
    row = list(cases(1)[0]["rows"][0])
    (source / "dns.log").write_text(log([row]))
    with ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        snapshot = read_snapshot(state)
        view = local_identity_view(state, snapshot)
        assert view["dns"]["report"]["findings"][0]["Device"] == row[2]
        assert row[2] not in json.dumps(snapshot)
        assert (state / IDENTITY_FILE).stat().st_mode & 0o777 == 0o600
        mapping = json.loads((state / IDENTITY_FILE).read_text())
        mapping["selection_revision"] = "stale"
        (state / IDENTITY_FILE).write_text(json.dumps(mapping))
        with pytest.raises(ValueError, match="generation"):
            local_identity_view(state, snapshot)
    (state / IDENTITY_FILE).chmod(0o644)
    with pytest.raises(ValueError, match="identity"):
        local_identity_view(state, snapshot)


@pytest.mark.skipif(os.name != "posix", reason="Private Linux collector")
def test_schema2_migration_keeps_private_backup_and_legacy_dns(tmp_path):
    source = tmp_path / "input"
    source.mkdir()
    state = tmp_path / "private"
    with ZeekCollector(source, state):
        pass
    with sqlite3.connect(state / "collector.sqlite") as db:
        db.execute("PRAGMA user_version=2")
    with ZeekCollector(source, state) as collector:
        assert collector.db.execute("PRAGMA user_version").fetchone()[0] == 3
    (backup,) = state.glob("collector.schema2-*.sqlite")
    assert backup.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(backup) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2


def test_prune_batches_under_sqlite_variable_limit_and_preserves_active(
    tmp_path, monkeypatch
):
    path = tmp_path / "cti.sqlite"
    cti_cache.initialize_cti_cache(path)
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO cti_records(value,ioc_type,source,tags_json,active,last_seen_in_refresh) VALUES (?, 'domain', 'Synthetic', '[]', 0, '2020-01-01T00:00:00+00:00')",
            ((f"{i}.test",) for i in range(2100)),
        )
        db.execute(
            "INSERT INTO cti_records(value,ioc_type,source,tags_json,active) VALUES ('active.test', 'domain', 'Synthetic', '[]', 1)"
        )
    connect = cti_cache._connect

    def limited(path):
        connection = connect(path)
        connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 32)
        return connection

    monkeypatch.setattr(cti_cache, "_connect", limited)
    assert cti_cache.prune_inactive_records(path, now=NOW) == 2100
    assert [r.value for r in cti_cache.load_ioc_records(path)] == ["active.test"]


def test_cache_reader_reuses_idle_data_and_notices_refresh(tmp_path):
    path = tmp_path / "cti.sqlite"
    cti_cache.replace_source_records(path, "Synthetic", [IOC])
    reader = cti_cache.CTICacheReader(path)
    first = reader.read()
    assert reader.read() is first
    cti_cache.replace_source_records(path, "Synthetic", [replace(IOC, value=GOOD_IP)])
    assert [r.value for r in reader.read()] == [GOOD_IP]


def test_prune_later_batch_failure_rolls_back_the_whole_cleanup(tmp_path, monkeypatch):
    path = tmp_path / "cti.sqlite"
    cti_cache.initialize_cti_cache(path)
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO cti_records(value,ioc_type,source,tags_json,active,last_seen_in_refresh) VALUES (?, 'domain', 'Synthetic', '[]', 0, '2020-01-01T00:00:00+00:00')",
            ((f"{i}.test",) for i in range(70)),
        )

    class FailingConnection(sqlite3.Connection):
        deletes = 0

        def execute(self, sql, parameters=()):
            if sql.startswith("DELETE FROM cti_records WHERE id IN"):
                self.deletes += 1
                if self.deletes == 2:
                    raise sqlite3.OperationalError("synthetic later-batch failure")
            return super().execute(sql, parameters)

    def connect(path):
        db = sqlite3.connect(path, factory=FailingConnection)
        db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 32)
        return db

    monkeypatch.setattr(cti_cache, "_connect", connect)
    with pytest.raises(sqlite3.OperationalError):
        cti_cache.prune_inactive_records(path, now=NOW)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM cti_records").fetchone()[0] == 70


def test_maintenance_failure_does_not_mislabel_successful_sources(
    tmp_path, monkeypatch
):
    from tests.test_cti_refresh import _patch_collectors

    _patch_collectors(monkeypatch)

    def fail(*args, **kwargs):
        raise sqlite3.OperationalError("private detail")

    monkeypatch.setattr(cti_refresh, "prune_inactive_records", fail)
    path = tmp_path / "cti.sqlite"
    outcomes = cti_refresh.refresh_configured_sources(
        path, threatfox_key="synthetic", urlhaus_key=None, force=True, now=NOW
    )
    assert next(o for o in outcomes if o.source == "ThreatFox").status == "refreshed"
    assert (
        outcomes[-1].source == "Cache maintenance" and outcomes[-1].status == "failed"
    )
    assert "private detail" not in outcomes[-1].detail
    assert cti_cache.load_ioc_records(path)


@pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
def test_nonfinite_refresh_config_is_rejected(value):
    with pytest.raises(ValueError):
        load_app_config({"THREATFUSION_CTI_STALE_HOURS_THREATFOX": value})


@pytest.mark.parametrize("grouped", [False, True])
def test_suricata_v3_answers_and_client_direction(grouped):
    dns = {
        "version": 3,
        "type": "answer",
        "queries": [{"rrname": "multi.test", "rrtype": "A"}],
        "rcode": "NOERROR",
    }
    if grouped:
        dns["grouped"] = {"A": [GOOD_IP, BAD_IP]}
    else:
        dns["answers"] = [{"rdata": GOOD_IP}, {"rdata": BAD_IP}]
    record = {
        "event_type": "dns",
        "src_ip": RESOLVER,
        "dest_ip": CLIENT,
        "src_port": 53,
        "dest_port": 40001,
        "dns": dns,
    }
    (event,) = parse_suricata_eve_with_diagnostics(json.dumps(record)).events
    assert event.client_ip == CLIENT and event.query_type == "A"
    assert set(response_ip_addresses(event)) == {GOOD_IP, BAD_IP}
    # Missing direction evidence must not label the resolver as the client.
    record.pop("src_port")
    record.pop("dest_port")
    (event,) = parse_suricata_eve_with_diagnostics(json.dumps(record)).events
    assert event.client_ip is None


def test_dns_answer_budget_is_enforced_before_analysis():
    event = DNSEvent("multi.test", response_ip=GOOD_IP, response_ips=(BAD_IP,) * 1024)
    with pytest.raises(ValueError, match="answer limit"):
        analyze_dns_events([event], [IOC], None)


@pytest.mark.skipif(os.name != "posix", reason="Private Linux collector")
def test_failed_analysis_preserves_snapshot_and_retries_committed_records(
    tmp_path, monkeypatch
):
    source = tmp_path / "input"
    source.mkdir()
    state = tmp_path / "private"
    row = list(cases(1)[0]["rows"][0])
    (source / "dns.1.log").write_text(log([row]))
    with ZeekCollector(source, state) as collector:
        from scripts.lab.evaluate_dns_collector import FIELDS

        indicator = IOCRecord(row[FIELDS.index("query")], IOCType.DOMAIN, "Synthetic")
        collector.tick(now=NOW, indicators=[indicator])
        original = (state / "connections.json").read_bytes()
        extra = list(row)
        extra[1] = "Cextra"
        (source / "dns.2.log").write_text(log([extra]))
        monkeypatch.setattr(matching, "MAX_IOC_MATCHES", 1)
        with pytest.raises(ValueError, match="match limit"):
            collector.tick(now=NOW, indicators=[indicator])
        assert (state / "connections.json").read_bytes() == original
        assert collector.db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 2
        monkeypatch.setattr(matching, "MAX_IOC_MATCHES", 250_000)
        status = collector.tick(now=NOW, indicators=[indicator])
        assert status["counts"]["new_records"] == 0
        assert status["counts"]["analyzed_dns_events"] == 2
        assert status["scan"]["analysis_recomputed"]


@pytest.mark.skipif(os.name != "posix", reason="Private Linux collector")
def test_collector_ui_local_identity_toggle_and_stale_mapping_are_safe(tmp_path):
    from streamlit.testing.v1 import AppTest

    source = tmp_path / "input"
    source.mkdir()
    state = tmp_path / "private"
    (source / "dns.log").write_text(log(cases(1)[0]["rows"][:1]))
    with ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\nrender_collector(Path("
        + repr(str(state))
        + "), public_mode=False)"
    )
    app.run(timeout=15)
    assert not app.exception
    app.checkbox(key="collector_local_ips").set_value(True).run(timeout=15)
    assert not app.exception
    (state / IDENTITY_FILE).unlink()
    app.run(timeout=15)
    assert not app.exception
    assert any("mapping" in warning.value for warning in app.warning)


def test_new_history_does_not_save_literal_endpoint_values(tmp_path):
    from threatfusion.persistence import save_runtime_analysis

    result = analyze_dns_events(
        [DNSEvent(BAD_IP, client_ip=CLIENT, response_ip=BAD_IP)], [IOC], None
    )
    path = tmp_path / "history.sqlite"
    save_runtime_analysis(path, result, model_name="cti-only")
    with sqlite3.connect(path) as db:
        domains = db.execute("SELECT domain FROM analysis_assessments").fetchall()
    assert domains == [("IP target 001 (run 1)",)]
    second = analyze_dns_events([DNSEvent(GOOD_IP, response_ip=GOOD_IP)], [], None)
    save_runtime_analysis(path, second, model_name="cti-only")
    with sqlite3.connect(path) as db:
        domains = db.execute(
            "SELECT domain FROM analysis_assessments ORDER BY id"
        ).fetchall()
    assert domains == [("IP target 001 (run 1)",), ("IP target 001 (run 2)",)]


def test_private_identity_path_cannot_pass_release_audit():
    from threatfusion.release_audit import scan_release_path

    assert scan_release_path("exports/collector-identities.json")


def test_pcap_pair_work_budget_and_unsupported_linktype_are_actionable(monkeypatch):
    from threatfusion import network_telemetry as telemetry

    monkeypatch.setattr(telemetry, "_MAX_PCAP_PAIR_CHECKS", 1)
    with pytest.raises(ValueError, match="pairing.*limit"):
        parse_pcap_dns_with_diagnostics(
            capture([(200, packet()), (300, packet()), (100, packet(reply=True))])
        )
    output = io.BytesIO()
    writer = dpkt.pcap.Writer(output, linktype=dpkt.pcap.DLT_RAW)
    writer.writepkt(b"raw", ts=100)
    with pytest.raises(ValueError, match="Ethernet"):
        parse_pcap_dns_with_diagnostics(output.getvalue())


def test_cli_target_ip_opt_in_requires_explicit_export_and_private_permissions(
    tmp_path,
):
    from threatfusion.cli import main

    input_file = tmp_path / "input.csv"
    input_file.write_text("query_name,response_ip\n" + BAD_IP + "," + BAD_IP + "\n")
    with pytest.raises(SystemExit):
        main([str(input_file), "--cti-only", "--include-target-ips"])
    path = tmp_path / "report.json"
    main(
        [
            str(input_file),
            "--cti-only",
            "--db",
            str(tmp_path / "cti.sqlite"),
            "--json-output",
            str(path),
            "--include-target-ips",
        ]
    )
    assert json.loads(path.read_text())["findings"][0]["domain"] == BAD_IP
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
