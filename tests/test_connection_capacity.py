"""Declared diversity, full-report preservation and bounded UI contracts."""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
from dataclasses import replace
from datetime import timedelta

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from tests.test_connections import log, row
from tests.test_telemetry_collector import NOW
from threatfusion import collector_reports as reports
from threatfusion import telemetry_collector as collector_module
from threatfusion import runtime_analysis as runtime
from threatfusion.expected_connections import parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.reporting import build_connection_report
from threatfusion.ui_collector import read_snapshot

unix = pytest.mark.skipif(os.name != "posix", reason="Private Linux collector/archive contract")


def connections(count=5, *, long=False):
    return parse_zeek_conn_log_with_diagnostics(log(*(row(uid=f"C{i}", ts=NOW.timestamp()-7200,
        **{"id.resp_h": f"198.51.100.{i+1}", "duration": 4000 if long else 1}) for i in range(count)))).connections


def make_input(tmp_path, count=5, *, long=False):
    source, state = tmp_path / "source", tmp_path / "state"
    source.mkdir(mode=0o700)
    text = log(*(row(uid=f"C{i}", ts=NOW.timestamp()-7200,
        **{"id.resp_h": f"198.51.100.{i+1}", "duration": 4000 if long else 1}) for i in range(count))) + "#close\tfixture\n"
    (source / "conn.log").write_text(text)
    return source, state


@pytest.fixture
def small_snapshot(monkeypatch):
    monkeypatch.setattr(reports, "MAX_GROUPS", 2)
    monkeypatch.setattr(collector_module, "MAX_GROUPS", 2)


def full_payload(state):
    snapshot = read_snapshot(state)
    raw = reports.read_archive(state, snapshot["full_report"])
    return json.loads(gzip.decompress(raw))


def rules_for(count=5, *, start=NOW-timedelta(days=1), end=NOW+timedelta(days=1)):
    return parse_expected_connections(json.dumps({"schema_version": 1, "rules": [{
        "id": f"service{i}", "originator_ip": "192.0.2.1", "responder_ip": f"198.51.100.{i+1}",
        "responder_port": 443, "protocol": "tcp", "valid_from": start.isoformat(), "valid_until": end.isoformat(),
        "max_connections": 10, "max_duration_seconds": 5000, "max_originator_bytes": 10000,
        "max_responder_bytes": 10000} for i in range(count)]}).encode())


def test_connection_diversity_bypasses_only_dns_name_cap_and_preserves_late_cti():
    base = connections(1)[0]
    start = int(ipaddress.IPv6Address("2001:db8::1"))
    records = [replace(base, uid=f"C{i}", responder_ip=str(ipaddress.IPv6Address(start+i))) for i in range(25001)]
    indicator = IOCRecord(records[-1].responder_ip, IOCType.IPV6, "Fixture")
    result = runtime.analyze_connection_records(records, (indicator,))
    assert len(result.events) == len(result.connection_findings) == 25001
    assert len(result.matches) == 1 and result.matches[0].event.response_ip == records[-1].responder_ip
    assert not result.assessments and not result.device_findings and not result.ml_scores
    with pytest.raises(ValueError, match="25000 unique-query"):
        runtime.analyze_dns_events(result.events, (), None)


@pytest.mark.parametrize("changes", [{}, {"uid": "C0"}, {"state": "S0", "duration_seconds": 0}, {"protocol": "unknown_transport"}])
def test_under_bound_connection_report_matches_original_global_analysis(changes):
    records = connections(3, long=True)
    records = (*records, replace(records[0], **changes))
    indicators = (IOCRecord(records[0].responder_ip, IOCType.IPV4, "Fixture"),)
    old = runtime.analyze_dns_events([runtime.DNSEvent(r.responder_ip, r.timestamp, r.originator_ip, response_ip=r.responder_ip)
                                     for r in records], indicators, None, connections=records)
    new = runtime.analyze_connection_records(records, indicators)
    assert build_connection_report(old, generated_at=NOW, evaluated_at=NOW) == build_connection_report(new, generated_at=NOW, evaluated_at=NOW)


def test_connection_event_and_metadata_budgets_still_apply(monkeypatch):
    monkeypatch.setattr(runtime, "MAX_DNS_EVENTS", 1)
    with pytest.raises(ValueError, match="event analysis limit"):
        runtime.analyze_connection_records(connections(2))
    with pytest.raises(ValueError, match="length limit"):
        runtime.analyze_connection_records([replace(connections(1)[0], responder_ip="x"*1025)])


@unix
def test_full_retention_cti_priority_mapping_and_complete_archive(tmp_path, small_snapshot):
    source, state = make_input(tmp_path, long=True)
    indicator = IOCRecord("198.51.100.5", IOCType.IPV4, "Fixture")
    with collector_module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW, indicators=(indicator,))
    snapshot, full = read_snapshot(state), full_payload(state)
    assert status["counts"]["retained_records"] == 5 and not status["capacity_coverage_loss"]
    assert len(snapshot["findings"]) == 2 and len(full["findings"]) == 5
    assert snapshot["connection_coverage"]["omitted_groups"] == 3
    assert snapshot["connection_coverage"]["omitted_review_groups"] == 3
    assert snapshot["connection_coverage"]["omitted_cti_groups"] == 0
    assert any(r["CTI match"] for r in snapshot["findings"])
    for item in snapshot["findings"]:
        original = full["findings"][item["Full report group"]-1]
        assert {k:v for k,v in item.items() if k not in {"Group", "Full report group"}} == {k:v for k,v in original.items() if k!="Group"}
        timeline = next(g for g in snapshot["timelines"]["groups"] if g["group"] == item["Group"])
        assert sum(b["connections"] for b in timeline["buckets"]) == item["Connections"]
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in state.iterdir())
    assert "198.51.100.5" not in json.dumps(full) and "C4" not in json.dumps(full)


@unix
def test_archive_cache_cti_change_and_restart_preserve_groups(tmp_path, small_snapshot):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        before = read_snapshot(state)
        repeat = collector.tick(now=NOW+timedelta(seconds=1))
        assert repeat["scan"]["archive_reused"] and not repeat["scan"]["report_recomputed"]
        assert before["full_report"] == read_snapshot(state)["full_report"]
        changed = collector.tick(now=NOW+timedelta(seconds=2), indicators=(IOCRecord("198.51.100.5", IOCType.IPV4, "Fixture"),))
        after = read_snapshot(state)
        assert changed["scan"]["report_recomputed"] and before["full_report"]["file"] != after["full_report"]["file"]
        assert before["collector"]["selection_revision"] != after["collector"]["selection_revision"]
        full = full_payload(state)
    with collector_module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW+timedelta(seconds=3), indicators=(IOCRecord("198.51.100.5", IOCType.IPV4, "Fixture"),))
        assert status["counts"]["new_records"] == 0
    restarted = full_payload(state)
    assert all(full[k] == restarted[k] for k in ("findings", "timelines", "attempts"))
    assert full["dns"]["coverage"] == restarted["dns"]["coverage"]
    assert full["dns"]["report"]["findings"] == restarted["dns"]["report"]["findings"]
    assert len(list(state.glob("connections.full-*.json.gz"))) == 2


@unix
def test_incomplete_coverage_disables_context_even_in_full_archive(tmp_path, small_snapshot):
    source, state = make_input(tmp_path, long=True)
    with collector_module.ZeekCollector(source, state, max_records=3) as collector:
        status = collector.tick(now=NOW, rules=rules_for())
    assert status["counts"]["retained_records"] == 3 and status["capacity_coverage_loss"]
    assert len(full_payload(state)["findings"]) == 3
    assert all(not r["Declared expected"] for r in full_payload(state)["findings"])


@unix
def test_archive_cache_rechecks_completion_and_expiry_without_new_records(tmp_path, small_snapshot):
    source, state = make_input(tmp_path, count=3, long=True)
    path = source / "conn.log"
    path.write_text(path.read_text().replace(str(NOW.timestamp()-7200), str(NOW.timestamp()-3999), 1))
    rules = rules_for(1, end=NOW+timedelta(seconds=30))
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW, rules=rules)
        assert not full_payload(state)["findings"][0]["Declared expected"]
        changed = collector.tick(now=NOW+timedelta(seconds=2), rules=rules)
        assert changed["counts"]["new_records"] == 0 and changed["scan"]["report_recomputed"]
        assert full_payload(state)["findings"][0]["Declared expected"]
        repeat = collector.tick(now=NOW+timedelta(seconds=3), rules=rules)
        assert repeat["scan"]["archive_reused"]
        expired = collector.tick(now=NOW+timedelta(seconds=31), rules=rules)
        assert expired["scan"]["report_recomputed"]
        assert not full_payload(state)["findings"][0]["Declared expected"]


@unix
def test_archive_cache_rechecks_rule_activation(tmp_path, small_snapshot):
    source, state = make_input(tmp_path, count=3)
    path = source / "conn.log"
    path.write_text(path.read_text().replace(str(NOW.timestamp()-7200), str(NOW.timestamp()+2), 1))
    rules = rules_for(1, start=NOW+timedelta(seconds=1), end=NOW+timedelta(seconds=30))
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW, rules=rules)
        assert not full_payload(state)["findings"][0]["Declared expected"]
        activated = collector.tick(now=NOW+timedelta(seconds=4), rules=rules)
        assert activated["scan"]["report_recomputed"] and activated["counts"]["new_records"] == 0
        assert full_payload(state)["findings"][0]["Declared expected"]


@unix
def test_publication_failure_keeps_previous_snapshot_and_archive(tmp_path, small_snapshot, monkeypatch):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        previous = (state / "connections.json").read_bytes()
        snapshot = read_snapshot(state)
        old_archive = reports.read_archive(state, snapshot["full_report"])
        original = collector_module._atomic
        def fail(path, content):
            if path.name == "connections.json":
                raise OSError("simulated interrupted publication")
            return original(path, content)
        monkeypatch.setattr(collector_module, "_atomic", fail)
        with pytest.raises(OSError):
            collector.tick(now=NOW, indicators=(IOCRecord("198.51.100.5", IOCType.IPV4, "Fixture"),))
        assert (state / "connections.json").read_bytes() == previous
        assert reports.read_archive(state, snapshot["full_report"]) == old_archive
        monkeypatch.setattr(collector_module, "_atomic", original)
    with collector_module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 0
    assert len(full_payload(state)["findings"]) == 5


@unix
@pytest.mark.parametrize("tamper", ["hash", "link", "permissions", "size", "path", "missing", "fifo"])
def test_changed_or_unsafe_archive_cannot_be_downloaded(tmp_path, small_snapshot, tamper):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    reference = dict(read_snapshot(state)["full_report"])
    path = state / reference["file"]
    if tamper == "hash":
        raw = path.read_bytes()
        path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
    elif tamper == "link":
        copy = state / "copy"
        copy.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(copy)
    elif tamper == "permissions":
        path.chmod(0o644)
    elif tamper == "size":
        reference["compressed_bytes"] += 1
    elif tamper == "path":
        reference["file"] = "../private.sqlite"
    elif tamper == "missing":
        path.unlink()
    else:
        path.unlink()
        os.mkfifo(path)
    with pytest.raises((ValueError, OSError)):
        reports.read_archive(state, reference)


@unix
@pytest.mark.parametrize("budget", ["MAX_EXPANDED_BYTES", "MAX_ARCHIVE_BYTES"])
def test_archive_budget_failure_preserves_old_generation(tmp_path, small_snapshot, monkeypatch, budget):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        snapshot = read_snapshot(state)
        raw = reports.read_archive(state, snapshot["full_report"])
        monkeypatch.setattr(reports, budget, 1)
        with pytest.raises(ValueError):
            collector.tick(now=NOW, indicators=(IOCRecord("198.51.100.5", IOCType.IPV4, "Fixture"),))
        assert (state / snapshot["full_report"]["file"]).read_bytes() == raw
        assert not list(state.glob(".collector-archive-*"))


@unix
def test_unrelated_archive_slot_file_survives(tmp_path, small_snapshot):
    source, state = make_input(tmp_path)
    state.mkdir(mode=0o700)
    user_file = state / "connections.full-a.json.gz"
    user_file.write_text("preserve user contents")
    with collector_module.ZeekCollector(source, state) as collector:
        with pytest.raises(ValueError, match="unrelated"):
            collector.tick(now=NOW)
    assert user_file.read_text() == "preserve user contents"


@unix
@pytest.mark.parametrize("language", ["en", "tr"])
def test_bilingual_partial_ui_defers_download_and_public_view_has_no_io(tmp_path, small_snapshot, monkeypatch, language):
    source, state = make_input(tmp_path, long=True)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    callbacks = []
    original = st.download_button
    def capture(*args, **kwargs):
        if callable(kwargs.get("data")):
            callbacks.append(kwargs["data"])
        return original(*args, **kwargs)
    monkeypatch.setattr(st, "download_button", capture)
    label = "🇹🇷 Türkçe" if language == "tr" else "🇬🇧 English"
    code = f'from pathlib import Path\nimport streamlit as st\nfrom threatfusion.ui_collector import render_collector\nst.session_state["language_selector"]={label!r}\nrender_collector(Path({str(state)!r}), public_mode=False)'
    app = AppTest.from_string(code).run()
    assert not app.exception and len(callbacks) == 1
    assert len(json.loads(gzip.decompress(callbacks[0]()))["findings"]) == 5
    metric = next(m for m in app.metric if m.label == ("Original TCP reviews" if language == "en" else "Asıl TCP incelemeleri"))
    assert metric.value == "5"
    callback = callbacks[0]
    (state / read_snapshot(state)["full_report"]["file"]).unlink()
    with pytest.raises(RuntimeError):
        callback()
    callbacks.clear()
    app = AppTest.from_string(code.replace("public_mode=False", "public_mode=True")).run()
    assert not app.exception and not callbacks and not app.metric and not app.warning


@unix
def test_malformed_projection_counts_and_mapping_fail_closed(tmp_path, small_snapshot):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    original = (state / "connections.json").read_bytes()
    for mutate in [lambda d: d["connection_coverage"].update(omitted_groups=0),
                   lambda d: d["connection_coverage"].update(omitted_cti_groups=1),
                   lambda d: d["findings"][0].update({"Full report group": 0}),
                   lambda d: d["full_report"].update(file="/private/secret"),
                   lambda d: d["collector"]["scan"].update(archive_reused="true")]:
        data = json.loads(original)
        mutate(data)
        (state / "connections.json").write_text(json.dumps(data))
        with pytest.raises(ValueError):
            read_snapshot(state)


@unix
def test_first_archive_publication_race_preserves_user_file(tmp_path, small_snapshot, monkeypatch):
    source, state = make_input(tmp_path)
    original = reports.publish
    def race(temporary, destination):
        destination.write_text("preserve concurrent user file")
        return original(temporary, destination)
    monkeypatch.setattr(reports, "publish", race)
    with collector_module.ZeekCollector(source, state) as collector:
        with pytest.raises(OSError):
            collector.tick(now=NOW)
    assert (state / "connections.full-a.json.gz").read_text() == "preserve concurrent user file"
    assert not (state / "connections.json").exists()
    monkeypatch.setattr(reports, "publish", original)
    with collector_module.ZeekCollector(source, state) as collector:
        with pytest.raises(ValueError, match="unrelated"):
            collector.tick(now=NOW)


@unix
def test_cached_archive_tampering_is_repaired_without_reimport(tmp_path, small_snapshot):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        old = read_snapshot(state)["full_report"]
        (state / old["file"]).write_text("damaged")
        status = collector.tick(now=NOW)
        assert status["counts"]["new_records"] == 0 and status["scan"]["report_recomputed"]
        assert read_snapshot(state)["full_report"]["file"] != old["file"]
        assert len(full_payload(state)["findings"]) == 5


@unix
def test_omitted_cti_and_review_counts_remain_visible(tmp_path, small_snapshot):
    source, state = make_input(tmp_path, long=True)
    indicators = [IOCRecord(f"198.51.100.{i+1}", IOCType.IPV4, "Fixture") for i in range(5)]
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW, indicators=indicators, rules=rules_for())
    coverage = read_snapshot(state)["connection_coverage"]
    assert coverage["review_counts"]["TCP CTI groups"] == 5
    assert coverage["omitted_cti_groups"] == coverage["omitted_review_groups"] == 3
    assert coverage["omitted_unexplained_groups"] == 3
    assert all(r["CTI match"] and not r["Declared expected"] for r in full_payload(state)["findings"])


@unix
@pytest.mark.parametrize("changed_user_file", [False, True])
def test_expiry_releases_cache_and_only_intact_owned_archives(tmp_path, small_snapshot, changed_user_file):
    source, state = make_input(tmp_path)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        path = state / read_snapshot(state)["full_report"]["file"]
        if changed_user_file:
            path.write_text("preserve user edits")
        status = collector.tick(now=NOW+timedelta(days=2))
        assert status["counts"]["retained_records"] == 0
        assert not read_snapshot(state)["findings"] and "full_report" not in read_snapshot(state)
        assert collector.report_cache is None
        if changed_user_file:
            assert path.read_text() == "preserve user edits"
        else:
            assert not path.exists()


@unix
def test_interrupted_archive_finalization_recovers_pending_ownership(tmp_path, small_snapshot, monkeypatch):
    source, state = make_input(tmp_path)
    indicator = IOCRecord("198.51.100.5", IOCType.IPV4, "Fixture")
    original = collector_module.write_archive
    def interrupted(directory, payload, owned, reserve):
        calls = 0
        def fail(slot, hashes):
            nonlocal calls
            calls += 1
            reserve(slot, hashes)
            if calls == 2:
                raise OSError("simulated archive finalization interruption")
        return original(directory, payload, owned, fail)
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        snapshot = read_snapshot(state)
        old = reports.read_archive(state, snapshot["full_report"])
        monkeypatch.setattr(collector_module, "write_archive", interrupted)
        with pytest.raises(OSError):
            collector.tick(now=NOW, indicators=(indicator,))
        assert reports.read_archive(state, snapshot["full_report"]) == old
    monkeypatch.setattr(collector_module, "write_archive", original)
    with collector_module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW, indicators=(indicator,))["counts"]["new_records"] == 0
    assert sum(r["CTI match"] for r in full_payload(state)["findings"]) == 1
