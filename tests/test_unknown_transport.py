"""Legitimate Zeek enum import without expanding TCP detection eligibility."""
import gzip
import json
import os
from datetime import datetime, timezone

import pytest

from tests.test_connections import log, row
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot
from scripts.lab import verify_unknown_transport as verifier


@pytest.mark.parametrize("protocol", ["tcp", "udp", "icmp", "unknown_transport"])
def test_official_transport_values_survive_without_invalid_metadata(protocol):
    parsed = parse_zeek_conn_log_with_diagnostics(log(row(proto=protocol)))
    assert parsed.diagnostics.accepted_rows == 1
    assert parsed.diagnostics.invalid_connection_fields == 0
    assert parsed.connections[0].protocol == protocol


@pytest.mark.parametrize("protocol", ["x" * 17, "unknown_transportx", "xunknown_transport", "UNKNOWN_TRANSPORT", "unknown_transport " + "x"])
def test_exception_does_not_accept_arbitrary_overlong_protocol_fields(protocol):
    parsed = parse_zeek_conn_log_with_diagnostics(log(row(proto=protocol)))
    assert parsed.diagnostics.invalid_connection_fields == 1
    assert parsed.connections[0].protocol is None


def test_unknown_long_periodic_and_failed_traffic_is_never_reclassified_as_tcp():
    records = [row(uid=f"U{i}", proto="unknown_transport", ts=1791072000 + 300 * i) for i in range(24)]
    records += [row(uid=f"F{i}", proto="unknown_transport", conn_state="S0", ts=1791072000 + i) for i in range(30)]
    records += [row(uid="TCP", proto="tcp")]
    result, diagnostics = analyze_zeek_conn_log_with_diagnostics(log(*records), (), None)
    assert diagnostics.invalid_connection_fields == 0
    unknown = next(f for f in result.connection_findings if f.protocol == "unknown_transport")
    tcp = next(f for f in result.connection_findings if f.protocol == "tcp")
    assert unknown.connection_count == 54 and unknown.priority == "observe"
    assert not unknown.reasons and unknown.confirmed_session_count == unknown.payload_session_count == unknown.failed_attempt_count == 0
    assert tcp.priority == "review" and tcp.reasons == ("long_bidirectional_tcp_session",)
    assert not result.connection_attempts.findings
    assert "unknown_transport" in build_connection_report(result)


def test_unknown_enum_exception_preserves_other_optional_field_bounds():
    parsed = parse_zeek_conn_log_with_diagnostics(log(row(proto="unknown_transport", uid="x" * 129, duration=-1)))
    assert parsed.diagnostics.invalid_connection_fields == 2
    assert parsed.connections[0].protocol == "unknown_transport"
    assert parsed.connections[0].uid is None and parsed.connections[0].duration_seconds is None


def test_conflicting_uid_across_known_and_unknown_transport_is_not_double_evidence():
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(row(proto="tcp"), row(proto="unknown_transport")), (), None)
    assert all(f.connection_count == 0 and f.priority == "observe" for f in result.connection_findings)
    assert all(f.conflicting_uids == 1 for f in result.connection_findings)


@pytest.mark.skipif(os.name != "posix", reason="Linux completed-file collector contract")
def test_collector_retains_unknown_rows_after_restart_and_gzip_copy(tmp_path):
    source, state = tmp_path / "source", tmp_path / "state"
    source.mkdir()
    raw = log(row(proto="unknown_transport"), row(uid="TCP", proto="tcp")) + "#close\t2026-10-04-00-00-00\n"
    (source / "conn.log").write_text(raw)
    now = datetime(2026, 10, 4, 2, tzinfo=timezone.utc)
    with ZeekCollector(source, state) as collector:
        first = collector.tick(now=now)
    assert first["counts"]["rejected_files"] == 0 and first["counts"]["retained_records"] == 2
    before = read_snapshot(state)
    assert "unknown_transport" in json.dumps(before)
    (source / "conn.copy.log.gz").write_bytes(gzip.compress(raw.encode()))
    with ZeekCollector(source, state) as collector:
        repeated = collector.tick(now=now)
    assert repeated["counts"]["new_records"] == 0 and repeated["counts"]["duplicate_files"] == 1
    assert read_snapshot(state)["findings"] == before["findings"]


@pytest.mark.skipif(os.name != "posix", reason="Linux completed-file collector contract")
def test_collector_still_rejects_arbitrary_oversized_protocol_fields(tmp_path):
    source, state = tmp_path / "source", tmp_path / "state"
    source.mkdir()
    (source / "conn.log").write_text(log(row(proto="unknown_transportx")) + "#close\t2026-10-04-00-00-00\n")
    with ZeekCollector(source, state) as collector:
        result = collector.tick(now=datetime(2026, 10, 4, 2, tzinfo=timezone.utc))
    assert result["counts"]["rejected_files"] == 1 and result["counts"]["retained_records"] == 0


@pytest.mark.skipif(os.name != "posix", reason="Private Linux replay directory")
@pytest.mark.parametrize("tamper", ["plan", "runtime"])
def test_compatibility_replay_aborts_before_analysis_when_scope_changes(tmp_path, monkeypatch, tamper):
    from scripts.lab.evaluate_dns_collector import private_root, write_new
    root = private_root(tmp_path / "replay")
    baseline = private_root(tmp_path / "baseline")
    write_new(root / "plan.json", {"protocol": "unknown-transport-import-v1", "permitted_change": ["src/threatfusion/network_telemetry.py"],
                                 "baseline_runtime": {"src/threatfusion/network_telemetry.py": "old", "other.py": "same"}})
    (root / "plan.sha256").write_text(verifier.sha(root / "plan.json") + "\n")
    if tamper == "plan":
        (root / "plan.json").write_text("{}")
    else:
        monkeypatch.setattr(verifier, "runtime_hashes", lambda: {"src/threatfusion/network_telemetry.py": "new", "other.py": "changed"})
    monkeypatch.setattr(verifier, "analyze_zeek_conn_log_with_diagnostics", lambda *a: pytest.fail("Changed scope reached analysis"))
    with pytest.raises(ValueError, match="changed|permitted"):
        verifier.evaluate(root, baseline)
    assert not (root / "candidate-freeze.json").exists()
