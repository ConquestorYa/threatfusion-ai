from __future__ import annotations

import json
import os
import socket

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion import cli
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.reporting import build_analysis_report, build_connection_report
from threatfusion.runtime_analysis import analyze_dns_upload_with_diagnostics, analyze_zeek_conn_log_with_diagnostics

FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "label")


def row(**changes):
    return dict(zip(FIELDS, (1791072000, "C1", "192.0.2.1", 45000, "198.51.100.1", 443,
                             "tcp", 4000, 100, 200, "SF", 0, "Malicious"), strict=True)) | changes


def log(*rows):
    return "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n" + "".join(
        "\t".join(str(r[field]) for field in FIELDS) + "\n" for r in rows
    )


def test_parser_preserves_connection_evidence_and_ignores_dataset_labels():
    parsed = parse_zeek_conn_log_with_diagnostics(log(row()))
    record = parsed.connections[0]
    assert record.uid == "C1"
    assert record.duration_seconds == 4000
    assert record.originator_bytes == 100 and record.responder_bytes == 200
    assert record.originator_port == 45000 and record.responder_port == 443
    assert record.state == "SF" and record.protocol == "tcp"
    assert not hasattr(record, "label")
    result, _, detection = analyze_dns_upload_with_diagnostics(log(row()).encode(), "conn.log", [], None)
    assert detection.format_name == "Zeek conn.log"
    assert result.connection_findings[0].reasons == ("long_bidirectional_tcp_session",)
    assert result.connection_findings[0].priority == "review"
    assert result.assessments[0].verdict.value == "low"
    assert "sustained_periodic_dns" not in result.device_findings[0].reasons


@pytest.mark.parametrize("field,value", [
    ("duration", "nan"), ("duration", "inf"), ("duration", -1),
    ("duration", 365 * 86400 + 1), ("orig_bytes", -1), ("resp_bytes", "1.5"),
    ("id.resp_p", 65536), ("uid", "x" * 129), ("missed_bytes", "unknown"),
])
def test_invalid_optional_metadata_is_counted_and_not_guessed(field, value):
    parsed = parse_zeek_conn_log_with_diagnostics(log(row(**{field: value})))
    assert parsed.diagnostics.accepted_rows == 1
    assert parsed.diagnostics.invalid_connection_fields == 1
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(row(**{field: value})), [], None)
    assert result.connection_findings[0].priority == "observe"


@pytest.mark.parametrize("changes", [
    {"proto": "udp"}, {"conn_state": "S0"}, {"missed_bytes": 1},
    {"orig_bytes": "-"}, {"resp_bytes": 0}, {"id.orig_h": "unknown"},
])
def test_incomplete_or_unconfirmed_long_sessions_are_not_reviewed(changes):
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(row(**changes)), [], None)
    assert result.connection_findings[0].priority == "observe"


def test_periodic_successful_connections_get_review_without_domain_claim():
    records = [row(uid=f"C{i}", ts=1791072000 + i * 300, duration=0.5) for i in range(24)]
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(*records), [], None)
    finding = result.connection_findings[0]
    assert finding.connection_count == 24 and finding.confirmed_session_count == 24
    assert finding.interval_seconds == 300 and finding.periodicity_score == 1
    assert finding.reasons == ("sustained_periodic_connections",)
    assert finding.originator_bytes == 2400 and finding.responder_bytes == 4800
    assert finding.limitations == ()
    assert result.assessments[0].verdict.value == "low"


def test_ports_and_protocols_are_independent_groups():
    records = [row(uid=f"C{i}", ts=1791072000 + i * 300, duration=0.5,
                   **{"id.resp_p": 443 if i % 2 else 8443}) for i in range(24)]
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(*records), [], None)
    assert len(result.connection_findings) == 2
    assert all(f.priority == "observe" for f in result.connection_findings)


def test_duplicate_and_conflicting_uids_cannot_create_extra_evidence():
    records = [row(uid=f"C{i}", ts=1791072000 + i * 300, duration=0.5) for i in range(12)]
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(*(records + records)), [], None)
    finding = result.connection_findings[0]
    assert finding.connection_count == 12 and finding.duplicate_rows == 12
    assert finding.priority == "observe"
    result, _ = analyze_zeek_conn_log_with_diagnostics(
        log(row(), row(**{"id.resp_h": "198.51.100.2"})), [], None,
    )
    assert len(result.connection_findings) == 2
    assert all(f.connection_count == 0 and f.conflicting_uids == 1 for f in result.connection_findings)
    assert all(f.priority == "observe" for f in result.connection_findings)


def test_missing_metadata_is_unknown_not_zero_and_empty_input_is_supported():
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(row(duration="-", orig_bytes="-")), [], None)
    finding = result.connection_findings[0]
    assert finding.max_duration_seconds is None and finding.originator_bytes is None
    assert finding.responder_bytes == 200
    assert analyze_zeek_conn_log_with_diagnostics("", [], None)[0].connection_findings == ()


def test_connection_exports_hide_both_endpoints_and_uids_by_default(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Local connection analysis must not access the network")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result, _ = analyze_zeek_conn_log_with_diagnostics(log(row()), [], None)
    report = build_connection_report(result)
    assert "192.0.2.1" not in report and "198.51.100.1" not in report and "C1" not in report
    assert json.loads(report)["findings"][0]["Originator"] == "Host 001"
    raw = build_connection_report(result, include_ips=True)
    assert "192.0.2.1" in raw and "198.51.100.1" in raw
    assert "connection_uids_included\": false" in raw
    assert "connection_findings" not in build_analysis_report(result, model_name="cti-only").json_text


def test_cli_has_explicit_private_connection_export(tmp_path, monkeypatch):
    path = tmp_path / "conn.log"
    path.write_text(log(row()))
    output = tmp_path / "connections.json"
    monkeypatch.setattr(cli, "load_ioc_records", lambda path: [])
    args = [str(path), "--format", "zeek-conn", "--cti-only", "--connection-json-output", str(output)]
    assert cli.main(args) == 0
    assert "192.0.2.1" not in output.read_text()
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        cli.main(args)
    with pytest.raises(SystemExit):
        cli.main([str(path), "--include-connection-ips"])


@pytest.mark.parametrize("public_mode", [True, False])
def test_connection_ui_has_explicit_local_ip_toggle(public_mode):
    app = AppTest.from_string(
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"result, _ = analyze_zeek_conn_log_with_diagnostics({log(row())!r}, [], None)\n"
        f"render_connections(result, public_mode={public_mode!r})\n"
    ).run(timeout=15)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["Originator"] == "Host 001"
    toggles = [c for c in app.checkbox if c.key == "connection_include_ips"]
    assert bool(toggles) is not public_mode
    if toggles:
        toggles[0].check().run(timeout=15)
        assert app.dataframe[0].value.iloc[0]["Originator"] == "192.0.2.1"
        app.checkbox(key="connection_include_ips").uncheck()
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["Başlatan"] == "Sistem 001"
    assert "Uzun çift yönlü" in app.dataframe[0].value.iloc[0]["Kanıt"]


def test_whole_dashboard_renders_auto_detected_connection_context(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFUSION_CTI_ONLY", "1")
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "0")
    monkeypatch.setenv("THREATFUSION_DB_PATH", str(tmp_path / "cti.sqlite"))
    monkeypatch.setenv("THREATFUSION_EVALUATION_REPORT", str(tmp_path / "missing.json"))
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from threatfusion.runtime_analysis import analyze_dns_upload_with_diagnostics\n"
        f"result, _, _ = analyze_dns_upload_with_diagnostics({log(row()).encode()!r}, 'conn.log', [], None)\n"
        "st.session_state['analysis_result'] = result\n"
        "import streamlit_app\nstreamlit_app.main()\n"
    ).run(timeout=15)
    assert not app.exception
    assert "Connection activity" in [tab.label for tab in app.tabs]
    frames = [frame.value for frame in app.dataframe if "Originator" in frame.value.columns]
    assert len(frames) == 1
    assert frames[0].iloc[0]["Max duration (s)"] == 4000
    assert frames[0].iloc[0]["Originator"] == "Host 001"
