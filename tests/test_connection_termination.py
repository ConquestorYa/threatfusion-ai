from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from streamlit.testing.v1 import AppTest

from scripts.lab.evaluate_connection_controls import zeek_text
from scripts.lab.evaluate_session_coverage import controls
from threatfusion.connections import ConnectionRecord, analyze_connections
from threatfusion.expected_connections import connection_contexts, parse_expected_connections
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics


@pytest.mark.parametrize("state", ["S2", "S3", "RSTO", "RSTR"])
def test_bidirectional_termination_evidence_can_review_but_cannot_be_declared_expected(state):
    start = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
    records = [ConnectionRecord(f"C{i}",start+timedelta(seconds=300*i),"192.0.2.1",
                               "198.51.100.1",40000+i,443,"tcp",1,100,200,state,0) for i in range(24)]
    finding, = analyze_connections(tuple(records))
    assert finding.priority == "review" and finding.payload_session_count == 24
    assert finding.confirmed_session_count == 0
    assert finding.reasons == ("sustained_periodic_payload_connections",)
    assert finding.reset_session_count == (24 if state.startswith("RST") else 0)
    assert finding.partial_close_count == (24 if state.startswith("S") else 0)
    rows = [{"ts":r.timestamp.timestamp(),"uid":r.uid,"id.orig_h":r.originator_ip,
             "id.orig_p":r.originator_port,"id.resp_h":r.responder_ip,"id.resp_p":443,
             "proto":"tcp","duration":1,"orig_bytes":100,"resp_bytes":200,
             "conn_state":state,"missed_bytes":0} for r in records]
    result, _ = analyze_zeek_conn_log_with_diagnostics(zeek_text(rows), [], None)
    rules = parse_expected_connections(json.dumps({"schema_version":1,"rules":[{
        "id":"verified-updater","originator_ip":"192.0.2.1","responder_ip":"198.51.100.1",
        "responder_port":443,"protocol":"tcp","valid_from":(start-timedelta(days=1)).isoformat(),
        "valid_until":(start+timedelta(days=1)).isoformat(),"max_connections":100,
        "max_duration_seconds":10000,"max_originator_bytes":100000,"max_responder_bytes":100000,
    }]}).encode())
    context, = connection_contexts(result,rules,evaluated_at=start+timedelta(hours=3))
    assert not context.expected and context.reason == "incomplete_evidence"
    report = build_connection_report(result,expected_rules=rules,evaluated_at=start+timedelta(hours=3))
    assert json.loads(report)["policy"] == "zeek-connection-context-v2"
    assert json.loads(report)["findings"][0]["Bidirectional payload sessions"] == 24
    assert "192.0.2.1" not in report and "C0" not in report and "verified-updater" not in report


@pytest.mark.parametrize("state", ["S0","REJ","RSTOS0","RSTRH","SH","SHR","OTH"])
def test_unconfirmed_states_do_not_inherit_payload_review_even_with_long_duration(state):
    record = ConnectionRecord("C1",datetime(2026,10,4,tzinfo=timezone.utc),"192.0.2.1",
                              "198.51.100.1",40000,443,"tcp",4000,100,200,state,0)
    finding, = analyze_connections((record,record))
    assert finding.priority == "observe" and finding.payload_session_count == 0
    assert finding.failed_attempt_count == (0 if state == "OTH" else 1)
    assert finding.duplicate_rows == 1
    missing, = analyze_connections((replace(record,missed_bytes=None),))
    assert missing.payload_session_count == 0


def test_declared_contract_controls_cover_benign_noise_and_incomplete_metadata():
    for case in controls(20261005):
        result, _ = analyze_zeek_conn_log_with_diagnostics(zeek_text(case["records"]),[],None)
        actual = "review" if any(f.priority == "review" for f in result.connection_findings) else "observe"
        assert actual == case["expected_priority"],case["name"]


def test_reset_session_ui_explains_coverage_and_translates_counts():
    records = next(c["records"] for c in controls(20261005) if c["name"] == "periodic_RSTR")
    app = AppTest.from_string(
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"r,_=analyze_zeek_conn_log_with_diagnostics({zeek_text(records)!r},[],None)\n"
        "render_connections(r,public_mode=True)\n"
    ).run(timeout=15)
    assert not app.exception
    row = app.dataframe[0].value.iloc[0]
    assert row["Reset endings"] == row["Bidirectional payload sessions"] == 24
    assert "reset" in row["Coverage limits"]
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception
    row = app.dataframe[0].value.iloc[0]
    assert row["Reset ile bitenler"] == row["Çift yönlü veri oturumları"] == 24
    assert "reset" in row["Kanıt"]


@pytest.mark.skipif(os.name != "posix", reason="Linux collector contract")
def test_completed_reset_log_reaches_private_collector_snapshot(tmp_path):
    from threatfusion.telemetry_collector import ZeekCollector
    from threatfusion.ui_collector import read_snapshot

    source = tmp_path / "spool"
    source.mkdir()
    case = next(c for c in controls(20261005) if c["name"] == "periodic_RSTR")
    (source/"conn.reset.log").write_text(zeek_text(case["records"])+"#close\tfixture\n")
    state = tmp_path / "private"
    with ZeekCollector(source,state) as collector:
        collector.tick(now=datetime(2026,10,4,18,tzinfo=timezone.utc))
    snapshot = read_snapshot(state)
    assert snapshot["policy"] == "zeek-connection-context-v2"
    row, = snapshot["findings"]
    assert row["Queue priority"] == "Review" and row["Reset endings"] == 24
    assert row["Confirmed sessions"] == 0 and not row["Declared expected"]
