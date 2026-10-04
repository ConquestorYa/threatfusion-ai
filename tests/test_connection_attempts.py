from __future__ import annotations

import copy
import json
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from streamlit.testing.v1 import AppTest

from scripts.lab.evaluate_attempt_controls import CONTRACT, controls
from scripts.lab.evaluate_connection_controls import zeek_text
from threatfusion.connection_attempts import (
    MAX_FINDINGS,
    analyze_attempts,
    validate_attempt_report,
)
from threatfusion.connections import ConnectionRecord, analyze_connections
from threatfusion.reporting import build_analysis_report, build_connection_report
from threatfusion.runtime_analysis import (
    analyze_dns_events,
    analyze_zeek_conn_log_with_diagnostics,
)

NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


def record(i, **changes):
    return replace(
        ConnectionRecord(
            f"private-uid-{i}",
            NOW + timedelta(seconds=i),
            "192.0.2.1",
            "198.51.100.1",
            40000 + i,
            20000 + i,
            "tcp",
            0.01,
            0,
            0,
            "REJ",
            0,
        ),
        **changes,
    )


def result_for(name):
    case = next(c for c in controls(20261008) if c["name"] == name)
    return analyze_zeek_conn_log_with_diagnostics(zeek_text(case["records"]), [], None)[
        0
    ]


@pytest.mark.parametrize("case", controls(20261008), ids=lambda c: c["name"])
def test_predeclared_attempt_contract_and_unchanged_original_pipeline(case):
    result, _ = analyze_zeek_conn_log_with_diagnostics(
        zeek_text(case["records"]), [], None
    )
    assert (
        sorted(f.pattern for f in result.connection_attempts.findings)
        == case["expected_patterns"]
    )
    original = analyze_dns_events(result.events, [], None)
    assert result.assessments == original.assessments
    assert result.device_findings == original.device_findings
    payload = json.loads(build_connection_report(result))
    assert payload["attempts"]["policy"] == CONTRACT["policy"]
    validate_attempt_report(payload["attempts"])


def test_identity_conflicts_across_sources_and_denominator_order_are_conservative():
    rows = tuple(record(i) for i in range(24))
    result = analyze_dns_events([], [], None, connections=rows + rows)
    assert result.connection_findings == analyze_connections(rows + rows)
    assert result.connection_attempts.duplicate_rows == 24
    assert result.connection_attempts.findings[0].failed_attempts == 24
    conflicts = rows + tuple(replace(r, originator_ip="192.0.2.2") for r in rows)
    analysis = analyze_attempts(conflicts)
    assert analysis.conflicting_uids == 24 and not analysis.findings
    case = next(
        c
        for c in controls(20261008)
        if c["name"] == "simultaneous_successes_count_in_denominator"
    )
    for rows in (case["records"], list(reversed(case["records"]))):
        result, _ = analyze_zeek_conn_log_with_diagnostics(zeek_text(rows), [], None)
        assert not result.connection_attempts.findings


def test_retry_denominator_boundary_other_windows_and_source_isolation():
    rows = tuple(record(i, responder_port=443, timestamp=NOW) for i in range(36))
    successful = tuple(
        record(
            100 + i,
            responder_port=443,
            timestamp=NOW,
            state="SF",
            originator_bytes=16,
            responder_bytes=16,
        )
        for i in range(4)
    )
    (finding,) = analyze_attempts(rows + successful).findings
    assert finding.failure_fraction == 0.9
    assert finding.failed_attempts == 36 and finding.observed_records == 40
    assert not analyze_attempts(
        rows
        + successful
        + (record(200, responder_port=443, timestamp=NOW, state="SF"),)
    ).findings
    bad = record(999, timestamp=NOW - timedelta(seconds=301), missed_bytes=1)
    assert len(analyze_attempts(rows + (bad,)).findings) == 1
    bad = replace(bad, timestamp=None, originator_ip="192.0.2.2")
    assert len(analyze_attempts(rows + (bad,)).findings) == 1
    bad = replace(bad, originator_ip="192.0.2.1")
    assert not analyze_attempts(rows + (bad,)).findings


def test_reports_hide_identity_keep_new_queue_separate_and_cap_outputs():
    result = result_for("vertical_rejections")
    private = build_connection_report(result)
    assert "192.0.2.1" not in private and "198.51.100.1" not in private
    raw = build_connection_report(result, include_ips=True)
    assert "192.0.2.1" in raw and "198.51.100.1" in raw
    assert "private-uid" not in raw
    assert "attempts" not in json.loads(
        build_analysis_report(result, model_name="cti-only").json_text
    )
    rows = tuple(
        record(
            j * 20 + i,
            originator_ip=f"192.0.{j // 254}.{j % 254 + 1}",
            responder_port=20000 + i,
        )
        for j in range(MAX_FINDINGS + 2)
        for i in range(20)
    )
    analysis = analyze_attempts(rows)
    assert len(analysis.findings) == MAX_FINDINGS and analysis.omitted_findings == 2
    assert not analyze_attempts(()).findings
    with pytest.raises(ValueError, match="limit"):
        analyze_attempts((record(0),) * 100001)


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p.update(policy="unknown"),
        lambda p: p.update(eligible_records=True),
        lambda p: p["findings"][0].update(**{"Failed attempts": -1}),
        lambda p: p["findings"][0].update(**{"Unanswered attempts": 99}),
        lambda p: p["findings"][0].update(**{"Failure fraction": float("nan")}),
        lambda p: p["findings"][0].update(**{"First observed": "2026-10-05T00:00:00"}),
        lambda p: p["findings"][0].update(
            **{"Last observed": "2026-10-05T01:00:00+00:00"}
        ),
        lambda p: p["findings"][0].update(**{"Responder port": 70000}),
        lambda p: p["findings"][0].update(Pattern="unknown"),
    ],
)
def test_private_snapshot_rejects_invalid_or_misleading_attempt_blocks(change):
    payload = json.loads(build_connection_report(result_for("vertical_rejections")))[
        "attempts"
    ]
    modified = copy.deepcopy(payload)
    change(modified)
    with pytest.raises(ValueError):
        validate_attempt_report(modified)


@pytest.mark.parametrize("public_mode", [False, True])
def test_upload_ui_shows_scans_even_when_original_review_filter_has_no_rows(
    public_mode,
):
    case = controls(20261008)[0]
    app = AppTest.from_string(
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"result,_=analyze_zeek_conn_log_with_diagnostics({zeek_text(case['records'])!r},[],None)\n"
        f"render_connections(result,public_mode={public_mode!r})\n"
    ).run(timeout=15)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["Distinct ports"] == 24
    assert app.dataframe[0].value.iloc[0]["Originator"] == "Host 001"
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["Farklı portlar"] == 24
    assert (
        app.dataframe[0].value.iloc[0]["Örüntü"]
        == "Birden fazla porta başarısız denemeler"
    )


@pytest.mark.skipif(os.name != "posix", reason="Linux collector contract")
def test_collector_restart_snapshot_and_bilingual_ui_match_offline_attempts(tmp_path):
    from threatfusion.telemetry_collector import ZeekCollector
    from threatfusion.ui_collector import read_snapshot

    source = tmp_path / "logs"
    source.mkdir()
    case = controls(20261008)[0]
    (source / "conn.log").write_text(zeek_text(case["records"]) + "#close\tfixture\n")
    state = tmp_path / "private"
    with ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
    assert (
        status["counts"]["attempt_review_groups"] == 1
        and status["counts"]["review_groups"] == 0
    )
    before = read_snapshot(state)
    assert (
        before["attempts"]
        == json.loads(build_connection_report(result_for("vertical_rejections")))[
            "attempts"
        ]
    )
    with ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 0
    assert read_snapshot(state)["attempts"] == before["attempts"]
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\n"
        f"render_collector(Path({str(state)!r}),public_mode=False)\n"
    ).run(timeout=15)
    assert not app.exception and app.dataframe[0].value.iloc[0]["Distinct ports"] == 24
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception and app.dataframe[0].value.iloc[0]["Farklı portlar"] == 24
