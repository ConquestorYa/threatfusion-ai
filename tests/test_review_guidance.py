"""Analyst task contracts, not a human usability or detection benchmark."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion import ui_connections
from threatfusion.dashboard import contextual_connection_rows
from threatfusion.expected_connections import parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
from threatfusion.ui_review_guidance import connection_steps, review_counts

NOW = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)


def rule(now=NOW, **changes):
    return dict(id="private-service-id", originator_ip="192.0.2.1", responder_ip="198.51.100.1",
                responder_port=443, protocol="tcp", valid_from=(now - timedelta(days=1)).isoformat(),
                valid_until=(now + timedelta(days=1)).isoformat(), max_connections=10,
                max_duration_seconds=7200, max_originator_bytes=10000, max_responder_bytes=10000) | changes


def telemetry(now=NOW, **changes):
    row = dict(ts=(now - timedelta(hours=3)).timestamp(), uid="private-uid",
               **{"id.orig_h": "192.0.2.1", "id.orig_p": 32000,
                  "id.resp_h": "198.51.100.1", "id.resp_p": 443},
               proto="tcp", duration=4000, orig_bytes=100, resp_bytes=200,
               conn_state="SF", missed_bytes=0) | changes
    return "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(row) + "\n" + "\t".join(map(str, row.values())) + "\n"


@pytest.mark.parametrize("rule_changes,record_changes,cti,expected,phrase", [
    ({}, {}, False, True, "unrelated process"),
    ({}, {}, True, False, "cannot clear this CTI"),
    ({"valid_until": NOW.isoformat()}, {}, False, False, "expiry"),
    ({"responder_port": 8443}, {}, False, False, "exact IP/port/protocol"),
    ({"max_duration_seconds": 3999}, {}, False, False, "before changing any limits"),
    ({}, {"conn_state": "RSTO"}, False, False, "Incomplete evidence"),
])
def test_context_tasks_preserve_priority_reports_and_sensitive_references(rule_changes, record_changes, cti, expected, phrase):
    indicators = [IOCRecord("198.51.100.1", IOCType.IPV4, "synthetic")] if cti else []
    result, _ = analyze_zeek_conn_log_with_diagnostics(telemetry(**record_changes), indicators, None)
    declarations = parse_expected_connections(json.dumps({"schema_version": 1, "rules": [rule(**rule_changes)]}).encode())
    before = build_connection_report(result, expected_rules=declarations, evaluated_at=NOW, generated_at=NOW)
    rows = contextual_connection_rows(result, declarations, evaluated_at=NOW)
    assert rows[0]["Declared expected"] is expected
    assert rows[0]["Queue priority"] == "Review"
    assert phrase in " ".join(connection_steps(rows[0]))
    counts = review_counts(rows)
    assert counts["Original TCP reviews"] == 1
    assert counts["Declared expected reviews"] == int(expected)
    assert counts["Unexplained / CTI groups"] == int(not expected)
    assert counts["TCP CTI groups"] == int(cti)
    assert build_connection_report(result, expected_rules=declarations, evaluated_at=NOW, generated_at=NOW) == before
    for value in ("192.0.2.1", "198.51.100.1", "private-service-id", "private-uid"):
        assert value not in before + str(connection_steps(rows[0]))


def test_cti_only_observation_remains_actionable_and_counts_do_not_hide_conflict():
    rows = [dict({"Queue priority": "Observe", "Declared expected": True, "CTI match": True})]
    assert review_counts(rows) == {"Original TCP reviews": 0, "Declared expected reviews": 0,
                                  "Unexplained / CTI groups": 1, "TCP CTI groups": 1}
    assert "cannot clear this CTI" in " ".join(connection_steps(rows[0]))


def test_uploaded_expected_filter_summary_and_bilingual_guidance(monkeypatch):
    now = datetime.now(timezone.utc)
    payload = json.dumps({"schema_version": 1, "rules": [rule(now)]}).encode()
    monkeypatch.setattr(ui_connections.st, "file_uploader", lambda *a, **kw: SimpleNamespace(
        size=len(payload), getvalue=lambda: payload))
    program = (
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"result, _ = analyze_zeek_conn_log_with_diagnostics({telemetry(now)!r}, [], None)\n"
        "render_connections(result, public_mode=False)\n"
    )
    app = AppTest.from_string(program).run(timeout=15)
    assert not app.exception and not app.dataframe
    assert {m.label: m.value for m in app.metric}["Declared expected reviews"] == "1"
    app.checkbox(key="connection_show_expected").check().run(timeout=15)
    assert any("software identity is unverified" in item.value for item in app.info)
    assert any("unrelated process" in item.value for item in app.markdown)
    assert app.dataframe[0].value.iloc[0]["Queue priority"] == "Review"
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception
    assert any("farklı bir süreç" in item.value for item in app.markdown)
    assert any(m.label == "Asıl TCP incelemeleri" and m.value == "1" for m in app.metric)
    app.checkbox(key="connection_show_expected").uncheck().run(timeout=15)
    assert not app.exception and not app.dataframe


@pytest.mark.parametrize("cti", [False, True])
def test_selected_dns_task_shared_resolver_limits_without_timeline(cti):
    row = {"Group": 201, "Device": "Device 001", "Target": "shared.lab.test", "Evidence": "query observations",
           "Queue priority": "Review", "Known CTI sources": "synthetic" if cti else "",
           "Coverage limits": "Fewer than 20 distinct timestamps"}
    app = AppTest.from_string(
        "from threatfusion.ui_dns_timeline import render_dns_timeline\n"
        f"render_dns_timeline([{row!r}], {{'groups': []}}, key='task', revision='one')\n"
    ).run(timeout=15)
    assert not app.exception and not app.dataframe
    assert any("Do not attribute a shared resolver" in item.value for item in app.markdown)
    assert any("cannot be joined" in item.value for item in app.caption)
    assert any("indicator source" in item.value for item in app.markdown) is cti
    assert any("cached DNS" in item.value for item in app.markdown) is not cti
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    # Format labels must remain usable across a later widget rerun.
    app.run(timeout=15)
    assert not app.exception
    assert app.selectbox(key="task_dns_device").options == ["Cihaz 001"]
    assert any("tek tek cihazlara atfetme" in item.value for item in app.markdown)


def test_upload_identity_change_resets_same_numbered_group():
    program = (
        "import streamlit as st\nfrom datetime import datetime, timezone\n"
        "from threatfusion.connections import ConnectionRecord\n"
        "from threatfusion.runtime_analysis import analyze_dns_events\n"
        "from threatfusion.ui_connections import render_connections\n"
        "changed = st.checkbox('Replace input', key='replace_input')\n"
        "ip = '198.51.100.3' if changed else '198.51.100.1'\n"
        "rows = tuple(ConnectionRecord(str(i), datetime(2026, 10, 5, tzinfo=timezone.utc), '192.0.2.1', ip, 32000, i, 'tcp', 4000, 100, 200, 'SF', 0) for i in (443, 8443))\n"
        "render_connections(analyze_dns_events([], [], None, connections=rows), public_mode=True)\n"
    )
    app = AppTest.from_string(program).run(timeout=15)
    app.selectbox(key="connection_timeline_group").select(2).run(timeout=15)
    app.checkbox(key="replace_input").check().run(timeout=15)
    assert not app.exception and app.selectbox(key="connection_timeline_group").value == 1
    assert app.checkbox(key="connection_reviews_only").value
    assert any("Connection metadata does not identify" in item.value for item in app.markdown)


def test_collector_filters_keep_cti_and_do_not_translate_snapshot_in_place(monkeypatch):
    import copy
    from threatfusion import ui_collector
    row = {"Group": 201, "Originator": "Host 001", "Responder": "Host 002", "Queue priority": "Observe",
           "Declared expected": True, "CTI match": True, "Analyst context": "CTI conflict",
           "Context reason": "cti_overrides_declaration", "Evidence": "", "Coverage limits": ""}
    snapshot = {"findings": [row], "collector": {"updated_at": datetime.now(timezone.utc).isoformat(),
                "cti_indicators": 1, "counts": {"retained_records": 1, "review_groups": 0, "rejected_files": 0}}}
    before = copy.deepcopy(snapshot)
    monkeypatch.setattr(ui_collector, "read_snapshot", lambda root: snapshot)
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\n"
        "render_collector(Path('/private/state'), public_mode=False)\n"
    ).run(timeout=15)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["CTI match"]
    assert any("takes precedence" in item.value for item in app.warning)
    assert any(m.label == "Unexplained / CTI groups" and m.value == "1" for m in app.metric)
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception and snapshot == before
    assert any("önceliklidir" in item.value for item in app.warning)


@pytest.mark.parametrize("filename", ["development/rules.json", "reserved/scenario.pcap", "plan.json"])
@pytest.mark.skipif(not hasattr(os, "getuid"), reason="Private Unix lab directory")
def test_task_protocol_refuses_changed_inputs_before_scoring(tmp_path, filename):
    from scripts.lab.evaluate_analyst_tasks import prepare, evaluate
    root = tmp_path / "private-tasks"
    prepare(root)
    original = (root / filename).read_bytes()
    with pytest.raises(FileExistsError):
        prepare(root)
    assert (root / filename).read_bytes() == original
    (root / filename).write_bytes(original + b" ")
    with pytest.raises(ValueError, match="Frozen task input changed"):
        evaluate(root)
    assert not (root / "summary.json").exists()
