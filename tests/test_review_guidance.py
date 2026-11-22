"""Analyst task contracts, not a human usability or detection benchmark."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest
from threatfusion.dashboard import contextual_connection_rows
from threatfusion.expected_connections import parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
from threatfusion.collector_reports import review_counts
from threatfusion.ui_review_guidance import connection_steps

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
