"""IP-target telemetry remains useful without exposing addresses in exports."""

import csv
import io
import json
import sqlite3

import pytest

from threatfusion.hybrid_assessment import assess_dns_domains
from threatfusion.matching import match_dns_events
from threatfusion.models import IOCRecord, IOCType
from threatfusion.network_telemetry import (
    parse_suricata_eve_with_diagnostics,
    parse_zeek_conn_log_with_diagnostics,
)
from threatfusion.persistence import (
    get_analysis_assessments,
    initialize_database,
    save_runtime_analysis,
)
from threatfusion.reporting import build_analysis_report
from threatfusion.runtime_analysis import RuntimeAnalysisResult


@pytest.mark.parametrize(
    "content,parser",
    [
        (
            "#separator \\x09\n#path\tconn\n"
            "#fields\tts\tid.orig_h\tid.resp_h\n"
            "1700000000\t10.0.0.1\t10.20.30.40\n",
            parse_zeek_conn_log_with_diagnostics,
        ),
        (
            '{"event_type":"alert","src_ip":"10.0.0.1",'
            '"dest_ip":"10.20.30.40"}\n',
            parse_suricata_eve_with_diagnostics,
        ),
    ],
)
def test_ip_target_export_and_history_redact_address(
    tmp_path, content, parser
) -> None:
    events = parser(content).events
    indicators = [IOCRecord("10.20.30.40", IOCType.IPV4, "fixture")]
    matches = tuple(match_dns_events(events, indicators))
    assessments = tuple(assess_dns_domains(events, matches))
    result = RuntimeAnalysisResult(events, matches, {}, assessments)

    report = build_analysis_report(result, model_name="fixture")
    payload = json.loads(report.json_text)
    csv_row = next(csv.DictReader(io.StringIO(report.csv_text)))

    assert payload["findings"][0]["target_type"] == "ip"
    assert payload["findings"][0]["domain"] is None
    assert payload["summary"]["unique_domains"] == 0
    assert payload["summary"]["ip_targets"] == 1
    assert payload["privacy"]["target_ip_values_included"] is False
    assert csv_row["target_type"] == "ip"
    assert csv_row["domain"] == ""
    assert "10.20.30.40" not in report.json_text + report.csv_text
    assert "10.0.0.1" not in report.json_text + report.csv_text

    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, result)
    persisted = get_analysis_assessments(db_path, run_id)
    assert len(persisted) == 1
    assert persisted[0].target_type == "ip"
    assert persisted[0].domain.startswith("IP target ")
    assert persisted[0].known_match_types == ("response_ip",)
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT target_type FROM analysis_assessments"
        ).fetchone() == ("ip",)
    assert b"10.20.30.40" not in db_path.read_bytes()
    assert b"10.0.0.1" not in db_path.read_bytes()


def test_existing_history_ip_target_rows_are_redacted_on_schema_upgrade(
    tmp_path,
) -> None:
    db_path = tmp_path / "legacy.sqlite"
    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "ALTER TABLE analysis_assessments DROP COLUMN target_type"
        )
        connection.execute(
            """INSERT INTO analysis_assessments (
                analysis_run_id, domain, verdict, event_count,
                unique_client_count, unique_response_ip_count,
                query_types_json, known_ioc_sources_json,
                known_match_types_json, behavior_signals_json, reasons_json
            ) VALUES (1, '10.20.30.40', 'review', 1, 1, 1,
                      '[]', '[]', '[]', '[]', '[]')"""
        )
        connection.execute(
            "INSERT INTO analyst_feedback "
            "(analysis_run_id, domain, label, updated_at) "
            "VALUES (1, '10.20.30.40', 'uncertain', '2026-09-28')"
        )

    initialize_database(db_path)
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT domain, target_type FROM analysis_assessments"
        ).fetchone() == ("IP target 1", "ip")
        assert connection.execute(
            "SELECT domain FROM analyst_feedback"
        ).fetchone() == ("IP target 1",)
