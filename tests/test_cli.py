from __future__ import annotations

import json
from types import SimpleNamespace

from threatfusion import cli
from threatfusion.dns import DNSParseDiagnostics, DNSEvent
from threatfusion.hybrid_assessment import MLThresholds, assess_dns_domains
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def _result() -> RuntimeAnalysisResult:
    events = (DNSEvent(query_name="example.com"),)
    scores = {"example.com": 0.9}
    assessments = tuple(
        assess_dns_domains(
            events,
            (),
            ml_probabilities=scores,
            ml_thresholds=MLThresholds(0.8, 0.6, 0.5),
        )
    )
    return RuntimeAnalysisResult(
        events=events,
        matches=(),
        ml_probabilities=scores,
        assessments=assessments,
    )


def _diagnostics() -> DNSParseDiagnostics:
    return DNSParseDiagnostics(
        total_rows=1,
        accepted_rows=1,
        skipped_missing_query_name=0,
        invalid_timestamps=0,
        invalid_response_ips=0,
    )


def test_cli_writes_reports_for_dns_csv(tmp_path, monkeypatch, capsys) -> None:
    input_path = tmp_path / "dns.csv"
    input_path.write_text("query_name\nexample.com\n", encoding="utf-8")
    json_path = tmp_path / "out" / "report.json"
    csv_path = tmp_path / "out" / "findings.csv"
    artifact = SimpleNamespace(
        metadata=SimpleNamespace(model_name="test-model"),
    )

    monkeypatch.setattr(cli, "load_trusted_ml_artifact", lambda path: artifact)
    monkeypatch.setattr(cli, "load_ioc_records", lambda path: [])
    monkeypatch.setattr(
        cli,
        "analyze_dns_csv_with_diagnostics",
        lambda content, indicators, loaded_artifact: (
            _result(),
            _diagnostics(),
        ),
    )

    exit_code = cli.main(
        [
            str(input_path),
            "--format",
            "dns-csv",
            "--json-output",
            str(json_path),
            "--csv-output",
            str(csv_path),
        ]
    )

    assert exit_code == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["model_name"] == "test-model"
    assert payload["findings"][0]["verdict"] == "High Risk"
    assert "example.com" in csv_path.read_text(encoding="utf-8")
    output = capsys.readouterr().out
    assert "ThreatFusion analysis complete" in output
    assert "High Risk: 1" in output


def test_cli_selects_zeek_analyzer(tmp_path, monkeypatch) -> None:
    input_path = tmp_path / "dns.log"
    input_path.write_text("#fields\tquery\nexample.com\n", encoding="utf-8")
    artifact = SimpleNamespace(
        metadata=SimpleNamespace(model_name="test-model"),
    )
    calls: list[str] = []

    monkeypatch.setattr(cli, "load_trusted_ml_artifact", lambda path: artifact)
    monkeypatch.setattr(cli, "load_ioc_records", lambda path: [])

    def zeek_analyzer(content, indicators, loaded_artifact):
        calls.append(content)
        return _result(), _diagnostics()

    monkeypatch.setattr(cli, "analyze_zeek_dns_log_with_diagnostics", zeek_analyzer)

    assert cli.main([str(input_path), "--format", "zeek"]) == 0
    assert calls == ["#fields\tquery\nexample.com\n"]


def test_cli_reads_pihole_input_as_binary(tmp_path, monkeypatch) -> None:
    input_path = tmp_path / "pihole-FTL.db"
    input_path.write_bytes(b"sqlite-bytes")
    artifact = SimpleNamespace(
        metadata=SimpleNamespace(model_name="test-model"),
    )
    calls: list[bytes] = []

    monkeypatch.setattr(cli, "load_trusted_ml_artifact", lambda path: artifact)
    monkeypatch.setattr(cli, "load_ioc_records", lambda path: [])

    def pihole_analyzer(content, indicators, loaded_artifact):
        calls.append(content)
        return _result(), _diagnostics()

    monkeypatch.setattr(
        cli,
        "analyze_pihole_query_db_with_diagnostics",
        pihole_analyzer,
    )

    assert cli.main([str(input_path), "--format", "pihole"]) == 0
    assert calls == [b"sqlite-bytes"]
