from __future__ import annotations

import csv
import io
import json
import socket
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import DomainBehavior
from threatfusion.hybrid_assessment import HybridAssessment, HybridVerdict
from threatfusion.matching import DNSIOCMatch
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_analysis_report
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def make_result() -> RuntimeAnalysisResult:
    event = DNSEvent(
        query_name="known.example",
        client_ip="10.0.0.55",
        query_type="A",
        response_ip="203.0.113.55",
    )
    indicator = IOCRecord(
        "known.example",
        IOCType.DOMAIN,
        "ThreatFox",
    )
    match = DNSIOCMatch(
        event=event,
        indicator=indicator,
        match_type="query_domain",
    )
    assessment = HybridAssessment(
        domain="known.example",
        verdict=HybridVerdict.KNOWN_THREAT,
        known_ioc_sources=("ThreatFox",),
        known_match_types=("query_domain",),
        ml_score=0.52,
        ml_tier="low",
        behavior=DomainBehavior(
            domain="known.example",
            event_count=1,
            unique_client_count=1,
            unique_response_ip_count=1,
            query_types=("A",),
            first_seen=None,
            last_seen=None,
            observed_span_seconds=None,
        ),
        behavior_signals=(),
        reasons=("known_ioc_match", "ml_low_confidence"),
    )
    return RuntimeAnalysisResult(
        events=(event,),
        matches=(match,),
        ml_scores={"known.example": 0.52},
        assessments=(assessment,),
    )


def test_json_report_contains_summary_and_aggregate_findings() -> None:
    generated_at = datetime(
        2026,
        9,
        25,
        12,
        0,
        tzinfo=timezone.utc,
    )

    report = build_analysis_report(
        make_result(),
        model_name="development-model",
        generated_at=generated_at,
    )
    payload = json.loads(report.json_text)

    assert payload["generated_at"] == generated_at.isoformat()
    assert payload["model_name"] == "development-model"
    assert payload["summary"] == {
        "dns_events": 1,
        "unique_domains": 1,
        "ip_targets": 0,
        "known_ioc_matches": 1,
        "known_threat": 1,
        "high_risk": 0,
        "review": 0,
        "low": 0,
    }
    assert payload["findings"][0]["domain"] == "known.example"
    assert payload["findings"][0]["verdict"] == "Known Threat"
    assert payload["findings"][0]["unique_clients"] == 1
    assert payload["findings"][0]["unique_response_ips"] == 1
    assert payload["findings"][0]["known_cti_sources"] == ["ThreatFox"]
    assert payload["findings"][0]["evidence"] == [
        "Exact known-domain IOC match",
        "Low ML score tier",
    ]


def test_reports_do_not_include_raw_client_or_response_ip_values() -> None:
    report = build_analysis_report(
        make_result(),
        model_name="development-model",
        generated_at=datetime(
            2026,
            9,
            25,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    combined = report.json_text + report.csv_text

    assert "10.0.0.55" not in combined
    assert "203.0.113.55" not in combined
    assert '"client_ip_values_included": false' in report.json_text
    assert '"response_ip_values_included": false' in report.json_text


def test_csv_report_is_portable_and_human_readable() -> None:
    report = build_analysis_report(
        make_result(),
        model_name="development-model",
        generated_at=datetime(
            2026,
            9,
            25,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )
    rows = list(csv.DictReader(io.StringIO(report.csv_text)))

    assert len(rows) == 1
    assert rows[0]["domain"] == "known.example"
    assert rows[0]["verdict"] == "Known Threat"
    assert rows[0]["ml_tier"] == "Low"
    assert rows[0]["query_types"] == "A"
    assert rows[0]["known_cti_sources"] == "ThreatFox"
    assert rows[0]["evidence"] == (
        "Exact known-domain IOC match; Low ML score tier"
    )




def test_report_marks_unscored_domain_distinctly() -> None:
    result = make_result()
    assessment = replace(
        result.assessments[0],
        ml_score=None,
        ml_tier=None,
        reasons=("known_ioc_match",),
    )
    report = build_analysis_report(
        replace(
            result,
            ml_scores={},
            assessments=(assessment,),
        ),
        model_name="development-model",
    )

    payload = json.loads(report.json_text)
    rows = list(csv.DictReader(io.StringIO(report.csv_text)))

    assert payload["findings"][0]["ml_score"] is None
    assert payload["findings"][0]["ml_tier"] == "Not scored"
    assert rows[0]["ml_tier"] == "Not scored"

def test_csv_report_escapes_spreadsheet_formula_prefixes() -> None:
    result = make_result()
    assessment = replace(
        result.assessments[0],
        domain="=2+2.example",
        behavior=replace(
            result.assessments[0].behavior,
            domain="=2+2.example",
        ),
    )
    report = build_analysis_report(
        replace(result, assessments=(assessment,)),
        model_name="development-model",
    )
    rows = list(csv.DictReader(io.StringIO(report.csv_text)))

    assert rows[0]["domain"] == "'=2+2.example"
    payload = json.loads(report.json_text)
    assert payload["findings"][0]["domain"] == "=2+2.example"

def test_naive_generated_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        build_analysis_report(
            make_result(),
            model_name="development-model",
            generated_at=datetime(
                2026,
                9,
                25,
                12,
                0,
                tzinfo=timezone.utc,
            ).replace(tzinfo=None),
        )


def test_empty_model_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="model_name"):
        build_analysis_report(
            make_result(),
            model_name=" ",
        )


def test_report_generation_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("report generation must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    report = build_analysis_report(
        make_result(),
        model_name="development-model",
    )

    assert report.json_text
    assert report.csv_text
