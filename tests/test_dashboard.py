from __future__ import annotations

from datetime import datetime, timezone

from threatfusion.cti_cache import CTICacheStatus
from threatfusion.dashboard import (
    assessment_rows,
    cti_status_rows,
    history_rows,
    match_rows,
    persisted_assessment_rows,
    summarize_runtime_result,
)
from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import DomainBehavior
from threatfusion.hybrid_assessment import HybridAssessment, HybridVerdict
from threatfusion.matching import DNSIOCMatch
from threatfusion.models import IOCRecord, IOCType
from threatfusion.persistence import (
    AnalysisRunSummary,
    PersistedDomainAssessment,
)
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def make_result() -> RuntimeAnalysisResult:
    event = DNSEvent(
        query_name="known.bad",
        client_ip="10.0.0.1",
        query_type="A",
    )
    indicator = IOCRecord("known.bad", IOCType.DOMAIN, "ThreatFox")
    match = DNSIOCMatch(event, indicator, "query_domain")

    known = HybridAssessment(
        domain="known.bad",
        verdict=HybridVerdict.KNOWN_THREAT,
        known_ioc_sources=("ThreatFox",),
        known_match_types=("query_domain",),
        ml_probability=0.2,
        ml_tier=None,
        behavior=DomainBehavior(
            domain="known.bad",
            event_count=1,
            unique_client_count=1,
            unique_response_ip_count=0,
            query_types=("A",),
            first_seen=None,
            last_seen=None,
            observed_span_seconds=None,
        ),
        behavior_signals=(),
        reasons=("known_ioc_match",),
    )
    review = HybridAssessment(
        domain="review.example",
        verdict=HybridVerdict.REVIEW,
        known_ioc_sources=(),
        known_match_types=(),
        ml_probability=0.55,
        ml_tier="low",
        behavior=DomainBehavior(
            domain="review.example",
            event_count=2,
            unique_client_count=1,
            unique_response_ip_count=1,
            query_types=("AAAA",),
            first_seen=None,
            last_seen=None,
            observed_span_seconds=None,
        ),
        behavior_signals=(),
        reasons=("ml_low_confidence",),
    )

    return RuntimeAnalysisResult(
        events=(event,),
        matches=(match,),
        ml_probabilities={"known.bad": 0.2, "review.example": 0.55},
        assessments=(review, known),
    )


def test_runtime_summary_counts_verdicts() -> None:
    summary = summarize_runtime_result(make_result())

    assert summary.event_count == 1
    assert summary.domain_count == 2
    assert summary.match_count == 1
    assert summary.known_threat_count == 1
    assert summary.high_risk_count == 0
    assert summary.review_count == 1
    assert summary.low_count == 0


def test_assessment_rows_are_severity_then_domain_sorted() -> None:
    rows = assessment_rows(make_result())

    assert [row["domain"] for row in rows] == ["known.bad", "review.example"]
    assert rows[0]["known_sources"] == "ThreatFox"
    assert rows[1]["ml_tier"] == "low"


def test_match_rows_do_not_expose_indicator_value() -> None:
    rows = match_rows(make_result())

    assert rows == [
        {
            "query_name": "known.bad",
            "source": "ThreatFox",
            "match_type": "query_domain",
            "ioc_type": "domain",
        }
    ]
    assert "value" not in rows[0]


def test_cti_status_rows() -> None:
    rows = cti_status_rows(
        [
            CTICacheStatus(
                source="ThreatFox",
                refreshed_at="2026-09-24T18:00:00+00:00",
                record_count=123,
            )
        ]
    )

    assert rows[0]["source"] == "ThreatFox"
    assert rows[0]["records"] == 123


def test_history_rows() -> None:
    rows = history_rows(
        [
            AnalysisRunSummary(
                id=7,
                created_at="2026-09-24T18:00:00+00:00",
                event_count=100,
                match_count=3,
                assessment_count=25,
                known_threat_count=2,
                high_risk_count=4,
                review_count=6,
                low_count=13,
                model_name="model-a",
            )
        ]
    )

    assert rows[0]["run_id"] == 7
    assert rows[0]["model"] == "model-a"


def test_persisted_assessment_rows_are_sorted() -> None:
    rows = persisted_assessment_rows(
        [
            PersistedDomainAssessment(
                domain="z.example",
                verdict="low",
                ml_probability=0.1,
                ml_tier=None,
                event_count=1,
                unique_client_count=1,
                unique_response_ip_count=0,
                query_types=("A",),
                first_seen=None,
                last_seen=None,
                observed_span_seconds=None,
                known_ioc_sources=(),
                known_match_types=(),
                behavior_signals=(),
                reasons=(),
            ),
            PersistedDomainAssessment(
                domain="a.example",
                verdict="high_risk",
                ml_probability=0.9,
                ml_tier="high",
                event_count=1,
                unique_client_count=1,
                unique_response_ip_count=1,
                query_types=("A",),
                first_seen=datetime(
                    2026, 9, 24, 10, 0, tzinfo=timezone.utc
                ).isoformat(),
                last_seen=None,
                observed_span_seconds=None,
                known_ioc_sources=(),
                known_match_types=(),
                behavior_signals=(),
                reasons=("ml_high_confidence",),
            ),
        ]
    )

    assert [row["domain"] for row in rows] == ["a.example", "z.example"]
