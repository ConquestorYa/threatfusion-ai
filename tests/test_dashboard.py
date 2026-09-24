from __future__ import annotations

from datetime import datetime, timezone

from threatfusion.campaign import (
    DomainRelationship,
    RelatedActivityCluster,
    RelatedActivityReport,
)
from threatfusion.cti_cache import CTICacheStatus
from threatfusion.dashboard import (
    assessment_detail,
    assessment_rows,
    cluster_rows,
    cti_status_rows,
    history_rows,
    match_rows,
    persisted_assessment_rows,
    reason_label,
    relationship_reason_label,
    relationship_rows,
    summarize_runtime_result,
    verdict_label,
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

def test_runtime_summary_counts_verdicts_and_domains() -> None:
    summary = summarize_runtime_result(make_result())

    assert summary.event_count == 1
    assert summary.domain_count == 2
    assert summary.match_count == 1
    assert summary.known_threat_count == 1
    assert summary.high_risk_count == 0
    assert summary.review_count == 1
    assert summary.low_count == 0

def test_human_readable_verdict_and_reason_labels() -> None:
    assert verdict_label("known_threat") == "Known Threat"
    assert verdict_label("high_risk") == "High Risk"
    assert reason_label("known_ioc_match") == "Known threat intelligence match"
    assert reason_label("rapid_query_burst") == "Rapid DNS query burst"

def test_assessment_rows_are_friendly_and_severity_sorted() -> None:
    rows = assessment_rows(make_result())

    assert [row["Domain"] for row in rows] == ["known.bad", "review.example"]
    assert rows[0]["Verdict"] == "Known Threat"
    assert rows[0]["Known CTI sources"] == "ThreatFox"
    assert rows[0]["Evidence"] == "Known threat intelligence match"
    assert rows[1]["ML tier"] == "Low"
    assert rows[1]["Evidence"] == "Low ML score tier"

def test_assessment_detail_explains_domain() -> None:
    assessment = next(
        item for item in make_result().assessments if item.domain == "known.bad"
    )

    detail = assessment_detail(assessment)

    assert detail["verdict"] == "Known Threat"
    assert detail["known_sources"] == ("ThreatFox",)
    assert detail["event_count"] == 1
    assert detail["evidence"] == ("Known threat intelligence match",)

def test_match_rows_do_not_expose_indicator_value() -> None:
    rows = match_rows(make_result())

    assert rows == [
        {
            "Query name": "known.bad",
            "Source": "ThreatFox",
            "Match type": "Query Domain",
            "IOC type": "DOMAIN",
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

    assert rows[0]["Source"] == "ThreatFox"
    assert rows[0]["Records"] == 123

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

    assert rows[0]["Run ID"] == 7
    assert rows[0]["Model"] == "model-a"
    assert rows[0]["Domains"] == 25

def test_persisted_assessment_rows_are_friendly_and_sorted() -> None:
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

    assert [row["Domain"] for row in rows] == ["a.example", "z.example"]
    assert rows[0]["Verdict"] == "High Risk"
    assert rows[0]["Evidence"] == "High ML score tier"

def test_campaign_rows_are_human_readable_and_privacy_preserving() -> None:
    relationship = DomainRelationship(
        domain_a="a.example",
        domain_b="b.example",
        shared_client_count=2,
        shared_response_ip_count=1,
        min_time_delta_seconds=30.0,
        reasons=(
            "shared_client",
            "shared_response_ip",
            "time_proximity",
        ),
    )
    report = RelatedActivityReport(
        clusters=(
            RelatedActivityCluster(
                cluster_id="group-1",
                domains=("a.example", "b.example"),
                relationships=(relationship,),
            ),
        ),
        relationships=(relationship,),
    )

    groups = cluster_rows(report)
    relationships = relationship_rows(report)

    assert groups == [
        {
            "Group": "group-1",
            "Domains": "a.example, b.example",
            "Domain count": 2,
            "Relationships": 1,
        }
    ]
    assert relationships[0]["Shared clients"] == 2
    assert relationships[0]["Shared response IPs"] == 1
    assert relationships[0]["Evidence"] == (
        "Shared client observation; Shared response IP observation; "
        "Observed close together in time"
    )
    assert "client_ip" not in relationships[0]
    assert relationship_reason_label("shared_client") == (
        "Shared client observation"
    )
