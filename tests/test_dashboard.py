from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from threatfusion.campaign import (
    DomainRelationship,
    RelatedActivityCluster,
    RelatedActivityReport,
)
from threatfusion.cti_cache import CTICacheStatus
from threatfusion.dashboard import (
    assessment_detail,
    assessment_rows,
    build_relationship_graph,
    cluster_rows,
    content_fingerprint,
    cti_status_rows,
    domain_match_rows,
    feedback_label,
    feedback_rows,
    format_timestamp,
    history_rows,
    ioc_corroboration_rows,
    match_evidence_scope,
    match_rows,
    ml_tier_label,
    persisted_assessment_rows,
    priority_assessment_rows,
    reason_label,
    relationship_penalty_label,
    relationship_reason_label,
    relationship_rows,
    relationship_strength_label,
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
    AnalystFeedback,
    PersistedDomainAssessment,
)
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def make_result() -> RuntimeAnalysisResult:
    event = DNSEvent(
        query_name="known.bad",
        client_ip="10.0.0.1",
        query_type="A",
    )
    indicator = IOCRecord(
        "known.bad",
        IOCType.DOMAIN,
        "ThreatFox",
        first_seen=datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc),
        threat_type="botnet_cc",
        confidence=0.9,
        tags=["c2", "malware"],
    )
    match = DNSIOCMatch(event, indicator, "query_domain")

    known = HybridAssessment(
        domain="known.bad",
        verdict=HybridVerdict.KNOWN_THREAT,
        known_ioc_sources=("ThreatFox",),
        known_match_types=("query_domain",),
        ml_score=0.2,
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
        ml_score=0.55,
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
        ml_scores={"known.bad": 0.2, "review.example": 0.55},
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
    assert reason_label("known_ioc_match") == "Exact known-domain IOC match"
    assert reason_label("rapid_query_burst") == "Rapid DNS query burst"
    assert reason_label("nxdomain_heavy_responses") == (
        "High NXDOMAIN ratio in DNS responses"
    )
    assert reason_label("periodic_query_pattern") == (
        "Periodic repeated query timing pattern"
    )
    assert ml_tier_label(None) == "Below threshold"
    assert ml_tier_label(None, scored=False) == "Not scored"
    assert match_evidence_scope("query_domain") == "Exact domain IOC"
    assert match_evidence_scope("url_hostname") == "URL hostname IOC"
    assert match_evidence_scope("response_ip") == "Response infrastructure IOC"
    assert (
        match_evidence_scope("response_ip_network")
        == "Response IPv6 network IOC"
    )
    assert (
        reason_label("response_ip_network_ioc_context")
        == "Response IPv6 address falls within a known threat network"
    )

def test_assessment_rows_are_friendly_and_severity_sorted() -> None:
    rows = assessment_rows(make_result())

    assert [row["Domain"] for row in rows] == ["known.bad", "review.example"]
    assert rows[0]["Verdict"] == "Known Threat"
    assert rows[0]["Known CTI sources"] == "ThreatFox"
    assert rows[0]["Evidence"] == "Exact known-domain IOC match"
    assert rows[1]["ML tier"] == "Low"
    assert rows[1]["Evidence"] == "Low ML score tier"



def test_unscored_assessment_is_not_presented_as_below_threshold() -> None:
    behavior = DomainBehavior(
        domain="printer.local",
        event_count=1,
        unique_client_count=1,
        unique_response_ip_count=0,
        query_types=("A",),
        first_seen=None,
        last_seen=None,
        observed_span_seconds=None,
    )
    assessment = HybridAssessment(
        domain="printer.local",
        verdict=HybridVerdict.LOW,
        known_ioc_sources=(),
        known_match_types=(),
        ml_score=None,
        ml_tier=None,
        behavior=behavior,
        behavior_signals=(),
        reasons=(),
    )
    result = RuntimeAnalysisResult(
        events=(DNSEvent(query_name="printer.local"),),
        matches=(),
        ml_scores={},
        assessments=(assessment,),
    )

    rows = assessment_rows(result)

    assert rows[0]["ML score"] is None
    assert rows[0]["ML tier"] == "Not scored"
    assert assessment_detail(assessment)["ml_tier"] == "Not scored"

def test_assessment_detail_explains_domain() -> None:
    assessment = next(
        item for item in make_result().assessments if item.domain == "known.bad"
    )

    detail = assessment_detail(assessment)

    assert detail["verdict"] == "Known Threat"
    assert detail["known_sources"] == ("ThreatFox",)
    assert detail["event_count"] == 1
    assert detail["label_count"] == 0
    assert detail["evidence"] == ("Exact known-domain IOC match",)

def test_match_rows_do_not_expose_indicator_value() -> None:
    rows = match_rows(make_result())

    assert rows == [
        {
            "Query name": "known.bad",
            "Source": "ThreatFox",
            "Match type": "Query Domain",
            "Evidence scope": "Exact domain IOC",
            "IOC type": "DOMAIN",
            "Threat type": "botnet_cc",
            "Confidence": 0.9,
            "First seen": "2026-09-20 10:00 UTC",
            "Last seen": "2026-09-24 12:00 UTC",
            "Tags": "c2, malware",
        }
    ]
    assert "value" not in rows[0]



def test_priority_rows_exclude_low_findings_and_keep_severity_order() -> None:
    result = make_result()

    rows = priority_assessment_rows(result)

    assert [row["Domain"] for row in rows] == [
        "known.bad",
        "review.example",
    ]
    assert all(row["Verdict"] != "Low" for row in rows)


def test_domain_match_rows_returns_only_selected_domain_evidence() -> None:
    result = make_result()

    rows = domain_match_rows(result, "KNOWN.BAD.")

    assert len(rows) == 1
    assert rows[0]["Evidence scope"] == "Exact domain IOC"
    assert rows[0]["Source"] == "ThreatFox"



def test_ioc_corroboration_rows_count_distinct_sources() -> None:
    result = make_result()
    known = next(
        item for item in result.assessments if item.domain == "known.bad"
    )
    corroborated = replace(
        known,
        known_ioc_sources=("SGB", "ThreatFox"),
        known_match_types=("query_domain", "url_hostname"),
    )
    result = replace(
        result,
        assessments=(
            corroborated,
            *(
                item
                for item in result.assessments
                if item.domain != "known.bad"
            ),
        ),
    )

    rows = ioc_corroboration_rows(result)

    assert rows[0] == {
        "Domain": "known.bad",
        "Source count": 2,
        "Sources": "SGB, ThreatFox",
        "Evidence scopes": "Exact domain IOC, URL hostname IOC",
        "Corroborated": "Yes",
    }

def test_cti_status_rows() -> None:
    rows = cti_status_rows(
        [
            CTICacheStatus(
                source="ThreatFox",
                refreshed_at="2026-09-24T18:00:00+00:00",
                record_count=123,
            )
        ],
        now=datetime(2026, 9, 24, 23, 0, tzinfo=timezone.utc),
    )

    assert rows[0]["Source"] == "ThreatFox"
    assert rows[0]["Records"] == 123
    assert rows[0]["Inactive history"] == 0
    assert rows[0]["Refreshed at"] == "2026-09-24 18:00 UTC"
    assert rows[0]["Age"] == "5.0 h"
    assert rows[0]["Stale after"] == "24.0 h"
    assert rows[0]["Status"] == "Fresh"


def test_cti_status_rows_marks_old_or_invalid_refresh_times() -> None:
    rows = cti_status_rows(
        [
            CTICacheStatus(
                source="ThreatFox",
                refreshed_at="2026-09-23T18:00:00+00:00",
                record_count=123,
            ),
            CTICacheStatus(
                source="SGB",
                refreshed_at="invalid",
                record_count=10,
            ),
        ],
        now=datetime(2026, 9, 25, 19, 0, tzinfo=timezone.utc),
    )

    assert rows[0]["Status"] == "Stale"
    assert rows[0]["Age"] == "49.0 h"
    assert rows[1]["Status"] == "Unknown"
    assert rows[1]["Age"] == "Unknown"

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
    assert rows[0]["Created at"] == "2026-09-24 18:00 UTC"
    assert rows[0]["Model"] == "model-a"
    assert rows[0]["Domains"] == 25

def test_persisted_assessment_rows_are_friendly_and_sorted() -> None:
    rows = persisted_assessment_rows(
        [
            PersistedDomainAssessment(
                domain="z.example",
                verdict="low",
                ml_score=0.1,
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
                ml_score=0.9,
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
    assert rows[1]["ML tier"] == "Below threshold"

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
            "shared_cti_source",
        ),
        strength=0.72,
        shared_cti_source_count=1,
        shared_cti_tag_count=2,
        shared_threat_type_count=1,
        penalties=("shared_response_ip_high_fanout",),
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
            "Max strength": 0.72,
        }
    ]
    assert relationships[0]["Strength"] == 0.72
    assert relationships[0]["Strength label"] == "Moderate"
    assert relationships[0]["Shared clients"] == 2
    assert relationships[0]["Shared response IPs"] == 1
    assert relationships[0]["Shared CTI sources"] == 1
    assert relationships[0]["Shared CTI tags"] == 2
    assert relationships[0]["Shared threat types"] == 1
    assert relationships[0]["Evidence"] == (
        "Shared client observation; Shared response IP observation; "
        "Observed close together in time; Shared CTI source context"
    )
    assert relationships[0]["Noise adjustment"] == (
        "Shared response IP appears across several suspicious domains"
    )
    assert "client_ip" not in relationships[0]
    assert relationship_reason_label("shared_client") == (
        "Shared client observation"
    )
    assert relationship_penalty_label(
        "shared_response_ip_high_fanout"
    ) == "Shared response IP appears across several suspicious domains"
    assert relationship_strength_label(0.80) == "Strong"
    assert relationship_strength_label(0.65) == "Moderate"
    assert relationship_strength_label(0.45) == "Limited"

def test_timestamp_formatting_and_upload_fingerprint_are_deterministic() -> None:
    assert format_timestamp("2026-09-24T21:30:45+03:00") == (
        "2026-09-24 18:30 UTC"
    )
    assert format_timestamp("not-a-timestamp") == "not-a-timestamp"

    first = content_fingerprint(b"same-content")
    second = content_fingerprint(b"same-content")
    different = content_fingerprint(b"different-content")

    assert first == second
    assert first != different



def test_relationship_graph_data_is_deterministic_and_privacy_preserving() -> None:
    relationship = DomainRelationship(
        domain_a="known.bad",
        domain_b="review.example",
        shared_client_count=2,
        shared_response_ip_count=1,
        min_time_delta_seconds=12.5,
        reasons=(
            "shared_client",
            "shared_response_ip",
            "time_proximity",
        ),
        strength=0.81,
    )
    report = RelatedActivityReport(
        clusters=(
            RelatedActivityCluster(
                cluster_id="group-1",
                domains=("known.bad", "review.example"),
                relationships=(relationship,),
            ),
        ),
        relationships=(relationship,),
    )

    first = build_relationship_graph(report, make_result())
    second = build_relationship_graph(report, make_result())

    assert first == second
    assert [node.domain for node in first.nodes] == [
        "known.bad",
        "review.example",
    ]
    assert first.nodes[0].verdict == "Known Threat"
    assert first.nodes[0].known_sources == ("ThreatFox",)
    assert first.nodes[1].verdict == "Review"
    assert len(first.edges) == 1
    edge = first.edges[0]
    assert edge.strength == 0.81
    assert "Strength: 0.81 (Strong)" in edge.hover_text
    assert "Shared clients: 2" in edge.hover_text
    assert "Shared response IPs: 1" in edge.hover_text
    assert "Closest time delta: 12.5 s" in edge.hover_text
    assert "10.0.0.1" not in edge.hover_text



def test_analyst_feedback_rows_are_human_readable() -> None:
    rows = feedback_rows(
        [
            AnalystFeedback(
                analysis_run_id=7,
                domain="review.example",
                label="confirmed_threat",
                note="Corroborated by analyst investigation",
                updated_at="2026-09-24T20:15:00+00:00",
            )
        ]
    )

    assert feedback_label(None) == "Not reviewed"
    assert feedback_label("benign") == "Benign"
    assert rows == [
        {
            "Domain": "review.example",
            "Analyst feedback": "Confirmed Threat",
            "Analyst note": "Corroborated by analyst investigation",
            "Updated at": "2026-09-24 20:15 UTC",
        }
    ]

def test_cti_status_rows_support_source_specific_freshness() -> None:
    rows = cti_status_rows(
        [
            CTICacheStatus(
                source="ThreatFox",
                refreshed_at="2026-09-25T10:00:00+00:00",
                record_count=100,
                inactive_record_count=7,
            ),
            CTICacheStatus(
                source="SGB",
                refreshed_at="2026-09-25T10:00:00+00:00",
                record_count=20,
                inactive_record_count=3,
            ),
        ],
        now=datetime(2026, 9, 25, 20, 0, tzinfo=timezone.utc),
        stale_after_by_source={
            "ThreatFox": timedelta(hours=6),
            "SGB": timedelta(hours=12),
        },
    )

    assert rows[0]["Source"] == "ThreatFox"
    assert rows[0]["Inactive history"] == 7
    assert rows[0]["Stale after"] == "6.0 h"
    assert rows[0]["Status"] == "Stale"
    assert rows[1]["Source"] == "SGB"
    assert rows[1]["Inactive history"] == 3
    assert rows[1]["Stale after"] == "12.0 h"
    assert rows[1]["Status"] == "Fresh"


def test_cti_status_rows_rejects_invalid_source_freshness() -> None:
    with pytest.raises(ValueError, match="source-specific"):
        cti_status_rows(
            [],
            stale_after_by_source={"ThreatFox": timedelta(0)},
        )

