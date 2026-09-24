from __future__ import annotations

from dataclasses import dataclass

from .campaign import RelatedActivityReport
from .cti_cache import CTICacheStatus
from .hybrid_assessment import HybridAssessment
from .persistence import AnalysisRunSummary, PersistedDomainAssessment
from .runtime_analysis import RuntimeAnalysisResult


@dataclass(frozen=True)
class DashboardSummary:
    event_count: int
    domain_count: int
    match_count: int
    known_threat_count: int
    high_risk_count: int
    review_count: int
    low_count: int


_VERDICT_ORDER = {
    "known_threat": 0,
    "high_risk": 1,
    "review": 2,
    "low": 3,
}

_VERDICT_LABELS = {
    "known_threat": "Known Threat",
    "high_risk": "High Risk",
    "review": "Review",
    "low": "Low",
}

_ML_TIER_LABELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

_RELATION_REASON_LABELS = {
    "shared_client": "Shared client observation",
    "shared_response_ip": "Shared response IP observation",
    "time_proximity": "Observed close together in time",
}

_REASON_LABELS = {
    "known_ioc_match": "Known threat intelligence match",
    "ml_high_confidence": "High ML score tier",
    "ml_medium_confidence": "Medium ML score tier",
    "ml_low_confidence": "Low ML score tier",
    "high_query_volume": "High DNS query volume",
    "multi_client_observation": "Observed from multiple clients",
    "response_ip_churn": "Multiple response IPs observed",
    "query_type_diversity": "Multiple DNS query types observed",
    "rapid_query_burst": "Rapid DNS query burst",
}



def relationship_reason_label(value: str) -> str:
    return _RELATION_REASON_LABELS.get(
        value,
        value.replace("_", " ").title(),
    )


def cluster_rows(
    report: RelatedActivityReport,
) -> list[dict[str, object]]:
    return [
        {
            "Group": cluster.cluster_id,
            "Domains": ", ".join(cluster.domains),
            "Domain count": len(cluster.domains),
            "Relationships": len(cluster.relationships),
        }
        for cluster in report.clusters
    ]


def relationship_rows(
    report: RelatedActivityReport,
) -> list[dict[str, object]]:
    return [
        {
            "Domain A": relationship.domain_a,
            "Domain B": relationship.domain_b,
            "Shared clients": relationship.shared_client_count,
            "Shared response IPs": relationship.shared_response_ip_count,
            "Closest time delta (s)": relationship.min_time_delta_seconds,
            "Evidence": "; ".join(
                relationship_reason_label(reason)
                for reason in relationship.reasons
            ),
        }
        for relationship in report.relationships
    ]


def verdict_label(value: str) -> str:
    return _VERDICT_LABELS.get(value, value.replace("_", " ").title())


def reason_label(value: str) -> str:
    return _REASON_LABELS.get(value, value.replace("_", " ").title())


def ml_tier_label(value: str | None) -> str:
    if value is None:
        return "None"
    return _ML_TIER_LABELS.get(value, value.title())


def summarize_runtime_result(
    result: RuntimeAnalysisResult,
) -> DashboardSummary:
    counts = {
        "known_threat": 0,
        "high_risk": 0,
        "review": 0,
        "low": 0,
    }
    for assessment in result.assessments:
        counts[assessment.verdict.value] += 1

    return DashboardSummary(
        event_count=len(result.events),
        domain_count=len(result.assessments),
        match_count=len(result.matches),
        known_threat_count=counts["known_threat"],
        high_risk_count=counts["high_risk"],
        review_count=counts["review"],
        low_count=counts["low"],
    )


def _evidence_text(reasons: tuple[str, ...]) -> str:
    return "; ".join(reason_label(reason) for reason in reasons)


def assessment_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, object]]:
    rows: list[tuple[int, str, dict[str, object]]] = []

    for assessment in result.assessments:
        behavior = assessment.behavior
        row = {
            "Domain": assessment.domain,
            "Verdict": verdict_label(assessment.verdict.value),
            "ML score": assessment.ml_probability,
            "ML tier": ml_tier_label(assessment.ml_tier),
            "DNS events": behavior.event_count,
            "Clients": behavior.unique_client_count,
            "Response IPs": behavior.unique_response_ip_count,
            "Query types": ", ".join(behavior.query_types),
            "Known CTI sources": ", ".join(assessment.known_ioc_sources),
            "Evidence": _evidence_text(assessment.reasons),
        }
        rows.append(
            (
                _VERDICT_ORDER.get(assessment.verdict.value, 99),
                assessment.domain,
                row,
            )
        )

    return [
        row
        for _, _, row in sorted(
            rows,
            key=lambda item: (item[0], item[1]),
        )
    ]


def assessment_detail(
    assessment: HybridAssessment,
) -> dict[str, object]:
    behavior = assessment.behavior
    return {
        "domain": assessment.domain,
        "verdict": verdict_label(assessment.verdict.value),
        "ml_score": assessment.ml_probability,
        "ml_tier": ml_tier_label(assessment.ml_tier),
        "known_sources": assessment.known_ioc_sources,
        "known_match_types": assessment.known_match_types,
        "event_count": behavior.event_count,
        "client_count": behavior.unique_client_count,
        "response_ip_count": behavior.unique_response_ip_count,
        "query_types": behavior.query_types,
        "evidence": tuple(reason_label(reason) for reason in assessment.reasons),
    }


def match_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, str]]:
    return [
        {
            "Query name": match.event.query_name,
            "Source": match.indicator.source,
            "Match type": match.match_type.replace("_", " ").title(),
            "IOC type": match.indicator.ioc_type.value.upper(),
        }
        for match in result.matches
    ]


def cti_status_rows(
    statuses: list[CTICacheStatus],
) -> list[dict[str, object]]:
    return [
        {
            "Source": status.source,
            "Records": status.record_count,
            "Refreshed at": status.refreshed_at,
        }
        for status in statuses
    ]


def history_rows(
    summaries: list[AnalysisRunSummary],
) -> list[dict[str, object]]:
    return [
        {
            "Run ID": summary.id,
            "Created at": summary.created_at,
            "DNS events": summary.event_count,
            "Domains": summary.assessment_count,
            "Matches": summary.match_count,
            "Known Threat": summary.known_threat_count,
            "High Risk": summary.high_risk_count,
            "Review": summary.review_count,
            "Low": summary.low_count,
            "Model": summary.model_name,
        }
        for summary in summaries
    ]


def persisted_assessment_rows(
    assessments: list[PersistedDomainAssessment],
) -> list[dict[str, object]]:
    rows: list[tuple[int, str, dict[str, object]]] = []

    for assessment in assessments:
        row = {
            "Domain": assessment.domain,
            "Verdict": verdict_label(assessment.verdict),
            "ML score": assessment.ml_probability,
            "ML tier": ml_tier_label(assessment.ml_tier),
            "DNS events": assessment.event_count,
            "Clients": assessment.unique_client_count,
            "Response IPs": assessment.unique_response_ip_count,
            "Query types": ", ".join(assessment.query_types),
            "Known CTI sources": ", ".join(assessment.known_ioc_sources),
            "Evidence": _evidence_text(assessment.reasons),
        }
        rows.append(
            (
                _VERDICT_ORDER.get(assessment.verdict, 99),
                assessment.domain,
                row,
            )
        )

    return [
        row
        for _, _, row in sorted(
            rows,
            key=lambda item: (item[0], item[1]),
        )
    ]
