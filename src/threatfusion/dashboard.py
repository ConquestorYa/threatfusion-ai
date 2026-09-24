from __future__ import annotations

from dataclasses import dataclass

from .cti_cache import CTICacheStatus
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


def assessment_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for assessment in result.assessments:
        behavior = assessment.behavior
        rows.append(
            {
                "domain": assessment.domain,
                "verdict": assessment.verdict.value,
                "ml_score": assessment.ml_probability,
                "ml_tier": assessment.ml_tier,
                "events": behavior.event_count,
                "clients": behavior.unique_client_count,
                "response_ips": behavior.unique_response_ip_count,
                "query_types": ", ".join(behavior.query_types),
                "known_sources": ", ".join(assessment.known_ioc_sources),
                "reasons": ", ".join(assessment.reasons),
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            _VERDICT_ORDER.get(str(row["verdict"]), 99),
            str(row["domain"]),
        ),
    )


def match_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, str]]:
    return [
        {
            "query_name": match.event.query_name,
            "source": match.indicator.source,
            "match_type": match.match_type,
            "ioc_type": match.indicator.ioc_type.value,
        }
        for match in result.matches
    ]


def cti_status_rows(
    statuses: list[CTICacheStatus],
) -> list[dict[str, object]]:
    return [
        {
            "source": status.source,
            "records": status.record_count,
            "refreshed_at": status.refreshed_at,
        }
        for status in statuses
    ]


def history_rows(
    summaries: list[AnalysisRunSummary],
) -> list[dict[str, object]]:
    return [
        {
            "run_id": summary.id,
            "created_at": summary.created_at,
            "events": summary.event_count,
            "domains": summary.assessment_count,
            "matches": summary.match_count,
            "known_threat": summary.known_threat_count,
            "high_risk": summary.high_risk_count,
            "review": summary.review_count,
            "low": summary.low_count,
            "model": summary.model_name,
        }
        for summary in summaries
    ]


def persisted_assessment_rows(
    assessments: list[PersistedDomainAssessment],
) -> list[dict[str, object]]:
    rows = [
        {
            "domain": assessment.domain,
            "verdict": assessment.verdict,
            "ml_score": assessment.ml_probability,
            "ml_tier": assessment.ml_tier,
            "events": assessment.event_count,
            "clients": assessment.unique_client_count,
            "response_ips": assessment.unique_response_ip_count,
            "query_types": ", ".join(assessment.query_types),
            "known_sources": ", ".join(assessment.known_ioc_sources),
            "reasons": ", ".join(assessment.reasons),
        }
        for assessment in assessments
    ]

    return sorted(
        rows,
        key=lambda row: (
            _VERDICT_ORDER.get(str(row["verdict"]), 99),
            str(row["domain"]),
        ),
    )
