from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import datetime, timezone

from .campaign import RelatedActivityReport
from .cti_cache import CTICacheStatus
from .hybrid_assessment import HybridAssessment
from .ml_scoring import evaluate_ml_scoring_eligibility
from .persistence import (
    AnalysisRunSummary,
    AnalystFeedback,
    PersistedDomainAssessment,
)
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


@dataclass(frozen=True)
class RelationshipGraphNode:
    domain: str
    cluster_id: str
    verdict: str
    ml_tier: str
    known_sources: tuple[str, ...]
    x: float
    y: float


@dataclass(frozen=True)
class RelationshipGraphEdge:
    domain_a: str
    domain_b: str
    x0: float
    y0: float
    x1: float
    y1: float
    hover_text: str


@dataclass(frozen=True)
class RelationshipGraphData:
    nodes: tuple[RelationshipGraphNode, ...]
    edges: tuple[RelationshipGraphEdge, ...]


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

_ML_SKIP_REASON_LABELS = {
    "invalid_domain": "The query is not a valid domain candidate.",
    "single_label": "Single-label/local host names are outside the ML model scope.",
    "non_public_suffix": "Local, reverse-DNS, or internal namespaces are outside the ML model scope.",
    "service_discovery": "Service-discovery names are outside the ML model scope.",
    "invalid_public_domain": "The query does not have valid public-domain syntax.",
}

_DEFAULT_CTI_STALE_AFTER_HOURS = 24.0

_FEEDBACK_LABELS = {
    "confirmed_threat": "Confirmed Threat",
    "benign": "Benign",
    "uncertain": "Uncertain",
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


def build_relationship_graph(
    report: RelatedActivityReport,
    result: RuntimeAnalysisResult,
) -> RelationshipGraphData:
    """Build deterministic, privacy-preserving graph presentation data."""
    assessment_by_domain = {
        assessment.domain: assessment
        for assessment in result.assessments
    }
    positions: dict[str, tuple[float, float]] = {}
    nodes: list[RelationshipGraphNode] = []

    for cluster_index, cluster in enumerate(report.clusters):
        domain_count = len(cluster.domains)
        radius = max(1.0, domain_count * 0.35)
        center_x = cluster_index * 3.5

        for domain_index, domain in enumerate(cluster.domains):
            angle = (2.0 * math.pi * domain_index) / domain_count
            x = center_x + radius * math.cos(angle)
            y = radius * math.sin(angle)
            positions[domain] = (x, y)

            assessment = assessment_by_domain.get(domain)
            if assessment is None:
                verdict = "Unknown"
                tier = "Below threshold"
                sources: tuple[str, ...] = ()
            else:
                verdict = verdict_label(assessment.verdict.value)
                tier = ml_status_label(
                    assessment.domain,
                    assessment.ml_probability,
                    assessment.ml_tier,
                )
                sources = assessment.known_ioc_sources

            nodes.append(
                RelationshipGraphNode(
                    domain=domain,
                    cluster_id=cluster.cluster_id,
                    verdict=verdict,
                    ml_tier=tier,
                    known_sources=sources,
                    x=x,
                    y=y,
                )
            )

    edges: list[RelationshipGraphEdge] = []
    for relationship in report.relationships:
        left = positions.get(relationship.domain_a)
        right = positions.get(relationship.domain_b)
        if left is None or right is None:
            continue

        time_text = (
            f"{relationship.min_time_delta_seconds:.1f} s"
            if relationship.min_time_delta_seconds is not None
            else "not comparable"
        )
        evidence = "; ".join(
            relationship_reason_label(reason)
            for reason in relationship.reasons
        )
        hover_text = (
            f"{relationship.domain_a} ↔ {relationship.domain_b}<br>"
            f"Shared clients: {relationship.shared_client_count}<br>"
            f"Shared response IPs: {relationship.shared_response_ip_count}<br>"
            f"Closest time delta: {time_text}<br>"
            f"Evidence: {evidence}"
        )
        edges.append(
            RelationshipGraphEdge(
                domain_a=relationship.domain_a,
                domain_b=relationship.domain_b,
                x0=left[0],
                y0=left[1],
                x1=right[0],
                y1=right[1],
                hover_text=hover_text,
            )
        )

    return RelationshipGraphData(
        nodes=tuple(nodes),
        edges=tuple(edges),
    )


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
        return "Below threshold"
    return _ML_TIER_LABELS.get(value, value.title())


def ml_status_label(
    domain: str,
    probability: float | None,
    tier: str | None,
) -> str:
    if probability is not None:
        return ml_tier_label(tier)

    eligibility = evaluate_ml_scoring_eligibility(domain)
    if not eligibility.eligible:
        return "Not scored"
    return "Unavailable"


def ml_status_note(
    domain: str,
    probability: float | None,
) -> str | None:
    if probability is not None:
        return None

    eligibility = evaluate_ml_scoring_eligibility(domain)
    if eligibility.eligible:
        return "ML score is unavailable for this domain."

    return _ML_SKIP_REASON_LABELS.get(
        eligibility.reason or "",
        "This query is outside the ML model scope.",
    )


def feedback_label(value: str | None) -> str:
    if value is None:
        return "Not reviewed"
    return _FEEDBACK_LABELS.get(value, value.replace("_", " ").title())


def feedback_rows(
    feedback: list[AnalystFeedback],
) -> list[dict[str, object]]:
    return [
        {
            "Domain": item.domain,
            "Analyst feedback": feedback_label(item.label),
            "Analyst note": item.note or "",
            "Updated at": format_timestamp(item.updated_at),
        }
        for item in feedback
    ]


def content_fingerprint(content: bytes) -> str:
    """Return a stable fingerprint for uploaded content."""
    return hashlib.sha256(content).hexdigest()


def format_timestamp(value: str) -> str:
    """Format stored ISO timestamps for compact dashboard display."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return value

    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M UTC")

    return parsed.strftime("%Y-%m-%d %H:%M")

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
            "ML tier": ml_status_label(
                assessment.domain,
                assessment.ml_probability,
                assessment.ml_tier,
            ),
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
        "ml_tier": ml_status_label(
            assessment.domain,
            assessment.ml_probability,
            assessment.ml_tier,
        ),
        "ml_note": ml_status_note(
            assessment.domain,
            assessment.ml_probability,
        ),
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

def _age_text(age_hours: float) -> str:
    if age_hours < 48:
        return f"{age_hours:.1f} h"
    return f"{age_hours / 24:.1f} d"


def cti_status_rows(
    statuses: list[CTICacheStatus],
    *,
    now: datetime | None = None,
    stale_after_hours: float = _DEFAULT_CTI_STALE_AFTER_HOURS,
) -> list[dict[str, object]]:
    if stale_after_hours <= 0:
        raise ValueError("stale_after_hours must be positive")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)

    rows: list[dict[str, object]] = []
    for status in statuses:
        age_hours: float | None = None
        freshness = "Unknown"
        try:
            refreshed = datetime.fromisoformat(
                status.refreshed_at.replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            refreshed = None

        if (
            refreshed is not None
            and refreshed.tzinfo is not None
            and refreshed.utcoffset() is not None
        ):
            age_hours = max(
                0.0,
                (current - refreshed.astimezone(timezone.utc)).total_seconds()
                / 3600,
            )
            freshness = (
                "Stale"
                if age_hours > stale_after_hours
                else "Fresh"
            )

        rows.append(
            {
                "Source": status.source,
                "Records": status.record_count,
                "Refreshed at": format_timestamp(status.refreshed_at),
                "Age": _age_text(age_hours) if age_hours is not None else "Unknown",
                "Status": freshness,
            }
        )
    return rows

def history_rows(
    summaries: list[AnalysisRunSummary],
) -> list[dict[str, object]]:
    return [
        {
            "Run ID": summary.id,
            "Created at": format_timestamp(summary.created_at),
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
            "ML tier": ml_status_label(
                assessment.domain,
                assessment.ml_probability,
                assessment.ml_tier,
            ),
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
