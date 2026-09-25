from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .campaign import RelatedActivityReport
from .cti_cache import CTICacheStatus
from .hybrid_assessment import HybridAssessment
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

_FEEDBACK_LABELS = {
    "confirmed_threat": "Confirmed Threat",
    "benign": "Benign",
    "uncertain": "Uncertain",
}

_MATCH_EVIDENCE_SCOPE_LABELS = {
    "query_domain": "Exact domain IOC",
    "url_hostname": "URL hostname IOC",
    "response_ip": "Response infrastructure IOC",
    "response_ip_network": "Response IPv6 network IOC",
}

_RELATION_REASON_LABELS = {
    "shared_client": "Shared client observation",
    "shared_response_ip": "Shared response IP observation",
    "time_proximity": "Observed close together in time",
}

_REASON_LABELS = {
    "known_ioc_match": "Exact known-domain IOC match",
    "url_hostname_ioc_context": "Hostname appears in a malicious URL IOC",
    "response_ip_ioc_context": "Response IP matches known threat infrastructure",
    "response_ip_network_ioc_context": (
        "Response IPv6 address falls within a known threat network"
    ),
    "ml_high_confidence": "High ML score tier",
    "ml_medium_confidence": "Medium ML score tier",
    "ml_low_confidence": "Low ML score tier",
    "high_query_volume": "High DNS query volume",
    "multi_client_observation": "Observed from multiple clients",
    "response_ip_churn": "Multiple response IPs observed",
    "query_type_diversity": "Multiple DNS query types observed",
    "rapid_query_burst": "Rapid DNS query burst",
    "nxdomain_heavy_responses": "High NXDOMAIN ratio in DNS responses",
    "high_response_ip_churn_rate": "High response-IP churn rate",
    "numeric_heavy_hostname": "Hostname contains many numeric characters",
    "random_like_hostname": "Hostname appears algorithmically random",
    "periodic_query_pattern": "Periodic repeated query timing pattern",
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
                tier = ml_tier_label(
                    assessment.ml_tier,
                    scored=assessment.ml_probability is not None,
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

def ml_tier_label(
    value: str | None,
    *,
    scored: bool = True,
) -> str:
    if not scored:
        return "Not scored"
    if value is None:
        return "Below threshold"
    return _ML_TIER_LABELS.get(value, value.title())


def match_evidence_scope(match_type: str) -> str:
    return _MATCH_EVIDENCE_SCOPE_LABELS.get(
        match_type,
        match_type.replace("_", " ").title(),
    )


def _ioc_datetime_label(value: datetime | None) -> str:
    if value is None:
        return ""
    return format_timestamp(value.isoformat())


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
            "ML tier": ml_tier_label(
                assessment.ml_tier,
                scored=assessment.ml_probability is not None,
            ),
            "DNS events": behavior.event_count,
            "Clients": behavior.unique_client_count,
            "Response IPs": behavior.unique_response_ip_count,
            "Response-IP churn rate": behavior.response_ip_churn_rate,
            "Query types": ", ".join(behavior.query_types),
            "Response codes": ", ".join(
                f"{code}:{count}" for code, count in behavior.response_code_counts
            ),
            "NXDOMAIN ratio": behavior.nxdomain_ratio,
            "Label count": behavior.label_count,
            "Subdomain depth": behavior.subdomain_depth,
            "Numeric ratio": behavior.numeric_character_ratio,
            "Hostname entropy": behavior.hostname_entropy,
            "Random-like hostname": behavior.random_like_hostname,
            "Periodic interval (s)": behavior.periodic_interval_seconds,
            "Periodicity score": behavior.periodicity_score,
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

def priority_assessment_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, object]]:
    """Return non-low findings in analyst triage order."""
    return [
        row
        for row in assessment_rows(result)
        if row["Verdict"] != "Low"
    ]


def domain_match_rows(
    result: RuntimeAnalysisResult,
    domain: str,
) -> list[dict[str, object]]:
    """Return IOC evidence rows associated with one normalized query domain."""
    normalized = domain.strip().casefold().removesuffix(".")
    return [
        row
        for match, row in zip(result.matches, match_rows(result), strict=True)
        if match.event.query_name.strip().casefold().removesuffix(".")
        == normalized
    ]


def assessment_detail(
    assessment: HybridAssessment,
) -> dict[str, object]:
    behavior = assessment.behavior
    return {
        "domain": assessment.domain,
        "verdict": verdict_label(assessment.verdict.value),
        "ml_score": assessment.ml_probability,
        "ml_tier": ml_tier_label(
            assessment.ml_tier,
            scored=assessment.ml_probability is not None,
        ),
        "known_sources": assessment.known_ioc_sources,
        "known_match_types": assessment.known_match_types,
        "event_count": behavior.event_count,
        "client_count": behavior.unique_client_count,
        "response_ip_count": behavior.unique_response_ip_count,
        "response_ip_churn_rate": behavior.response_ip_churn_rate,
        "query_types": behavior.query_types,
        "response_code_counts": behavior.response_code_counts,
        "nxdomain_ratio": behavior.nxdomain_ratio,
        "label_count": behavior.label_count,
        "subdomain_depth": behavior.subdomain_depth,
        "numeric_character_ratio": behavior.numeric_character_ratio,
        "hostname_entropy": behavior.hostname_entropy,
        "random_like_hostname": behavior.random_like_hostname,
        "periodic_interval_seconds": behavior.periodic_interval_seconds,
        "periodicity_score": behavior.periodicity_score,
        "periodic_query_pattern": behavior.periodic_query_pattern,
        "evidence": tuple(reason_label(reason) for reason in assessment.reasons),
    }

def match_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, object]]:
    return [
        {
            "Query name": match.event.query_name,
            "Source": match.indicator.source,
            "Match type": match.match_type.replace("_", " ").title(),
            "Evidence scope": match_evidence_scope(match.match_type),
            "IOC type": match.indicator.ioc_type.value.upper(),
            "Threat type": match.indicator.threat_type or "",
            "Confidence": match.indicator.confidence,
            "First seen": _ioc_datetime_label(match.indicator.first_seen),
            "Last seen": _ioc_datetime_label(match.indicator.last_seen),
            "Tags": ", ".join(match.indicator.tags),
        }
        for match in result.matches
    ]

def ioc_corroboration_rows(
    result: RuntimeAnalysisResult,
) -> list[dict[str, object]]:
    """Summarize domain-level CTI corroboration across cached sources."""
    rows: list[dict[str, object]] = []

    for assessment in result.assessments:
        sources = assessment.known_ioc_sources
        if not sources:
            continue

        scopes = sorted(
            {
                match_evidence_scope(match_type)
                for match_type in assessment.known_match_types
            }
        )
        rows.append(
            {
                "Domain": assessment.domain,
                "Source count": len(sources),
                "Sources": ", ".join(sources),
                "Evidence scopes": ", ".join(scopes),
                "Corroborated": "Yes" if len(sources) >= 2 else "No",
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            -int(row["Source count"]),
            str(row["Domain"]),
        ),
    )


def cti_status_rows(
    statuses: list[CTICacheStatus],
    *,
    now: datetime | None = None,
    stale_after: timedelta = timedelta(hours=24),
    stale_after_by_source: Mapping[str, timedelta] | None = None,
) -> list[dict[str, object]]:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if stale_after.total_seconds() <= 0:
        raise ValueError("stale_after must be positive")

    source_thresholds = dict(stale_after_by_source or {})
    if any(
        threshold.total_seconds() <= 0
        for threshold in source_thresholds.values()
    ):
        raise ValueError("source-specific stale_after values must be positive")

    rows: list[dict[str, object]] = []
    for status in statuses:
        threshold = source_thresholds.get(status.source, stale_after)
        try:
            refreshed = datetime.fromisoformat(
                status.refreshed_at.replace("Z", "+00:00")
            )
        except (AttributeError, TypeError, ValueError):
            refreshed = None

        freshness = "Unknown"
        age_text = "Unknown"
        if (
            refreshed is not None
            and refreshed.tzinfo is not None
            and refreshed.utcoffset() is not None
        ):
            age = max(
                timedelta(0),
                current.astimezone(timezone.utc)
                - refreshed.astimezone(timezone.utc),
            )
            age_hours = age.total_seconds() / 3600.0
            age_text = f"{age_hours:.1f} h"
            freshness = "Stale" if age > threshold else "Fresh"

        rows.append(
            {
                "Source": status.source,
                "Records": status.record_count,
                "Inactive history": status.inactive_record_count,
                "Refreshed at": format_timestamp(status.refreshed_at),
                "Age": age_text,
                "Stale after": (
                    f"{threshold.total_seconds() / 3600.0:.1f} h"
                ),
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
            "ML tier": ml_tier_label(
                assessment.ml_tier,
                scored=assessment.ml_probability is not None,
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
