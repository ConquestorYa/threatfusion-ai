from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from .hybrid_assessment import HybridVerdict
from .models import IOCType
from .normalization import normalize_ioc_value
from .runtime_analysis import RuntimeAnalysisResult


@dataclass(frozen=True)
class DomainRelationship:
    domain_a: str
    domain_b: str
    shared_client_count: int
    shared_response_ip_count: int
    min_time_delta_seconds: float | None
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class RelatedActivityCluster:
    cluster_id: str
    domains: tuple[str, ...]
    relationships: tuple[DomainRelationship, ...]


@dataclass(frozen=True)
class RelatedActivityReport:
    clusters: tuple[RelatedActivityCluster, ...]
    relationships: tuple[DomainRelationship, ...]


def _timestamp_is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _minimum_time_delta(
    left: tuple[datetime, ...],
    right: tuple[datetime, ...],
) -> float | None:
    best: float | None = None

    for left_value in left:
        for right_value in right:
            if _timestamp_is_aware(left_value) != _timestamp_is_aware(right_value):
                continue
            delta = abs((left_value - right_value).total_seconds())
            if best is None or delta < best:
                best = delta

    return best


def find_related_activity(
    result: RuntimeAnalysisResult,
    *,
    time_proximity_seconds: float = 300.0,
) -> RelatedActivityReport:
    """Find possible related suspicious-domain activity from local DNS evidence.

    A relationship requires a shared client observation or shared response IP.
    Time proximity is supporting context only and never creates an edge alone.
    """
    if time_proximity_seconds < 0:
        raise ValueError("time_proximity_seconds must be non-negative")

    candidate_domains = {
        assessment.domain
        for assessment in result.assessments
        if assessment.verdict is not HybridVerdict.LOW
    }

    clients: dict[str, set[str]] = defaultdict(set)
    response_ips: dict[str, set[str]] = defaultdict(set)
    timestamps: dict[str, list[datetime]] = defaultdict(list)

    for event in result.events:
        domain = normalize_ioc_value(event.query_name, IOCType.DOMAIN)
        if domain not in candidate_domains:
            continue
        if event.client_ip is not None:
            clients[domain].add(event.client_ip)
        if event.response_ip is not None:
            response_ips[domain].add(event.response_ip)
        if event.timestamp is not None:
            timestamps[domain].append(event.timestamp)

    domains = sorted(candidate_domains)
    relationships: list[DomainRelationship] = []

    for index, domain_a in enumerate(domains):
        for domain_b in domains[index + 1 :]:
            shared_clients = clients[domain_a] & clients[domain_b]
            shared_response_ips = response_ips[domain_a] & response_ips[domain_b]

            if not shared_clients and not shared_response_ips:
                continue

            time_delta = _minimum_time_delta(
                tuple(timestamps[domain_a]),
                tuple(timestamps[domain_b]),
            )

            reasons: list[str] = []
            if shared_clients:
                reasons.append("shared_client")
            if shared_response_ips:
                reasons.append("shared_response_ip")
            if (
                time_delta is not None
                and time_delta <= time_proximity_seconds
            ):
                reasons.append("time_proximity")

            relationships.append(
                DomainRelationship(
                    domain_a=domain_a,
                    domain_b=domain_b,
                    shared_client_count=len(shared_clients),
                    shared_response_ip_count=len(shared_response_ips),
                    min_time_delta_seconds=time_delta,
                    reasons=tuple(reasons),
                )
            )

    adjacency: dict[str, set[str]] = defaultdict(set)
    for relationship in relationships:
        adjacency[relationship.domain_a].add(relationship.domain_b)
        adjacency[relationship.domain_b].add(relationship.domain_a)

    components: list[tuple[str, ...]] = []
    visited: set[str] = set()

    for domain in domains:
        if domain in visited or domain not in adjacency:
            continue

        stack = [domain]
        component: set[str] = set()

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            component.add(current)
            stack.extend(
                sorted(adjacency[current] - visited, reverse=True)
            )

        if len(component) >= 2:
            components.append(tuple(sorted(component)))

    components.sort()
    clusters: list[RelatedActivityCluster] = []

    for index, component in enumerate(components, start=1):
        component_set = set(component)
        cluster_relationships = tuple(
            relationship
            for relationship in relationships
            if relationship.domain_a in component_set
            and relationship.domain_b in component_set
        )
        clusters.append(
            RelatedActivityCluster(
                cluster_id=f"group-{index}",
                domains=component,
                relationships=cluster_relationships,
            )
        )

    return RelatedActivityReport(
        clusters=tuple(clusters),
        relationships=tuple(relationships),
    )
