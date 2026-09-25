from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from .hybrid_assessment import HybridVerdict
from .models import IOCType
from .normalization import normalize_ioc_value
from .runtime_analysis import RuntimeAnalysisResult

MAX_RELATED_ACTIVITY_DOMAINS = 500
MAX_RELATED_ACTIVITY_RELATIONSHIPS = 10_000
MAX_SHARED_VALUE_PAIR_FANOUT = 8
COMMON_SHARED_VALUE_FANOUT = 3
MIN_RELATIONSHIP_STRENGTH = 0.45


@dataclass(frozen=True)
class DomainRelationship:
    domain_a: str
    domain_b: str
    shared_client_count: int
    shared_response_ip_count: int
    min_time_delta_seconds: float | None
    reasons: tuple[str, ...]
    strength: float = 0.0
    shared_cti_source_count: int = 0
    shared_cti_tag_count: int = 0
    shared_threat_type_count: int = 0
    penalties: tuple[str, ...] = ()


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


def _minimum_sorted_time_delta(
    left: list[datetime],
    right: list[datetime],
) -> float | None:
    if not left or not right:
        return None

    left_sorted = sorted(left)
    right_sorted = sorted(right)
    left_index = 0
    right_index = 0
    best: float | None = None

    while left_index < len(left_sorted) and right_index < len(right_sorted):
        left_value = left_sorted[left_index]
        right_value = right_sorted[right_index]
        delta = abs((left_value - right_value).total_seconds())
        if best is None or delta < best:
            best = delta
            if best == 0.0:
                return 0.0

        if left_value < right_value:
            left_index += 1
        else:
            right_index += 1

    return best


def _minimum_time_delta(
    left: tuple[datetime, ...],
    right: tuple[datetime, ...],
) -> float | None:
    best: float | None = None

    for awareness in (False, True):
        left_group = [
            value for value in left if _timestamp_is_aware(value) is awareness
        ]
        right_group = [
            value for value in right if _timestamp_is_aware(value) is awareness
        ]
        candidate = _minimum_sorted_time_delta(left_group, right_group)
        if candidate is not None and (best is None or candidate < best):
            best = candidate

    return best


def _domains_by_value(
    values_by_domain: dict[str, set[str]],
) -> dict[str, set[str]]:
    domains_by_value: dict[str, set[str]] = defaultdict(set)
    for domain, values in values_by_domain.items():
        for value in values:
            domains_by_value[value].add(domain)
    return domains_by_value


def _value_fanout(
    values_by_domain: dict[str, set[str]],
) -> dict[str, int]:
    return {
        value: len(domains)
        for value, domains in _domains_by_value(values_by_domain).items()
    }


def _pairs_from_shared_values(
    values_by_domain: dict[str, set[str]],
) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()

    for domains in _domains_by_value(values_by_domain).values():
        if len(domains) > MAX_SHARED_VALUE_PAIR_FANOUT:
            continue

        ordered = sorted(domains)
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                pairs.add((left, right))
                if len(pairs) > MAX_RELATED_ACTIVITY_RELATIONSHIPS:
                    raise ValueError(
                        "related-activity relationship limit exceeded"
                    )

    return pairs


def _normalized_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        normalized = normalize_ioc_value(value, IOCType.DOMAIN)
    except ValueError:
        return None
    return normalized or None


def _cti_context(
    result: RuntimeAnalysisResult,
    candidate_domains: set[str],
) -> tuple[
    dict[str, set[str]],
    dict[str, set[str]],
    dict[str, set[str]],
]:
    sources: dict[str, set[str]] = defaultdict(set)
    tags: dict[str, set[str]] = defaultdict(set)
    threat_types: dict[str, set[str]] = defaultdict(set)

    for match in result.matches:
        domain = _normalized_domain(match.event.query_name)
        if domain not in candidate_domains:
            continue

        source = match.indicator.source.strip()
        if source:
            sources[domain].add(source.casefold())

        for raw_tag in match.indicator.tags:
            tag = raw_tag.strip().casefold()
            if tag:
                tags[domain].add(tag)

        if match.indicator.threat_type:
            threat_type = match.indicator.threat_type.strip().casefold()
            if threat_type:
                threat_types[domain].add(threat_type)

    return sources, tags, threat_types


def _score_relationship(
    *,
    shared_clients: set[str],
    shared_response_ips: set[str],
    client_fanout: dict[str, int],
    response_ip_fanout: dict[str, int],
    time_delta: float | None,
    time_proximity_seconds: float,
    shared_cti_source_count: int,
    shared_cti_tag_count: int,
    shared_threat_type_count: int,
) -> tuple[float, tuple[str, ...], tuple[str, ...]]:
    reasons: list[str] = []
    penalties: list[str] = []
    score = 0.0
    penalty = 0.0

    rare_clients = sum(
        client_fanout.get(value, 0) < COMMON_SHARED_VALUE_FANOUT
        for value in shared_clients
    )
    common_clients = len(shared_clients) - rare_clients

    if shared_clients:
        reasons.append("shared_client")
    if rare_clients:
        score += min(0.65, 0.50 + 0.08 * (rare_clients - 1))
    if common_clients:
        score += min(0.18, 0.08 * common_clients)
        if not rare_clients:
            penalties.append("shared_client_high_fanout")
            penalty += 0.10

    rare_response_ips = sum(
        response_ip_fanout.get(value, 0) < COMMON_SHARED_VALUE_FANOUT
        for value in shared_response_ips
    )
    common_response_ips = len(shared_response_ips) - rare_response_ips

    if shared_response_ips:
        reasons.append("shared_response_ip")
    if rare_response_ips:
        score += min(0.60, 0.45 + 0.07 * (rare_response_ips - 1))
    if common_response_ips:
        score += min(0.12, 0.05 * common_response_ips)
        if not rare_response_ips:
            penalties.append("shared_response_ip_high_fanout")
            penalty += 0.15

    if (
        time_delta is not None
        and time_delta <= time_proximity_seconds
    ):
        reasons.append("time_proximity")
        close_window = min(60.0, time_proximity_seconds)
        score += 0.15 if time_delta <= close_window else 0.10

    if shared_cti_source_count:
        reasons.append("shared_cti_source")
        score += min(0.15, 0.10 + 0.02 * (shared_cti_source_count - 1))

    if shared_cti_tag_count:
        reasons.append("shared_cti_tag")
        score += min(0.15, 0.10 + 0.02 * (shared_cti_tag_count - 1))

    if shared_threat_type_count:
        reasons.append("shared_threat_type")
        score += min(0.20, 0.15 + 0.025 * (shared_threat_type_count - 1))

    strength = round(max(0.0, min(1.0, score - penalty)), 3)
    return strength, tuple(reasons), tuple(penalties)


def find_related_activity(
    result: RuntimeAnalysisResult,
    *,
    time_proximity_seconds: float = 300.0,
) -> RelatedActivityReport:
    """Find possible related suspicious-domain activity from local evidence.

    Shared client or response-infrastructure observations create bounded
    candidate pairs. The final edge score combines rarity-aware local
    infrastructure evidence with time and CTI metadata overlap. High-fanout
    values are filtered or penalized to reduce likely resolver/CDN/NAT noise.
    The output remains non-attributive and does not claim a malware campaign.
    """
    if time_proximity_seconds < 0:
        raise ValueError("time_proximity_seconds must be non-negative")

    candidate_domains = {
        assessment.domain
        for assessment in result.assessments
        if assessment.verdict is not HybridVerdict.LOW
    }

    domains = sorted(candidate_domains)
    if len(domains) > MAX_RELATED_ACTIVITY_DOMAINS:
        raise ValueError(
            "related-activity suspicious-domain limit exceeded"
        )

    clients: dict[str, set[str]] = defaultdict(set)
    response_ips: dict[str, set[str]] = defaultdict(set)
    timestamps: dict[str, list[datetime]] = defaultdict(list)

    for event in result.events:
        domain = _normalized_domain(event.query_name)
        if domain not in candidate_domains:
            continue
        if event.client_ip is not None:
            clients[domain].add(event.client_ip)
        if event.response_ip is not None:
            response_ips[domain].add(event.response_ip)
        if event.timestamp is not None:
            timestamps[domain].append(event.timestamp)

    client_fanout = _value_fanout(clients)
    response_ip_fanout = _value_fanout(response_ips)

    candidate_pairs = (
        _pairs_from_shared_values(clients)
        | _pairs_from_shared_values(response_ips)
    )
    if len(candidate_pairs) > MAX_RELATED_ACTIVITY_RELATIONSHIPS:
        raise ValueError("related-activity relationship limit exceeded")

    cti_sources, cti_tags, cti_threat_types = _cti_context(
        result,
        candidate_domains,
    )

    relationships: list[DomainRelationship] = []

    for domain_a, domain_b in sorted(candidate_pairs):
        shared_clients = clients[domain_a] & clients[domain_b]
        shared_response_ips = response_ips[domain_a] & response_ips[domain_b]

        time_delta = _minimum_time_delta(
            tuple(timestamps[domain_a]),
            tuple(timestamps[domain_b]),
        )

        shared_sources = cti_sources[domain_a] & cti_sources[domain_b]
        shared_tags = cti_tags[domain_a] & cti_tags[domain_b]
        shared_threat_types = (
            cti_threat_types[domain_a] & cti_threat_types[domain_b]
        )

        strength, reasons, penalties = _score_relationship(
            shared_clients=shared_clients,
            shared_response_ips=shared_response_ips,
            client_fanout=client_fanout,
            response_ip_fanout=response_ip_fanout,
            time_delta=time_delta,
            time_proximity_seconds=time_proximity_seconds,
            shared_cti_source_count=len(shared_sources),
            shared_cti_tag_count=len(shared_tags),
            shared_threat_type_count=len(shared_threat_types),
        )

        if strength < MIN_RELATIONSHIP_STRENGTH:
            continue

        relationships.append(
            DomainRelationship(
                domain_a=domain_a,
                domain_b=domain_b,
                shared_client_count=len(shared_clients),
                shared_response_ip_count=len(shared_response_ips),
                min_time_delta_seconds=time_delta,
                reasons=reasons,
                strength=strength,
                shared_cti_source_count=len(shared_sources),
                shared_cti_tag_count=len(shared_tags),
                shared_threat_type_count=len(shared_threat_types),
                penalties=penalties,
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
