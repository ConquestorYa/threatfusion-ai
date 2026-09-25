from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise
from statistics import pstdev

from .dns import DNSEvent
from .models import IOCType
from .normalization import normalize_ioc_value


@dataclass(frozen=True)
class DomainBehavior:
    domain: str
    event_count: int
    unique_client_count: int
    unique_response_ip_count: int
    query_types: tuple[str, ...]
    first_seen: datetime | None
    last_seen: datetime | None
    observed_span_seconds: float | None
    response_code_counts: tuple[tuple[str, int], ...] = ()
    nxdomain_count: int = 0
    nxdomain_ratio: float | None = None
    label_count: int = 0
    subdomain_depth: int = 0
    numeric_character_ratio: float | None = None
    hostname_entropy: float | None = None
    random_like_hostname: bool | None = None
    response_ip_churn_rate: float | None = None
    periodic_interval_seconds: float | None = None
    periodicity_score: float | None = None
    periodic_query_pattern: bool | None = None


def _timestamp_summary(
    timestamps: list[datetime],
) -> tuple[datetime | None, datetime | None, float | None]:
    if not timestamps:
        return None, None, None

    awareness = {
        timestamp.tzinfo is not None and timestamp.utcoffset() is not None
        for timestamp in timestamps
    }
    if len(awareness) > 1:
        return None, None, None

    first_seen = min(timestamps)
    last_seen = max(timestamps)
    return first_seen, last_seen, (last_seen - first_seen).total_seconds()


def _response_code_counts(domain_events: list[DNSEvent]) -> tuple[tuple[str, int], ...]:
    counts = Counter(
        code.upper()
        for event in domain_events
        if (code := event.response_code) is not None and code.strip()
    )
    return tuple(sorted(counts.items()))


def _nxdomain_ratio(response_code_counts: tuple[tuple[str, int], ...]) -> tuple[int, float | None]:
    if not response_code_counts:
        return 0, None
    total = sum(count for _, count in response_code_counts)
    nxdomain_count = sum(
        count
        for code, count in response_code_counts
        if code in {"NXDOMAIN", "RCODE3", "3"}
    )
    return nxdomain_count, nxdomain_count / total if total > 0 else None


def _domain_shape_metrics(
    domain: str,
) -> tuple[int, int, float | None, float | None, bool | None]:
    labels = [label for label in domain.split(".") if label]
    label_count = len(labels)
    subdomain_depth = max(0, label_count - 2)

    alnum_chars = [char for char in domain if char.isalnum()]
    if not alnum_chars:
        return label_count, subdomain_depth, None, None, None

    numeric_ratio = sum(char.isdigit() for char in alnum_chars) / len(alnum_chars)
    frequencies = Counter(alnum_chars)
    entropy = -sum(
        (count / len(alnum_chars)) * math.log2(count / len(alnum_chars))
        for count in frequencies.values()
    )
    random_like = (
        len(alnum_chars) >= 12 and entropy >= 3.2 and numeric_ratio >= 0.2
    )
    return label_count, subdomain_depth, numeric_ratio, entropy, random_like


def _response_ip_churn_rate(domain_events: list[DNSEvent]) -> float | None:
    response_ip_observations = [
        event.response_ip for event in domain_events if event.response_ip is not None
    ]
    if not response_ip_observations:
        return None
    return len(set(response_ip_observations)) / len(response_ip_observations)


def _periodicity_metrics(
    timestamps: list[datetime],
) -> tuple[float | None, float | None, bool | None]:
    if len(timestamps) < 3:
        return None, None, None

    awareness = {
        timestamp.tzinfo is not None and timestamp.utcoffset() is not None
        for timestamp in timestamps
    }
    if len(awareness) > 1:
        return None, None, None

    ordered = sorted(timestamps)
    intervals = [
        (right - left).total_seconds()
        for left, right in pairwise(ordered)
        if (right - left).total_seconds() > 0
    ]
    if len(intervals) < 2:
        return None, None, None

    mean_interval = sum(intervals) / len(intervals)
    if mean_interval <= 0:
        return None, None, None
    variation = pstdev(intervals) / mean_interval
    score = 1.0 / (1.0 + variation)
    return mean_interval, score, score >= 0.85


def aggregate_dns_behavior(events: Iterable[DNSEvent]) -> list[DomainBehavior]:
    """Aggregate local DNS observations by normalized query domain."""
    grouped: dict[str, list[DNSEvent]] = defaultdict(list)

    for event in events:
        if not isinstance(event.query_name, str):
            continue
        domain = normalize_ioc_value(event.query_name, IOCType.DOMAIN)
        if not domain:
            continue
        grouped[domain].append(event)

    results: list[DomainBehavior] = []
    for domain in sorted(grouped):
        domain_events = grouped[domain]
        clients = {
            event.client_ip
            for event in domain_events
            if event.client_ip is not None
        }
        response_ips = {
            event.response_ip
            for event in domain_events
            if event.response_ip is not None
        }
        query_types = {
            event.query_type
            for event in domain_events
            if event.query_type is not None
        }
        timestamps = [
            event.timestamp
            for event in domain_events
            if event.timestamp is not None
        ]
        first_seen, last_seen, observed_span_seconds = _timestamp_summary(timestamps)
        response_code_counts = _response_code_counts(domain_events)
        nxdomain_count, nxdomain_ratio = _nxdomain_ratio(response_code_counts)
        (
            label_count,
            subdomain_depth,
            numeric_character_ratio,
            hostname_entropy,
            random_like_hostname,
        ) = _domain_shape_metrics(domain)
        response_ip_churn_rate = _response_ip_churn_rate(domain_events)
        (
            periodic_interval_seconds,
            periodicity_score,
            periodic_query_pattern,
        ) = _periodicity_metrics(timestamps)

        results.append(
            DomainBehavior(
                domain=domain,
                event_count=len(domain_events),
                unique_client_count=len(clients),
                unique_response_ip_count=len(response_ips),
                query_types=tuple(sorted(query_types)),
                first_seen=first_seen,
                last_seen=last_seen,
                observed_span_seconds=observed_span_seconds,
                response_code_counts=response_code_counts,
                nxdomain_count=nxdomain_count,
                nxdomain_ratio=nxdomain_ratio,
                label_count=label_count,
                subdomain_depth=subdomain_depth,
                numeric_character_ratio=numeric_character_ratio,
                hostname_entropy=hostname_entropy,
                random_like_hostname=random_like_hostname,
                response_ip_churn_rate=response_ip_churn_rate,
                periodic_interval_seconds=periodic_interval_seconds,
                periodicity_score=periodicity_score,
                periodic_query_pattern=periodic_query_pattern,
            )
        )

    return results
