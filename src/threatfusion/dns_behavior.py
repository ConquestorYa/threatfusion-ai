from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

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
            )
        )

    return results
