"""Local client/domain triage; queue priority is separate from threat verdict."""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .dns import DNSEvent
from .hybrid_assessment import (
    BehaviorHeuristicConfig,
    HybridAssessment,
    HybridVerdict,
    MLThresholds,
    assess_dns_domains,
)
from .matching import DNSIOCMatch
from .models import IOCType
from .normalization import normalize_ioc_value

POLICY_ID = "dns-device-triage-v1"
# Engineering coverage gates, not measured malware-detection thresholds.
MIN_PERIODIC_TIMESTAMPS = 20
MIN_PERIODIC_SPAN_SECONDS = 1800


@dataclass(frozen=True)
class DeviceFinding:
    client_ip: str | None
    assessment: HybridAssessment
    priority: str
    reasons: tuple[str, ...]
    timestamped_events: int
    distinct_timestamps: int
    limitations: tuple[str, ...]


def _client_key(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip())) if value else None
    except ValueError:
        return None


def build_device_findings(
    events: Iterable[DNSEvent],
    matches: Iterable[DNSIOCMatch],
    *,
    ml_scores: Mapping[str, float] | None = None,
    ml_thresholds: MLThresholds | None = None,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[DeviceFinding, ...]:
    """Assess each observed client independently without scoring ML again.

    Matches must refer to input event objects, as match_dns_events does. No
    domain-level infrastructure evidence is copied across different clients.
    Unknown clients are one unattributed bucket, never a periodic device.
    """
    by_client: dict[str | None, list[DNSEvent]] = defaultdict(list)
    event_clients: dict[int, str | None] = {}
    for event in events:
        client = _client_key(event.client_ip)
        by_client[client].append(event)
        event_clients[id(event)] = client
    by_match: dict[str | None, list[DNSIOCMatch]] = defaultdict(list)
    for match in matches:
        if id(match.event) in event_clients:
            by_match[event_clients[id(match.event)]].append(match)

    findings = []
    for client, client_events in by_client.items():
        by_domain: dict[str, list[DNSEvent]] = defaultdict(list)
        for event in client_events:
            domain = normalize_ioc_value(event.query_name, IOCType.DOMAIN)
            if domain:
                by_domain[domain].append(event)
        scores = (
            {domain: ml_scores[domain] for domain in by_domain if domain in ml_scores}
            if ml_scores is not None else None
        )
        assessments = assess_dns_domains(
            client_events, by_match[client], ml_scores=scores,
            ml_thresholds=ml_thresholds, behavior_config=behavior_config,
        )
        for assessment in assessments:
            domain_events = by_domain[assessment.domain]
            timestamps = [e.timestamp for e in domain_events if e.timestamp is not None]
            distinct = len(set(timestamps))
            coverage = []
            try:
                ipaddress.ip_address(assessment.domain)
            except ValueError:
                pass
            else:
                coverage.append("ip_target_not_dns_query")
            if client is None:
                coverage.append("missing_or_invalid_client_ip")
            if len(timestamps) != len(domain_events):
                coverage.append("missing_timestamps")
            if any(t.tzinfo is None or t.utcoffset() is None for t in timestamps):
                coverage.append("ambiguous_timestamp_timezone")
            if distinct < MIN_PERIODIC_TIMESTAMPS:
                coverage.append("insufficient_distinct_timestamps")
            span = assessment.behavior.observed_span_seconds
            if span is None or span < MIN_PERIODIC_SPAN_SECONDS:
                coverage.append("insufficient_observed_span")
            reasons = list(assessment.reasons)
            if assessment.verdict in {HybridVerdict.KNOWN_THREAT, HybridVerdict.HIGH_RISK}:
                priority = "investigate"
            elif assessment.verdict is HybridVerdict.REVIEW:
                priority = "review"
            else:
                priority = "observe"
            if not coverage and assessment.behavior.periodic_query_pattern:
                reasons.append("sustained_periodic_dns")
                if priority == "observe":
                    priority = "review"
            findings.append(DeviceFinding(
                client_ip=client, assessment=assessment, priority=priority,
                reasons=tuple(reasons), timestamped_events=len(timestamps),
                distinct_timestamps=distinct, limitations=tuple(coverage),
            ))
    order = {"investigate": 0, "review": 1, "observe": 2}
    return tuple(sorted(findings, key=lambda f: (
        order[f.priority], f.client_ip or "", f.assessment.domain,
    )))
