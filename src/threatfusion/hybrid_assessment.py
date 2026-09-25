from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum

from .dns import DNSEvent
from .dns_behavior import DomainBehavior, aggregate_dns_behavior
from .matching import DNSIOCMatch
from .models import IOCType
from .normalization import normalize_ioc_value


class HybridVerdict(str, Enum):
    KNOWN_THREAT = "known_threat"
    HIGH_RISK = "high_risk"
    REVIEW = "review"
    LOW = "low"


@dataclass(frozen=True)
class MLThresholds:
    high_confidence: float
    medium_confidence: float
    low_confidence: float

    def __post_init__(self) -> None:
        values = (
            self.high_confidence,
            self.medium_confidence,
            self.low_confidence,
        )
        if any(not math.isfinite(value) for value in values):
            raise ValueError("ML thresholds must be finite")
        if not (
            1.0
            >= self.high_confidence
            >= self.medium_confidence
            >= self.low_confidence
            >= 0.0
        ):
            raise ValueError(
                "ML thresholds must satisfy 1 >= high >= medium >= low >= 0"
            )


@dataclass(frozen=True)
class BehaviorHeuristicConfig:
    high_query_count: int = 50
    multi_client_count: int = 3
    response_ip_churn_count: int = 3
    query_type_diversity_count: int = 3
    burst_query_count: int = 20
    burst_span_seconds: float = 60.0

    def __post_init__(self) -> None:
        integer_values = (
            self.high_query_count,
            self.multi_client_count,
            self.response_ip_churn_count,
            self.query_type_diversity_count,
            self.burst_query_count,
        )
        if any(value < 1 for value in integer_values):
            raise ValueError("behavior count thresholds must be positive")
        if self.burst_span_seconds <= 0:
            raise ValueError("burst_span_seconds must be positive")


@dataclass(frozen=True)
class HybridAssessment:
    domain: str
    verdict: HybridVerdict
    known_ioc_sources: tuple[str, ...]
    known_match_types: tuple[str, ...]
    ml_probability: float | None
    ml_tier: str | None
    behavior: DomainBehavior
    behavior_signals: tuple[str, ...]
    reasons: tuple[str, ...]


def _behavior_signals(
    behavior: DomainBehavior,
    config: BehaviorHeuristicConfig,
) -> tuple[str, ...]:
    signals: list[str] = []

    if behavior.event_count >= config.high_query_count:
        signals.append("high_query_volume")
    if behavior.unique_client_count >= config.multi_client_count:
        signals.append("multi_client_observation")
    if behavior.unique_response_ip_count >= config.response_ip_churn_count:
        signals.append("response_ip_churn")
    if len(behavior.query_types) >= config.query_type_diversity_count:
        signals.append("query_type_diversity")
    if (
        behavior.event_count >= config.burst_query_count
        and behavior.observed_span_seconds is not None
        and behavior.observed_span_seconds <= config.burst_span_seconds
    ):
        signals.append("rapid_query_burst")

    return tuple(signals)


def _normalize_probability_mapping(
    probabilities: Mapping[str, float],
) -> dict[str, float]:
    normalized: dict[str, float] = {}

    for raw_domain, raw_probability in probabilities.items():
        if not isinstance(raw_domain, str):
            raise TypeError("ML probability keys must be domain strings")

        domain = normalize_ioc_value(raw_domain, IOCType.DOMAIN)
        if not domain:
            raise ValueError("ML probability keys must not be empty")

        probability = float(raw_probability)
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise ValueError("ML probabilities must be finite values between 0 and 1")

        normalized[domain] = probability

    return normalized


def _ml_tier(probability: float | None, thresholds: MLThresholds | None) -> str | None:
    if probability is None or thresholds is None:
        return None
    if probability >= thresholds.high_confidence:
        return "high"
    if probability >= thresholds.medium_confidence:
        return "medium"
    if probability >= thresholds.low_confidence:
        return "low"
    return None


def assess_dns_domains(
    events: Iterable[DNSEvent],
    matches: Iterable[DNSIOCMatch],
    *,
    ml_probabilities: Mapping[str, float] | None = None,
    ml_thresholds: MLThresholds | None = None,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> list[HybridAssessment]:
    """Combine known IOC evidence, ML tiers, and local DNS behavior.

    This returns an explainable educational risk verdict. It is not a
    calibrated malware probability and it performs no network activity.
    """
    if (ml_probabilities is None) != (ml_thresholds is None):
        raise ValueError(
            "ml_probabilities and ml_thresholds must be supplied together"
        )

    event_list = list(events)
    match_list = list(matches)
    behaviors = aggregate_dns_behavior(event_list)
    config = behavior_config or BehaviorHeuristicConfig()

    probabilities = (
        _normalize_probability_mapping(ml_probabilities)
        if ml_probabilities is not None
        else {}
    )

    sources_by_domain: dict[str, set[str]] = defaultdict(set)
    match_types_by_domain: dict[str, set[str]] = defaultdict(set)

    for match in match_list:
        query_name = match.event.query_name
        if not isinstance(query_name, str):
            continue
        domain = normalize_ioc_value(query_name, IOCType.DOMAIN)
        if not domain:
            continue
        sources_by_domain[domain].add(match.indicator.source)
        match_types_by_domain[domain].add(match.match_type)

    assessments: list[HybridAssessment] = []

    for behavior in behaviors:
        sources = tuple(sorted(sources_by_domain.get(behavior.domain, set())))
        match_types = tuple(
            sorted(match_types_by_domain.get(behavior.domain, set()))
        )
        probability = probabilities.get(behavior.domain)
        tier = _ml_tier(probability, ml_thresholds)
        behavior_signals = _behavior_signals(behavior, config)

        exact_domain_ioc = "query_domain" in match_types
        contextual_ioc = bool(
            {"url_hostname", "response_ip"} & set(match_types)
        )

        reasons: list[str] = []
        if exact_domain_ioc:
            reasons.append("known_ioc_match")
        if "url_hostname" in match_types:
            reasons.append("url_hostname_ioc_context")
        if "response_ip" in match_types:
            reasons.append("response_ip_ioc_context")
        if tier is not None:
            reasons.append(f"ml_{tier}_confidence")
        reasons.extend(behavior_signals)

        if exact_domain_ioc:
            verdict = HybridVerdict.KNOWN_THREAT
        elif tier == "high" or (
            tier == "medium" and len(behavior_signals) >= 2
        ):
            verdict = HybridVerdict.HIGH_RISK
        elif (
            contextual_ioc
            or tier in {"medium", "low"}
            or len(behavior_signals) >= 2
        ):
            verdict = HybridVerdict.REVIEW
        else:
            verdict = HybridVerdict.LOW

        assessments.append(
            HybridAssessment(
                domain=behavior.domain,
                verdict=verdict,
                known_ioc_sources=sources,
                known_match_types=match_types,
                ml_probability=probability,
                ml_tier=tier,
                behavior=behavior,
                behavior_signals=behavior_signals,
                reasons=tuple(reasons),
            )
        )

    return assessments
