from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .dns import DNSEvent, parse_dns_csv
from .hybrid_assessment import (
    BehaviorHeuristicConfig,
    HybridAssessment,
    assess_dns_domains,
)
from .matching import DNSIOCMatch, match_dns_events
from .ml_artifact import TrainedMLArtifact, predict_domain_probabilities
from .ml_scoring import evaluate_ml_scoring_eligibility
from .models import IOCRecord


DEFAULT_MAX_EVENTS = 100_000
DEFAULT_MAX_UNIQUE_DOMAINS = 20_000


@dataclass(frozen=True)
class RuntimeAnalysisResult:
    events: tuple[DNSEvent, ...]
    matches: tuple[DNSIOCMatch, ...]
    ml_probabilities: dict[str, float]
    assessments: tuple[HybridAssessment, ...]


def _validate_positive_limit(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


def _materialize_bounded_events(
    events: Iterable[DNSEvent],
    *,
    max_events: int,
    max_unique_domains: int,
) -> list[DNSEvent]:
    _validate_positive_limit("max_events", max_events)
    _validate_positive_limit("max_unique_domains", max_unique_domains)

    materialized: list[DNSEvent] = []
    unique_domains: set[str] = set()

    for event in events:
        if len(materialized) >= max_events:
            raise ValueError(
                f"DNS analysis exceeds the {max_events} event limit"
            )
        materialized.append(event)

        query_name = event.query_name
        if not isinstance(query_name, str):
            continue
        normalized_key = query_name.strip().casefold().removesuffix(".")
        if not normalized_key:
            continue

        unique_domains.add(normalized_key)
        if len(unique_domains) > max_unique_domains:
            raise ValueError(
                "DNS analysis exceeds the "
                f"{max_unique_domains} unique-domain limit"
            )

    return materialized


def analyze_dns_events(
    events: Iterable[DNSEvent],
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_unique_domains: int = DEFAULT_MAX_UNIQUE_DOMAINS,
) -> RuntimeAnalysisResult:
    """Run the local ThreatFusion analysis pipeline over DNS events.

    This function performs no network activity. IOC values remain inert data;
    matching, ML inference, behavior aggregation, and hybrid assessment all
    operate on already-loaded local objects.

    Known-IOC matching and behavior analysis apply to every retained DNS
    observation. The public-domain string classifier is called only for query
    names that match its intended public Internet-domain scope.
    """
    event_list = _materialize_bounded_events(
        events,
        max_events=max_events,
        max_unique_domains=max_unique_domains,
    )
    indicator_list = list(indicators)

    matches = match_dns_events(event_list, indicator_list)
    ml_domains = [
        event.query_name
        for event in event_list
        if evaluate_ml_scoring_eligibility(event.query_name).eligible
    ]
    ml_probabilities = predict_domain_probabilities(
        artifact,
        ml_domains,
    )
    assessments = assess_dns_domains(
        event_list,
        matches,
        ml_probabilities=ml_probabilities,
        ml_thresholds=artifact.thresholds,
        behavior_config=behavior_config,
    )

    return RuntimeAnalysisResult(
        events=tuple(event_list),
        matches=tuple(matches),
        ml_probabilities=ml_probabilities,
        assessments=tuple(assessments),
    )


def analyze_dns_csv(
    content: str,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
    max_events: int = DEFAULT_MAX_EVENTS,
    max_unique_domains: int = DEFAULT_MAX_UNIQUE_DOMAINS,
) -> RuntimeAnalysisResult:
    """Parse DNS CSV text and run the local runtime analysis pipeline."""
    events = parse_dns_csv(content)
    return analyze_dns_events(
        events,
        indicators,
        artifact,
        behavior_config=behavior_config,
        max_events=max_events,
        max_unique_domains=max_unique_domains,
    )
