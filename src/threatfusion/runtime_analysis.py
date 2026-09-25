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
from .ml_dataset import normalize_domain_candidate
from .models import IOCRecord


MAX_DNS_EVENTS = 100_000
MAX_UNIQUE_QUERY_NAMES = 25_000

_ML_EXCLUDED_SUFFIXES = (
    ".in-addr.arpa",
    ".ip6.arpa",
    ".local",
    ".localdomain",
)


@dataclass(frozen=True)
class RuntimeAnalysisResult:
    events: tuple[DNSEvent, ...]
    matches: tuple[DNSIOCMatch, ...]
    ml_probabilities: dict[str, float]
    assessments: tuple[HybridAssessment, ...]



def is_ml_scoring_candidate(value: str) -> bool:
    """Return whether a DNS query is suitable for internet-domain ML scoring."""
    normalized = normalize_domain_candidate(value)
    if normalized is None or "." not in normalized:
        return False
    if normalized == "localhost":
        return False
    return not normalized.endswith(_ML_EXCLUDED_SUFFIXES)


def _validate_runtime_bounds(events: list[DNSEvent]) -> None:
    if len(events) > MAX_DNS_EVENTS:
        raise ValueError(
            f"DNS input exceeds the {MAX_DNS_EVENTS} event analysis limit"
        )

    unique_names = {
        event.query_name.strip().casefold().removesuffix(".")
        for event in events
        if isinstance(event.query_name, str) and event.query_name.strip()
    }
    if len(unique_names) > MAX_UNIQUE_QUERY_NAMES:
        raise ValueError(
            "DNS input exceeds the "
            f"{MAX_UNIQUE_QUERY_NAMES} unique-query analysis limit"
        )

def analyze_dns_events(
    events: Iterable[DNSEvent],
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> RuntimeAnalysisResult:
    """Run the local ThreatFusion analysis pipeline over DNS events.

    This function performs no network activity. IOC values remain inert data;
    matching, ML inference, behavior aggregation, and hybrid assessment all
    operate on already-loaded local objects.
    """
    event_list = list(events)
    indicator_list = list(indicators)
    _validate_runtime_bounds(event_list)

    matches = match_dns_events(event_list, indicator_list)
    ml_probabilities = predict_domain_probabilities(
        artifact,
        [
            event.query_name
            for event in event_list
            if is_ml_scoring_candidate(event.query_name)
        ],
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
) -> RuntimeAnalysisResult:
    """Parse DNS CSV text and run the local runtime analysis pipeline."""
    events = parse_dns_csv(content)
    return analyze_dns_events(
        events,
        indicators,
        artifact,
        behavior_config=behavior_config,
    )
