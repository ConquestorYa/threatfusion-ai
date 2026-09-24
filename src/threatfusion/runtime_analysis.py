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
from .models import IOCRecord


@dataclass(frozen=True)
class RuntimeAnalysisResult:
    events: tuple[DNSEvent, ...]
    matches: tuple[DNSIOCMatch, ...]
    ml_probabilities: dict[str, float]
    assessments: tuple[HybridAssessment, ...]


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

    matches = match_dns_events(event_list, indicator_list)
    ml_probabilities = predict_domain_probabilities(
        artifact,
        [event.query_name for event in event_list],
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
