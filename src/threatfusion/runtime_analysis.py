from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .dns import DNSEvent, DNSParseDiagnostics, parse_dns_csv_with_diagnostics
from .dns_ingest import DNSInputDetection, parse_dns_upload_with_diagnostics
from .dns_adguard import parse_adguard_query_log_with_diagnostics
from .dns_pihole import parse_pihole_query_db_with_diagnostics
from .dns_zeek import parse_zeek_dns_log_with_diagnostics
from .dns_behavior import DomainBehavior
from .hybrid_assessment import (
    BehaviorHeuristicConfig,
    HybridAssessment,
    HybridVerdict,
    assess_dns_domains,
)
from .matching import DNSIOCMatch, match_dns_events
from .ml_artifact import TrainedMLArtifact, predict_domain_scores
from .ml_dataset import normalize_domain_candidate
from .models import IOCRecord

MAX_DNS_EVENTS = 100_000
MAX_UNIQUE_QUERY_NAMES = 25_000

_ML_EXCLUDED_SUFFIXES = (
    ".in-addr.arpa",
    ".ip6.arpa",
    ".local",
    ".localdomain",
    ".localhost",
    ".home.arpa",
)


@dataclass(frozen=True)
class RuntimeAnalysisResult:
    events: tuple[DNSEvent, ...]
    matches: tuple[DNSIOCMatch, ...]
    ml_scores: dict[str, float]
    assessments: tuple[HybridAssessment, ...]

    @property
    def ml_probabilities(self) -> dict[str, float]:
        """Backward-compatible alias for uncalibrated ML scores."""
        return self.ml_scores


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


def _connection_target_assessments(
    events: list[DNSEvent],
    matches: list[DNSIOCMatch],
) -> list[HybridAssessment]:
    grouped: dict[str, list[DNSEvent]] = defaultdict(list)
    for event in events:
        target = event.query_name.strip() if isinstance(event.query_name, str) else ""
        if target:
            grouped[target].append(event)

    sources_by_target: dict[str, set[str]] = defaultdict(set)
    match_types_by_target: dict[str, set[str]] = defaultdict(set)
    for match in matches:
        target = (
            match.event.query_name.strip()
            if isinstance(match.event.query_name, str)
            else ""
        )
        if not target:
            continue
        sources_by_target[target].add(match.indicator.source)
        match_types_by_target[target].add(match.match_type)

    assessments: list[HybridAssessment] = []
    for target in sorted(grouped):
        target_events = grouped[target]
        timestamps = [
            event.timestamp
            for event in target_events
            if event.timestamp is not None
        ]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None
        span = (
            (last_seen - first_seen).total_seconds()
            if first_seen is not None and last_seen is not None
            else None
        )
        clients = {
            event.client_ip
            for event in target_events
            if event.client_ip is not None
        }
        query_types = tuple(
            sorted(
                {
                    event.query_type
                    for event in target_events
                    if event.query_type is not None
                }
            )
        )
        sources = tuple(sorted(sources_by_target.get(target, set())))
        match_types = tuple(sorted(match_types_by_target.get(target, set())))
        reasons: list[str] = []
        if "response_ip" in match_types:
            reasons.append("response_ip_ioc_context")
        if "response_ip_network" in match_types:
            reasons.append("response_ip_network_ioc_context")

        behavior = DomainBehavior(
            domain=target,
            event_count=len(target_events),
            unique_client_count=len(clients),
            unique_response_ip_count=1,
            query_types=query_types,
            first_seen=first_seen,
            last_seen=last_seen,
            observed_span_seconds=span,
        )
        assessments.append(
            HybridAssessment(
                domain=target,
                verdict=HybridVerdict.REVIEW if sources else HybridVerdict.LOW,
                known_ioc_sources=sources,
                known_match_types=match_types,
                ml_score=None,
                ml_tier=None,
                behavior=behavior,
                behavior_signals=(),
                reasons=tuple(reasons),
            )
        )
    return assessments


def analyze_connection_events(
    events: Iterable[DNSEvent],
    indicators: Iterable[IOCRecord],
) -> RuntimeAnalysisResult:
    """Analyze connection destination IPs against local CTI only."""
    event_list = list(events)
    indicator_list = list(indicators)
    _validate_runtime_bounds(event_list)
    matches = match_dns_events(event_list, indicator_list)
    assessments = _connection_target_assessments(event_list, matches)
    return RuntimeAnalysisResult(
        events=tuple(event_list),
        matches=tuple(matches),
        ml_scores={},
        assessments=tuple(assessments),
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
    ml_scores = predict_domain_scores(
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
        ml_scores=ml_scores,
        ml_thresholds=artifact.thresholds,
        behavior_config=behavior_config,
    )

    return RuntimeAnalysisResult(
        events=tuple(event_list),
        matches=tuple(matches),
        ml_scores=ml_scores,
        assessments=tuple(assessments),
    )


def analyze_dns_upload_with_diagnostics(
    content: bytes,
    filename: str | None,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics, DNSInputDetection]:
    """Auto-detect uploaded DNS telemetry and run the local analysis pipeline."""
    parsed, detection = parse_dns_upload_with_diagnostics(content, filename)
    if detection.analysis_mode == "connection":
        result = analyze_connection_events(parsed.events, indicators)
    else:
        result = analyze_dns_events(
            parsed.events,
            indicators,
            artifact,
            behavior_config=behavior_config,
        )
    return result, parsed.diagnostics, detection


def analyze_adguard_query_log_with_diagnostics(
    content: str,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics]:
    """Parse an AdGuard Home query log and analyze it locally."""
    parsed = parse_adguard_query_log_with_diagnostics(content)
    result = analyze_dns_events(
        parsed.events,
        indicators,
        artifact,
        behavior_config=behavior_config,
    )
    return result, parsed.diagnostics


def analyze_dns_csv_with_diagnostics(
    content: str,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics]:
    """Parse DNS CSV text, preserve input-quality diagnostics, and analyze it."""
    parsed = parse_dns_csv_with_diagnostics(content)
    result = analyze_dns_events(
        parsed.events,
        indicators,
        artifact,
        behavior_config=behavior_config,
    )
    return result, parsed.diagnostics


def analyze_pihole_query_db_with_diagnostics(
    content: bytes,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics]:
    """Parse an uploaded Pi-hole FTL query database and analyze it."""
    parsed = parse_pihole_query_db_with_diagnostics(content)
    result = analyze_dns_events(
        parsed.events,
        indicators,
        artifact,
        behavior_config=behavior_config,
    )
    return result, parsed.diagnostics


def analyze_zeek_dns_log_with_diagnostics(
    content: str,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics]:
    """Parse Zeek dns.log text, preserve diagnostics, and analyze it."""
    parsed = parse_zeek_dns_log_with_diagnostics(content)
    result = analyze_dns_events(
        parsed.events,
        indicators,
        artifact,
        behavior_config=behavior_config,
    )
    return result, parsed.diagnostics


def analyze_dns_csv(
    content: str,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> RuntimeAnalysisResult:
    """Parse DNS CSV text and run the local runtime analysis pipeline."""
    result, _ = analyze_dns_csv_with_diagnostics(
        content,
        indicators,
        artifact,
        behavior_config=behavior_config,
    )
    return result
