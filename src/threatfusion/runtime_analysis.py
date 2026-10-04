from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .dns import DNSEvent, DNSParseDiagnostics, parse_dns_csv_with_diagnostics
from .device_triage import DeviceFinding, build_device_findings
from .connections import ConnectionFinding, ConnectionRecord, analyze_connections
from .connection_timeline import ConnectionTimeline, build_timelines
from .network_telemetry import parse_zeek_conn_log_with_diagnostics
from .dns_ingest import DNSInputDetection, parse_dns_upload_with_diagnostics
from .dns_adguard import parse_adguard_query_log_with_diagnostics
from .dns_pihole import parse_pihole_query_db_with_diagnostics
from .dns_zeek import parse_zeek_dns_log_with_diagnostics
from .hybrid_assessment import (
    BehaviorHeuristicConfig,
    HybridAssessment,
    assess_dns_domains,
)
from .matching import DNSIOCMatch, match_dns_events
from .ml_artifact import TrainedMLArtifact, predict_domain_scores
from .ml_dataset import normalize_domain_candidate
from .models import IOCRecord

MAX_DNS_EVENTS = 100_000
MAX_UNIQUE_QUERY_NAMES = 25_000
MAX_QUERY_NAME_CHARS = 1_024
MAX_EVENT_METADATA_CHARS = 4_096

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
    device_findings: tuple[DeviceFinding, ...] = ()
    connection_findings: tuple[ConnectionFinding, ...] = ()
    connection_timelines: tuple[ConnectionTimeline, ...] = ()

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
        raise ValueError(f"DNS input exceeds the {MAX_DNS_EVENTS} event analysis limit")

    for event in events:
        if not isinstance(event.query_name, str):
            raise ValueError("DNS query name must be text")
        if len(event.query_name) > MAX_QUERY_NAME_CHARS:
            raise ValueError("DNS query name exceeds the safe analysis length limit")

        for field_name, value in (
            ("client_ip", event.client_ip),
            ("query_type", event.query_type),
            ("response_ip", event.response_ip),
            ("response_code", event.response_code),
        ):
            if value is None:
                continue
            if not isinstance(value, str):
                raise ValueError(f"DNS {field_name} value must be text")
            if len(value) > MAX_EVENT_METADATA_CHARS:
                raise ValueError(
                    f"DNS {field_name} exceeds the safe analysis length limit"
                )

    unique_names = {
        event.query_name.strip().casefold().removesuffix(".")
        for event in events
        if event.query_name.strip()
    }
    if len(unique_names) > MAX_UNIQUE_QUERY_NAMES:
        raise ValueError(
            "DNS input exceeds the "
            f"{MAX_UNIQUE_QUERY_NAMES} unique-query analysis limit"
        )


def analyze_dns_events(
    events: Iterable[DNSEvent],
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact | None,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
    connections: Iterable[ConnectionRecord] = (),
) -> RuntimeAnalysisResult:
    """Run the local ThreatFusion analysis pipeline over DNS events.

    This function performs no network activity. IOC values remain inert data;
    matching, ML inference, behavior aggregation, and hybrid assessment all
    operate on already-loaded local objects.
    """
    event_list = list(events)
    indicator_list = list(indicators)
    _validate_runtime_bounds(event_list)
    connection_list = tuple(connections)
    if len(connection_list) > MAX_DNS_EVENTS:
        raise ValueError("Connection input exceeds the event analysis limit")

    matches = match_dns_events(event_list, indicator_list)
    ml_scores = (
        predict_domain_scores(
            artifact,
            [
                event.query_name
                for event in event_list
                if is_ml_scoring_candidate(event.query_name)
            ],
        )
        if artifact is not None
        else {}
    )
    assessments = assess_dns_domains(
        event_list,
        matches,
        ml_scores=ml_scores if artifact is not None else None,
        ml_thresholds=artifact.thresholds if artifact is not None else None,
        behavior_config=behavior_config,
    )

    connection_findings = analyze_connections(connection_list)
    return RuntimeAnalysisResult(
        events=tuple(event_list),
        matches=tuple(matches),
        ml_scores=ml_scores,
        assessments=tuple(assessments),
        device_findings=build_device_findings(
            event_list, matches,
            ml_scores=ml_scores if artifact is not None else None,
            ml_thresholds=artifact.thresholds if artifact is not None else None,
            behavior_config=behavior_config,
        ),
        connection_findings=connection_findings,
        connection_timelines=build_timelines(connection_list, connection_findings),
    )


def analyze_dns_upload_with_diagnostics(
    content: bytes,
    filename: str | None,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact | None,
    *,
    behavior_config: BehaviorHeuristicConfig | None = None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics, DNSInputDetection]:
    """Auto-detect uploaded DNS telemetry and run the local analysis pipeline."""
    parsed, detection = parse_dns_upload_with_diagnostics(content, filename)
    result = analyze_dns_events(
        parsed.events,
        indicators,
        artifact,
        behavior_config=behavior_config,
        connections=parsed.connections,
    )
    return result, parsed.diagnostics, detection


def analyze_zeek_conn_log_with_diagnostics(
    content: str, indicators: Iterable[IOCRecord], artifact: TrainedMLArtifact | None,
) -> tuple[RuntimeAnalysisResult, DNSParseDiagnostics]:
    parsed = parse_zeek_conn_log_with_diagnostics(content)
    result = analyze_dns_events(
        parsed.events, indicators, artifact, connections=parsed.connections,
    )
    return result, parsed.diagnostics


def analyze_adguard_query_log_with_diagnostics(
    content: str,
    indicators: Iterable[IOCRecord],
    artifact: TrainedMLArtifact | None,
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
    artifact: TrainedMLArtifact | None,
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
    artifact: TrainedMLArtifact | None,
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
    artifact: TrainedMLArtifact | None,
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
    artifact: TrainedMLArtifact | None,
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
