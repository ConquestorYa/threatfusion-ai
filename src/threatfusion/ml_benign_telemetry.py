from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .dns import DNSEvent
from .ml_artifact import TrainedMLArtifact, predict_domain_scores
from .ml_dataset import DomainSample, normalize_domain_candidate
from .normalization import normalize_domain_name
from .runtime_analysis import is_ml_scoring_candidate

_SCHEMA_VERSION = 1
_PROTOCOL = "confirmed_benign_dns_telemetry"
_WILSON_Z_95 = 1.959963984540054


@dataclass(frozen=True)
class BenignRateInterval:
    lower: float
    upper: float
    confidence_level: float = 0.95


@dataclass(frozen=True)
class BenignOperatingPoint:
    threshold: float
    false_positive_count: int
    benign_count: int
    false_positive_rate: float
    false_positive_rate_ci: BenignRateInterval


@dataclass(frozen=True)
class BenignTelemetryPreparation:
    input_event_count: int
    public_candidate_event_count: int
    unique_candidate_count: int
    development_overlap_removed: int
    retained_domains: tuple[str, ...]


@dataclass(frozen=True)
class BenignTelemetryEvaluation:
    preparation: BenignTelemetryPreparation
    high: BenignOperatingPoint
    medium: BenignOperatingPoint
    low: BenignOperatingPoint


@dataclass(frozen=True)
class BenignTelemetryReport:
    schema_version: int
    protocol: str
    generated_at: str
    model_name: str
    artifact_checksum: str
    input_format: str
    label_basis: str
    input_event_count: int
    public_candidate_event_count: int
    unique_candidate_count: int
    development_overlap_removed: int
    retained_benign_count: int
    high: BenignOperatingPoint
    medium: BenignOperatingPoint
    low: BenignOperatingPoint


def _wilson_interval(successes: int, total: int) -> BenignRateInterval:
    if total <= 0:
        raise ValueError("benign evaluation requires at least one retained domain")
    if successes < 0 or successes > total:
        raise ValueError("successes must be between zero and total")

    proportion = successes / total
    z_squared = _WILSON_Z_95**2
    denominator = 1.0 + z_squared / total
    center = (proportion + z_squared / (2.0 * total)) / denominator
    margin = (
        _WILSON_Z_95
        * math.sqrt(
            (
                proportion * (1.0 - proportion)
                + z_squared / (4.0 * total)
            )
            / total
        )
        / denominator
    )
    return BenignRateInterval(
        lower=max(0.0, center - margin),
        upper=min(1.0, center + margin),
    )


def _development_domain_set(
    development_samples: Sequence[DomainSample],
) -> set[str]:
    domains: set[str] = set()
    for sample in development_samples:
        normalized = normalize_domain_name(sample.domain, strict=False)
        if normalized:
            domains.add(normalized)
    return domains


def prepare_benign_telemetry(
    events: Sequence[DNSEvent],
    development_samples: Sequence[DomainSample],
) -> BenignTelemetryPreparation:
    """Prepare unique public domains from operator-confirmed benign telemetry."""
    development_domains = _development_domain_set(development_samples)
    seen_candidates: set[str] = set()
    retained: list[str] = []
    public_candidate_event_count = 0
    development_overlap_removed = 0

    for event in events:
        normalized = normalize_domain_candidate(event.query_name)
        if normalized is None or not is_ml_scoring_candidate(normalized):
            continue

        public_candidate_event_count += 1
        if normalized in seen_candidates:
            continue
        seen_candidates.add(normalized)

        if normalized in development_domains:
            development_overlap_removed += 1
            continue
        retained.append(normalized)

    if not retained:
        raise ValueError(
            "benign telemetry has no retained public domains after filtering "
            "and development-overlap removal"
        )

    return BenignTelemetryPreparation(
        input_event_count=len(events),
        public_candidate_event_count=public_candidate_event_count,
        unique_candidate_count=len(seen_candidates),
        development_overlap_removed=development_overlap_removed,
        retained_domains=tuple(retained),
    )


def _operating_point(
    scores: Sequence[float],
    *,
    threshold: float,
) -> BenignOperatingPoint:
    total = len(scores)
    false_positive_count = sum(score >= threshold for score in scores)
    return BenignOperatingPoint(
        threshold=float(threshold),
        false_positive_count=false_positive_count,
        benign_count=total,
        false_positive_rate=false_positive_count / total,
        false_positive_rate_ci=_wilson_interval(false_positive_count, total),
    )


def evaluate_benign_thresholds(
    artifact: TrainedMLArtifact,
    development_samples: Sequence[DomainSample],
    events: Sequence[DNSEvent],
    *,
    thresholds: Sequence[float],
) -> tuple[BenignTelemetryPreparation, tuple[BenignOperatingPoint, ...]]:
    """Measure arbitrary diagnostic thresholds on confirmed-benign telemetry."""
    if not thresholds:
        raise ValueError("at least one diagnostic threshold is required")

    normalized_thresholds: list[float] = []
    for threshold in thresholds:
        value = float(threshold)
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError("diagnostic thresholds must be finite values between 0 and 1")
        normalized_thresholds.append(value)

    preparation = prepare_benign_telemetry(events, development_samples)
    score_by_domain = predict_domain_scores(
        artifact,
        preparation.retained_domains,
    )
    if len(score_by_domain) != len(preparation.retained_domains):
        raise ValueError("ML scoring did not return every retained benign domain")

    scores = [score_by_domain[domain] for domain in preparation.retained_domains]
    points = tuple(
        _operating_point(scores, threshold=threshold)
        for threshold in normalized_thresholds
    )
    return preparation, points


def evaluate_benign_telemetry(
    artifact: TrainedMLArtifact,
    development_samples: Sequence[DomainSample],
    events: Sequence[DNSEvent],
) -> BenignTelemetryEvaluation:
    """Measure frozen-threshold false positives on confirmed-benign telemetry."""
    preparation, points = evaluate_benign_thresholds(
        artifact,
        development_samples,
        events,
        thresholds=(
            artifact.thresholds.high_confidence,
            artifact.thresholds.medium_confidence,
            artifact.thresholds.low_confidence,
        ),
    )
    high, medium, low = points
    return BenignTelemetryEvaluation(
        preparation=preparation,
        high=high,
        medium=medium,
        low=low,
    )


def build_benign_telemetry_report(
    evaluation: BenignTelemetryEvaluation,
    *,
    model_name: str,
    artifact_checksum: str,
    input_format: str,
    generated_at: datetime | None = None,
) -> BenignTelemetryReport:
    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    checksum = artifact_checksum.strip().lower()
    if len(checksum) != 64 or any(ch not in "0123456789abcdef" for ch in checksum):
        raise ValueError("artifact checksum must be a SHA-256 hex digest")

    preparation = evaluation.preparation
    return BenignTelemetryReport(
        schema_version=_SCHEMA_VERSION,
        protocol=_PROTOCOL,
        generated_at=timestamp.astimezone(timezone.utc).isoformat(),
        model_name=model_name,
        artifact_checksum=checksum,
        input_format=input_format,
        label_basis="operator_confirmed_benign",
        input_event_count=preparation.input_event_count,
        public_candidate_event_count=preparation.public_candidate_event_count,
        unique_candidate_count=preparation.unique_candidate_count,
        development_overlap_removed=preparation.development_overlap_removed,
        retained_benign_count=len(preparation.retained_domains),
        high=evaluation.high,
        medium=evaluation.medium,
        low=evaluation.low,
    )


def write_benign_telemetry_report(
    report: BenignTelemetryReport,
    path: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Persist aggregate-only benign telemetry metrics."""
    output = Path(path)
    if output.exists() and not overwrite:
        raise FileExistsError(
            "benign telemetry report already exists; use overwrite=True to replace it"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(asdict(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output
