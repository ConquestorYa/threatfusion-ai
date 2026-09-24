from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Sequence

from .ml_artifact import TrainedMLArtifact
from .ml_dataset import DomainSample, normalize_domain_candidate
from .ml_high_recall import ThresholdMetrics, calculate_threshold_metrics


@dataclass(frozen=True)
class HoldoutPreparation:
    samples: tuple[DomainSample, ...]
    input_count: int
    overlap_removed: int


@dataclass(frozen=True)
class HoldoutSourceRecall:
    source: str
    total: int
    high_detected: int
    high_recall: float
    medium_detected: int
    medium_recall: float
    low_detected: int
    low_recall: float


@dataclass(frozen=True)
class FrozenHoldoutEvaluation:
    input_count: int
    retained_count: int
    overlap_removed: int
    malicious_count: int
    benign_count: int
    high: ThresholdMetrics
    medium: ThresholdMetrics
    low: ThresholdMetrics
    source_recalls: tuple[HoldoutSourceRecall, ...]


def validate_fresh_snapshot_dates(
    development_date: str | None,
    holdout_date: str | None,
) -> None:
    """Require an explicitly later benign snapshot date for final evaluation."""
    if development_date is None or holdout_date is None:
        raise ValueError(
            "development and holdout snapshots require benign snapshot dates"
        )

    try:
        development = date.fromisoformat(development_date)
        holdout = date.fromisoformat(holdout_date)
    except ValueError as error:
        raise ValueError("snapshot dates must use ISO YYYY-MM-DD format") from error

    if holdout <= development:
        raise ValueError(
            "holdout benign snapshot date must be later than development date"
        )


def prepare_disjoint_holdout(
    development_samples: Sequence[DomainSample],
    holdout_samples: Sequence[DomainSample],
) -> HoldoutPreparation:
    """Remove every normalized domain seen in development from the holdout."""
    development_domains: set[str] = set()
    for sample in development_samples:
        normalized = normalize_domain_candidate(sample.domain)
        if normalized is None:
            raise ValueError("development snapshot contains an invalid domain")
        development_domains.add(normalized)

    retained: dict[str, DomainSample] = {}
    overlap_removed = 0

    for sample in holdout_samples:
        normalized = normalize_domain_candidate(sample.domain)
        if normalized is None:
            raise ValueError("holdout snapshot contains an invalid domain")
        if sample.label not in {0, 1}:
            raise ValueError("holdout labels must be 0 or 1")

        if normalized in development_domains:
            overlap_removed += 1
            continue

        existing = retained.get(normalized)
        if existing is not None:
            if existing.label != sample.label:
                raise ValueError("holdout contains conflicting labels")
            continue

        retained[normalized] = DomainSample(
            domain=normalized,
            label=sample.label,
            source=sample.source,
        )

    samples = tuple(retained.values())
    labels = {sample.label for sample in samples}
    if labels != {0, 1}:
        raise ValueError(
            "disjoint holdout must retain both malicious and benign samples"
        )

    return HoldoutPreparation(
        samples=samples,
        input_count=len(holdout_samples),
        overlap_removed=overlap_removed,
    )


def _positive_probabilities(
    artifact: TrainedMLArtifact,
    samples: tuple[DomainSample, ...],
) -> list[float]:
    probabilities = artifact.model.predict_proba(
        [sample.domain for sample in samples]
    )
    classes = list(artifact.model.classes_)
    positive_index = classes.index(1)
    return [float(row[positive_index]) for row in probabilities]


def _source_recalls(
    samples: tuple[DomainSample, ...],
    probabilities: Sequence[float],
    *,
    high_threshold: float,
    medium_threshold: float,
    low_threshold: float,
) -> tuple[HoldoutSourceRecall, ...]:
    malicious_by_source: dict[str, list[float]] = {}

    for sample, probability in zip(samples, probabilities, strict=True):
        if sample.label != 1:
            continue
        malicious_by_source.setdefault(sample.source, []).append(
            float(probability)
        )

    results: list[HoldoutSourceRecall] = []
    for source in sorted(malicious_by_source):
        values = malicious_by_source[source]
        total = len(values)
        high_detected = sum(value >= high_threshold for value in values)
        medium_detected = sum(value >= medium_threshold for value in values)
        low_detected = sum(value >= low_threshold for value in values)

        results.append(
            HoldoutSourceRecall(
                source=source,
                total=total,
                high_detected=high_detected,
                high_recall=high_detected / total,
                medium_detected=medium_detected,
                medium_recall=medium_detected / total,
                low_detected=low_detected,
                low_recall=low_detected / total,
            )
        )

    return tuple(results)


def evaluate_frozen_artifact_on_holdout(
    artifact: TrainedMLArtifact,
    development_samples: Sequence[DomainSample],
    holdout_samples: Sequence[DomainSample],
) -> FrozenHoldoutEvaluation:
    """Evaluate a frozen artifact and frozen thresholds on a disjoint holdout."""
    prepared = prepare_disjoint_holdout(
        development_samples,
        holdout_samples,
    )
    labels = [sample.label for sample in prepared.samples]
    probabilities = _positive_probabilities(artifact, prepared.samples)

    high = calculate_threshold_metrics(
        labels,
        probabilities,
        threshold=artifact.thresholds.high_confidence,
    )
    medium = calculate_threshold_metrics(
        labels,
        probabilities,
        threshold=artifact.thresholds.medium_confidence,
    )
    low = calculate_threshold_metrics(
        labels,
        probabilities,
        threshold=artifact.thresholds.low_confidence,
    )

    malicious_count = sum(sample.label == 1 for sample in prepared.samples)
    benign_count = len(prepared.samples) - malicious_count

    return FrozenHoldoutEvaluation(
        input_count=prepared.input_count,
        retained_count=len(prepared.samples),
        overlap_removed=prepared.overlap_removed,
        malicious_count=malicious_count,
        benign_count=benign_count,
        high=high,
        medium=medium,
        low=low,
        source_recalls=_source_recalls(
            prepared.samples,
            probabilities,
            high_threshold=artifact.thresholds.high_confidence,
            medium_threshold=artifact.thresholds.medium_confidence,
            low_threshold=artifact.thresholds.low_confidence,
        ),
    )
