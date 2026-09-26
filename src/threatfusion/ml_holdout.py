from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from .ml_artifact import TrainedMLArtifact
from .ml_dataset import DomainSample, normalize_domain_candidate
from .ml_high_recall import ThresholdMetrics, calculate_threshold_metrics
from .normalization import normalize_domain_name


@dataclass(frozen=True)
class HoldoutPreparation:
    samples: tuple[DomainSample, ...]
    input_count: int
    overlap_removed: int
    malicious_first_seen_after: str | None = None
    malicious_missing_first_seen_removed: int = 0
    malicious_not_after_cutoff_removed: int = 0


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
class HoldoutSourceMetrics:
    source: str
    malicious_total: int
    benign_total: int
    high_detected: int
    high_false_positive: int
    medium_detected: int
    medium_false_positive: int
    low_detected: int
    low_false_positive: int


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
    source_metrics: tuple[HoldoutSourceMetrics, ...] = ()
    malicious_first_seen_after: str | None = None
    malicious_missing_first_seen_removed: int = 0
    malicious_not_after_cutoff_removed: int = 0


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


def _development_overlap_key(value: str) -> str | None:
    """Canonicalize legacy development rows without reapplying ML eligibility."""
    if not isinstance(value, str):
        return None

    normalized = normalize_domain_name(value, strict=False)
    return normalized or None


def prepare_disjoint_holdout(
    development_samples: Sequence[DomainSample],
    holdout_samples: Sequence[DomainSample],
    *,
    malicious_first_seen_after: date | None = None,
) -> HoldoutPreparation:
    """Remove every canonical domain seen in development from the holdout.

    Historical development snapshots may contain rows that predate the current
    strict ML-eligibility rules. Those rows still belong to the development
    evidence set, so overlap bookkeeping uses stable non-strict canonicalization
    for development only. Holdout rows remain subject to current strict
    validation before they can be evaluated.
    """
    development_domains: set[str] = set()
    for sample in development_samples:
        normalized = _development_overlap_key(sample.domain)
        if normalized is not None:
            development_domains.add(normalized)

    retained: dict[str, DomainSample] = {}
    overlap_removed = 0
    malicious_missing_first_seen_removed = 0
    malicious_not_after_cutoff_removed = 0

    for sample in holdout_samples:
        normalized = normalize_domain_candidate(sample.domain)
        if normalized is None:
            raise ValueError("holdout snapshot contains an invalid domain")
        if sample.label not in {0, 1}:
            raise ValueError("holdout labels must be 0 or 1")

        if normalized in development_domains:
            overlap_removed += 1
            continue

        if sample.label == 1 and malicious_first_seen_after is not None:
            if sample.first_seen is None:
                malicious_missing_first_seen_removed += 1
                continue
            if sample.first_seen.date() <= malicious_first_seen_after:
                malicious_not_after_cutoff_removed += 1
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
            first_seen=sample.first_seen,
            last_seen=sample.last_seen,
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
        malicious_first_seen_after=(
            malicious_first_seen_after.isoformat()
            if malicious_first_seen_after is not None
            else None
        ),
        malicious_missing_first_seen_removed=(
            malicious_missing_first_seen_removed
        ),
        malicious_not_after_cutoff_removed=(
            malicious_not_after_cutoff_removed
        ),
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


def _source_metrics(
    samples: tuple[DomainSample, ...],
    probabilities: Sequence[float],
    *,
    high_threshold: float,
    medium_threshold: float,
    low_threshold: float,
) -> tuple[HoldoutSourceMetrics, ...]:
    by_source: dict[str, list[tuple[int, float]]] = {}

    for sample, probability in zip(samples, probabilities, strict=True):
        by_source.setdefault(sample.source, []).append(
            (sample.label, float(probability))
        )

    results: list[HoldoutSourceMetrics] = []
    for source in sorted(by_source):
        values = by_source[source]
        malicious = [probability for label, probability in values if label == 1]
        benign = [probability for label, probability in values if label == 0]

        results.append(
            HoldoutSourceMetrics(
                source=source,
                malicious_total=len(malicious),
                benign_total=len(benign),
                high_detected=sum(
                    value >= high_threshold for value in malicious
                ),
                high_false_positive=sum(
                    value >= high_threshold for value in benign
                ),
                medium_detected=sum(
                    value >= medium_threshold for value in malicious
                ),
                medium_false_positive=sum(
                    value >= medium_threshold for value in benign
                ),
                low_detected=sum(
                    value >= low_threshold for value in malicious
                ),
                low_false_positive=sum(
                    value >= low_threshold for value in benign
                ),
            )
        )

    return tuple(results)


def evaluate_frozen_artifact_on_holdout(
    artifact: TrainedMLArtifact,
    development_samples: Sequence[DomainSample],
    holdout_samples: Sequence[DomainSample],
    *,
    malicious_first_seen_after: date | None = None,
) -> FrozenHoldoutEvaluation:
    """Evaluate a frozen artifact and frozen thresholds on a disjoint holdout."""
    prepared = prepare_disjoint_holdout(
        development_samples,
        holdout_samples,
        malicious_first_seen_after=malicious_first_seen_after,
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
        source_metrics=_source_metrics(
            prepared.samples,
            probabilities,
            high_threshold=artifact.thresholds.high_confidence,
            medium_threshold=artifact.thresholds.medium_confidence,
            low_threshold=artifact.thresholds.low_confidence,
        ),
        malicious_first_seen_after=prepared.malicious_first_seen_after,
        malicious_missing_first_seen_removed=(
            prepared.malicious_missing_first_seen_removed
        ),
        malicious_not_after_cutoff_removed=(
            prepared.malicious_not_after_cutoff_removed
        ),
    )
