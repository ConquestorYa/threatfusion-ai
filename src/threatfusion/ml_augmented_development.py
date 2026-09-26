from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .dns import DNSEvent
from .ml_dataset import DomainSample, normalize_domain_candidate
from .normalization import normalize_domain_name
from .runtime_analysis import is_ml_scoring_candidate


@dataclass(frozen=True)
class AugmentedBenignPreparation:
    input_event_count: int
    public_candidate_event_count: int
    unique_candidate_count: int
    overlap_with_base_removed: int
    added_benign_count: int
    samples: tuple[DomainSample, ...]


@dataclass(frozen=True)
class BenignSourceFPR:
    source: str
    total: int
    false_positive: int
    true_negative: int
    false_positive_rate: float


def prepare_augmented_development_samples(
    base_samples: Sequence[DomainSample],
    events: Sequence[DNSEvent],
    *,
    source: str = "CESNET",
) -> AugmentedBenignPreparation:
    """Add new confirmed-benign domains to an existing development dataset."""
    source_name = source.strip()
    if not source_name:
        raise ValueError("benign source name must not be empty")

    base_domains: set[str] = set()
    for sample in base_samples:
        normalized = normalize_domain_name(sample.domain, strict=False)
        if normalized:
            base_domains.add(normalized)

    seen_candidates: set[str] = set()
    added: list[DomainSample] = []
    public_candidate_event_count = 0
    overlap_with_base_removed = 0

    for event in events:
        normalized = normalize_domain_candidate(event.query_name)
        if normalized is None or not is_ml_scoring_candidate(normalized):
            continue

        public_candidate_event_count += 1
        if normalized in seen_candidates:
            continue
        seen_candidates.add(normalized)

        if normalized in base_domains:
            overlap_with_base_removed += 1
            continue

        added.append(
            DomainSample(
                domain=normalized,
                label=0,
                source=source_name,
            )
        )

    if not added:
        raise ValueError(
            "confirmed-benign augmentation added no new public domains"
        )

    return AugmentedBenignPreparation(
        input_event_count=len(events),
        public_candidate_event_count=public_candidate_event_count,
        unique_candidate_count=len(seen_candidates),
        overlap_with_base_removed=overlap_with_base_removed,
        added_benign_count=len(added),
        samples=tuple([*base_samples, *added]),
    )


def calculate_benign_source_fpr(
    samples: Sequence[DomainSample],
    predictions: Sequence[int],
) -> tuple[BenignSourceFPR, ...]:
    """Calculate false-positive rate separately for each benign source."""
    if len(samples) != len(predictions):
        raise ValueError("samples and predictions must have the same length")
    if any(prediction not in {0, 1} for prediction in predictions):
        raise ValueError("predictions must contain only 0 or 1")

    totals: dict[str, int] = {}
    false_positives: dict[str, int] = {}

    for sample, prediction in zip(samples, predictions, strict=True):
        if sample.label != 0:
            continue
        totals[sample.source] = totals.get(sample.source, 0) + 1
        if prediction == 1:
            false_positives[sample.source] = (
                false_positives.get(sample.source, 0) + 1
            )

    return tuple(
        BenignSourceFPR(
            source=source,
            total=totals[source],
            false_positive=false_positives.get(source, 0),
            true_negative=totals[source] - false_positives.get(source, 0),
            false_positive_rate=false_positives.get(source, 0) / totals[source],
        )
        for source in sorted(totals)
    )
