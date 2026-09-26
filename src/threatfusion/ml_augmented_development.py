from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .dns import DNSEvent
from .ml_dataset import DomainSample, normalize_domain_candidate
from .ml_snapshot import (
    DatasetSnapshotMetadata,
    DatasetSnapshotStatistics,
    DomainDatasetSnapshot,
)
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

def build_augmented_development_snapshot(
    base_snapshot: DomainDatasetSnapshot,
    events: Sequence[DNSEvent],
    *,
    source: str = "CESNET",
    source_snapshot_id: str | None = None,
) -> tuple[DomainDatasetSnapshot, AugmentedBenignPreparation]:
    """Build a reproducible derivative development snapshot with added benign data."""
    preparation = prepare_augmented_development_samples(
        base_snapshot.samples,
        events,
        source=source,
    )
    samples = list(preparation.samples)
    final_malicious_count = sum(sample.label == 1 for sample in samples)
    final_benign_count = sum(sample.label == 0 for sample in samples)

    malicious_by_source: dict[str, int] = {}
    for sample in samples:
        if sample.label != 1:
            continue
        malicious_by_source[sample.source] = (
            malicious_by_source.get(sample.source, 0) + 1
        )

    source_id = (source_snapshot_id or source).strip()
    base_id = base_snapshot.metadata.benign_snapshot_id or "base"
    snapshot = DomainDatasetSnapshot(
        samples=samples,
        metadata=DatasetSnapshotMetadata(
            benign_source=f"{base_snapshot.metadata.benign_source}+{source}",
            benign_snapshot_id=f"{base_id}+{source_id}",
            benign_snapshot_date=base_snapshot.metadata.benign_snapshot_date,
        ),
        statistics=DatasetSnapshotStatistics(
            malicious_input_count=base_snapshot.statistics.malicious_input_count,
            benign_input_count=(
                base_snapshot.statistics.benign_input_count
                + preparation.input_event_count
            ),
            malicious_unique_count=final_malicious_count,
            benign_unique_count=final_benign_count,
            final_malicious_count=final_malicious_count,
            final_benign_count=final_benign_count,
            final_total_count=len(samples),
            overlap_removed_from_benign=(
                base_snapshot.statistics.overlap_removed_from_benign
                + preparation.overlap_with_base_removed
            ),
            malicious_by_source=malicious_by_source,
        ),
    )
    return snapshot, preparation

