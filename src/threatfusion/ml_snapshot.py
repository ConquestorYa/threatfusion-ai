from __future__ import annotations

import csv
from collections.abc import Iterable
from dataclasses import dataclass
from io import StringIO

from .ml_dataset import (
    DomainSample,
    build_benign_samples,
    build_domain_dataset,
    extract_malicious_domains,
)
from .models import IOCRecord


@dataclass(frozen=True)
class DatasetSnapshotMetadata:
    benign_source: str
    benign_snapshot_id: str | None = None
    benign_snapshot_date: str | None = None


@dataclass(frozen=True)
class DatasetSnapshotStatistics:
    malicious_input_count: int
    benign_input_count: int
    malicious_unique_count: int
    benign_unique_count: int
    final_malicious_count: int
    final_benign_count: int
    final_total_count: int
    overlap_removed_from_benign: int
    malicious_by_source: dict[str, int]


@dataclass(frozen=True)
class DomainDatasetSnapshot:
    samples: list[DomainSample]
    metadata: DatasetSnapshotMetadata
    statistics: DatasetSnapshotStatistics


def _validate_limit(limit: int | None) -> None:
    if limit is None:
        return
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")


def parse_tranco_csv(content: str, limit: int | None = None) -> list[str]:
    """Parse caller-supplied rank/domain CSV text without external access."""
    _validate_limit(limit)

    domains: list[str] = []
    for row in csv.reader(StringIO(content)):
        if len(row) < 2:
            continue

        rank = row[0].strip()
        domain = row[1].strip()
        if not rank or not rank.isdigit() or int(rank) < 1 or not domain:
            continue

        domains.append(domain)
        if limit is not None and len(domains) >= limit:
            break

    return domains


def _count_malicious_by_source(samples: Iterable[DomainSample]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sample in samples:
        if sample.label != 1:
            continue
        counts[sample.source] = counts.get(sample.source, 0) + 1
    return counts


def build_domain_snapshot(
    indicators: Iterable[IOCRecord],
    benign_domains: Iterable[str],
    *,
    benign_source: str = "Tranco",
    benign_snapshot_id: str | None = None,
    benign_snapshot_date: str | None = None,
) -> DomainDatasetSnapshot:
    """Assemble an in-memory, reproducible labeled domain snapshot."""
    indicator_values = list(indicators)
    benign_values = list(benign_domains)

    malicious_candidates = extract_malicious_domains(indicator_values)
    benign_samples = build_benign_samples(benign_values, source=benign_source)
    unique_malicious_samples = build_domain_dataset(malicious_candidates, [])
    final_samples = build_domain_dataset(malicious_candidates, benign_samples)

    final_malicious_count = sum(sample.label == 1 for sample in final_samples)
    final_benign_count = sum(sample.label == 0 for sample in final_samples)
    statistics = DatasetSnapshotStatistics(
        malicious_input_count=len(malicious_candidates),
        benign_input_count=len(benign_values),
        malicious_unique_count=len(unique_malicious_samples),
        benign_unique_count=len(benign_samples),
        final_malicious_count=final_malicious_count,
        final_benign_count=final_benign_count,
        final_total_count=len(final_samples),
        overlap_removed_from_benign=len(benign_samples) - final_benign_count,
        malicious_by_source=_count_malicious_by_source(final_samples),
    )

    return DomainDatasetSnapshot(
        samples=final_samples,
        metadata=DatasetSnapshotMetadata(
            benign_source=benign_source,
            benign_snapshot_id=benign_snapshot_id,
            benign_snapshot_date=benign_snapshot_date,
        ),
        statistics=statistics,
    )
