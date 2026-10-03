from __future__ import annotations

import csv
import json
from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .ml_dataset import DomainSample
from .ml_snapshot import (
    DatasetSnapshotMetadata,
    DatasetSnapshotStatistics,
    DomainDatasetSnapshot,
)

_DATASET_FILENAME = "dataset.csv"
_METADATA_FILENAME = "metadata.json"
_REQUIRED_DATASET_COLUMNS = {"domain", "label", "source"}
_DATASET_COLUMNS = ["domain", "label", "source", "first_seen", "last_seen"]
_METADATA_FIELDS = {"benign_source", "benign_snapshot_id", "benign_snapshot_date"}
_STATISTICS_FIELDS = {
    "malicious_input_count",
    "benign_input_count",
    "malicious_unique_count",
    "benign_unique_count",
    "final_malicious_count",
    "final_benign_count",
    "final_total_count",
    "overlap_removed_from_benign",
    "malicious_by_source",
}
_SECRET_FIELD_MARKERS = ("api_key", "auth_key", "password", "secret", "token")


def _json_metadata(
    snapshot: DomainDatasetSnapshot,
    experiment_metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if experiment_metadata is not None:
        if not isinstance(experiment_metadata, Mapping):
            raise ValueError("experiment_metadata must be a JSON object")
        for key in experiment_metadata:
            if not isinstance(key, str):
                raise ValueError(  # noqa: TRY004
                    "experiment_metadata keys must be strings"
                )
            if any(marker in key.casefold() for marker in _SECRET_FIELD_MARKERS):
                raise ValueError("experiment_metadata cannot contain secret fields")

    payload = {
        "metadata": asdict(snapshot.metadata),
        "statistics": asdict(snapshot.statistics),
        "experiment_metadata": dict(experiment_metadata or {}),
    }
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as error:
        raise ValueError("experiment_metadata must be JSON-serializable") from error
    return payload


def write_domain_snapshot(
    snapshot: DomainDatasetSnapshot,
    output_dir: Path,
    experiment_metadata: Mapping[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Write the exact in-memory snapshot to deterministic local files."""
    output_path = Path(output_dir)
    dataset_path = output_path / _DATASET_FILENAME
    metadata_path = output_path / _METADATA_FILENAME
    metadata_payload = _json_metadata(snapshot, experiment_metadata)

    output_path.mkdir(parents=True, exist_ok=True)
    with dataset_path.open("w", encoding="utf-8", newline="") as dataset_file:
        writer = csv.DictWriter(dataset_file, fieldnames=_DATASET_COLUMNS)
        writer.writeheader()
        for sample in snapshot.samples:
            writer.writerow(
                {
                    "domain": sample.domain,
                    "label": sample.label,
                    "source": sample.source,
                    "first_seen": (
                        sample.first_seen.isoformat()
                        if sample.first_seen is not None
                        else ""
                    ),
                    "last_seen": (
                        sample.last_seen.isoformat()
                        if sample.last_seen is not None
                        else ""
                    ),
                }
            )

    with metadata_path.open("w", encoding="utf-8") as metadata_file:
        json.dump(metadata_payload, metadata_file, ensure_ascii=False, indent=2)
        metadata_file.write("\n")

    return dataset_path, metadata_path


def _load_metadata(metadata_path: Path) -> dict[str, Any]:
    try:
        with metadata_path.open("r", encoding="utf-8") as metadata_file:
            payload = json.load(metadata_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("metadata.json is not valid JSON") from error

    if not isinstance(payload, dict):
        raise ValueError(  # noqa: TRY004
            "metadata.json must contain a JSON object"
        )
    return payload


def _require_mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(  # noqa: TRY004
            f"metadata.json requires an object named {key}"
        )
    return value


def _parse_metadata(payload: dict[str, Any]) -> DatasetSnapshotMetadata:
    metadata = _require_mapping(payload, "metadata")
    if not _METADATA_FIELDS.issubset(metadata):
        raise ValueError("metadata.json is missing required snapshot metadata")

    benign_source = metadata["benign_source"]
    snapshot_id = metadata["benign_snapshot_id"]
    snapshot_date = metadata["benign_snapshot_date"]
    if not isinstance(benign_source, str):
        raise ValueError(  # noqa: TRY004
            "metadata.json benign_source must be a string"
        )
    if snapshot_id is not None and not isinstance(snapshot_id, str):
        raise ValueError("metadata.json benign_snapshot_id must be a string or null")
    if snapshot_date is not None and not isinstance(snapshot_date, str):
        raise ValueError("metadata.json benign_snapshot_date must be a string or null")

    return DatasetSnapshotMetadata(
        benign_source=benign_source,
        benign_snapshot_id=snapshot_id,
        benign_snapshot_date=snapshot_date,
    )


def _parse_nonnegative_int(statistics: dict[str, Any], key: str) -> int:
    value = statistics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"metadata.json statistic {key} must be a non-negative integer")
    return value


def _parse_statistics(payload: dict[str, Any]) -> DatasetSnapshotStatistics:
    statistics = _require_mapping(payload, "statistics")
    if not _STATISTICS_FIELDS.issubset(statistics):
        raise ValueError("metadata.json is missing required snapshot statistics")

    source_counts = statistics["malicious_by_source"]
    if not isinstance(source_counts, dict):
        raise ValueError(  # noqa: TRY004
            "metadata.json malicious_by_source must be an object"
        )
    parsed_source_counts: dict[str, int] = {}
    for source, count in source_counts.items():
        if not isinstance(source, str) or isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("metadata.json malicious_by_source has invalid counts")
        parsed_source_counts[source] = count

    return DatasetSnapshotStatistics(
        malicious_input_count=_parse_nonnegative_int(statistics, "malicious_input_count"),
        benign_input_count=_parse_nonnegative_int(statistics, "benign_input_count"),
        malicious_unique_count=_parse_nonnegative_int(statistics, "malicious_unique_count"),
        benign_unique_count=_parse_nonnegative_int(statistics, "benign_unique_count"),
        final_malicious_count=_parse_nonnegative_int(statistics, "final_malicious_count"),
        final_benign_count=_parse_nonnegative_int(statistics, "final_benign_count"),
        final_total_count=_parse_nonnegative_int(statistics, "final_total_count"),
        overlap_removed_from_benign=_parse_nonnegative_int(
            statistics, "overlap_removed_from_benign"
        ),
        malicious_by_source=parsed_source_counts,
    )


def _parse_optional_timestamp(value: str | None, field: str) -> datetime | None:
    if value is None or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"dataset.csv {field} must be an ISO timestamp") from error


def _read_samples(dataset_path: Path) -> list[DomainSample]:
    try:
        with dataset_path.open("r", encoding="utf-8", newline="") as dataset_file:
            reader = csv.DictReader(dataset_file)
            fieldnames = set(reader.fieldnames or [])
            if not _REQUIRED_DATASET_COLUMNS.issubset(fieldnames):
                raise ValueError("dataset.csv is missing required columns")

            samples: list[DomainSample] = []
            for row in reader:
                domain = row.get("domain")
                label = row.get("label")
                source = row.get("source")
                if not isinstance(domain, str) or not isinstance(label, str) or not isinstance(source, str):
                    raise ValueError(  # noqa: TRY004
                        "dataset.csv contains a malformed row"
                    )
                try:
                    parsed_label = int(label)
                except ValueError as error:
                    raise ValueError("dataset.csv labels must be integers 0 or 1") from error
                if parsed_label not in {0, 1}:
                    raise ValueError("dataset.csv labels must be integers 0 or 1")
                samples.append(
                    DomainSample(
                        domain=domain,
                        label=parsed_label,
                        source=source,
                        first_seen=_parse_optional_timestamp(
                            row.get("first_seen"),
                            "first_seen",
                        ),
                        last_seen=_parse_optional_timestamp(
                            row.get("last_seen"),
                            "last_seen",
                        ),
                    )
                )
    except OSError as error:
        raise ValueError("dataset.csv could not be read") from error

    return samples


def _validate_loaded_counts(
    samples: list[DomainSample],
    statistics: DatasetSnapshotStatistics,
) -> None:
    malicious_count = sum(sample.label == 1 for sample in samples)
    benign_count = sum(sample.label == 0 for sample in samples)
    if malicious_count != statistics.final_malicious_count:
        raise ValueError("metadata.json final_malicious_count does not match dataset.csv")
    if benign_count != statistics.final_benign_count:
        raise ValueError("metadata.json final_benign_count does not match dataset.csv")
    if len(samples) != statistics.final_total_count:
        raise ValueError("metadata.json final_total_count does not match dataset.csv")

    source_counts: dict[str, int] = {}
    for sample in samples:
        if sample.label == 1:
            source_counts[sample.source] = source_counts.get(sample.source, 0) + 1
    if source_counts != statistics.malicious_by_source:
        raise ValueError("metadata.json malicious_by_source does not match dataset.csv")


def read_domain_snapshot(output_dir: Path) -> DomainDatasetSnapshot:
    """Read and validate a previously written domain snapshot."""
    output_path = Path(output_dir)
    metadata_payload = _load_metadata(output_path / _METADATA_FILENAME)
    metadata = _parse_metadata(metadata_payload)
    statistics = _parse_statistics(metadata_payload)
    samples = _read_samples(output_path / _DATASET_FILENAME)
    _validate_loaded_counts(samples, statistics)
    return DomainDatasetSnapshot(
        samples=samples,
        metadata=metadata,
        statistics=statistics,
    )


def read_snapshot_experiment_metadata(output_dir: Path) -> dict[str, Any]:
    """Read optional collection provenance from a saved local snapshot."""
    payload = _load_metadata(Path(output_dir) / _METADATA_FILENAME)
    if "experiment_metadata" not in payload:
        return {}
    return _require_mapping(payload, "experiment_metadata")
