from __future__ import annotations

from pathlib import Path

import pytest

from threatfusion.ml_artifact import MLArtifactMetadata
from threatfusion.ml_holdout_collection import (
    final_holdout_experiment_metadata,
    prepare_final_holdout_collection,
)
from threatfusion.ml_snapshot import DatasetSnapshotMetadata


def artifact_metadata() -> MLArtifactMetadata:
    return MLArtifactMetadata(
        schema_version=1,
        model_name="lr_char_2_6_sublinear_balanced",
        random_state=42,
        train_count=100,
        validation_count=20,
        development_test_count=20,
        high_fpr_budget=0.01,
        medium_fpr_budget=0.05,
        low_fpr_budget=0.10,
        high_threshold=0.9,
        medium_threshold=0.7,
        low_threshold=0.5,
        sklearn_version="test",
    )


def development_metadata() -> DatasetSnapshotMetadata:
    return DatasetSnapshotMetadata(
        benign_source="Tranco",
        benign_snapshot_id="OLD01",
        benign_snapshot_date="2026-09-23",
    )


def test_final_holdout_collection_requires_newer_distinct_snapshot(
    tmp_path: Path,
) -> None:
    context = prepare_final_holdout_collection(
        development_metadata=development_metadata(),
        artifact_metadata=artifact_metadata(),
        artifact_sha256="a" * 64,
        holdout_snapshot_id="NEW02",
        holdout_snapshot_date="2026-09-26",
        development_snapshot_dir=tmp_path / "development",
        output_dir=tmp_path / "holdout",
    )

    assert context.development_snapshot_id == "OLD01"
    assert context.holdout_snapshot_id == "NEW02"
    assert context.holdout_snapshot_date == "2026-09-26"
    assert context.artifact_sha256 == "a" * 64


def test_final_holdout_rejects_same_snapshot_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="different benign snapshot ID"):
        prepare_final_holdout_collection(
            development_metadata=development_metadata(),
            artifact_metadata=artifact_metadata(),
            artifact_sha256="b" * 64,
            holdout_snapshot_id="OLD01",
            holdout_snapshot_date="2026-09-26",
            development_snapshot_dir=tmp_path / "development",
            output_dir=tmp_path / "holdout",
        )


def test_final_holdout_rejects_non_later_date(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="later"):
        prepare_final_holdout_collection(
            development_metadata=development_metadata(),
            artifact_metadata=artifact_metadata(),
            artifact_sha256="c" * 64,
            holdout_snapshot_id="NEW02",
            holdout_snapshot_date="2026-09-23",
            development_snapshot_dir=tmp_path / "development",
            output_dir=tmp_path / "holdout",
        )


def test_final_holdout_rejects_development_output_directory(
    tmp_path: Path,
) -> None:
    same = tmp_path / "snapshot"

    with pytest.raises(ValueError, match="must differ"):
        prepare_final_holdout_collection(
            development_metadata=development_metadata(),
            artifact_metadata=artifact_metadata(),
            artifact_sha256="d" * 64,
            holdout_snapshot_id="NEW02",
            holdout_snapshot_date="2026-09-26",
            development_snapshot_dir=same,
            output_dir=same,
        )


def test_final_holdout_rejects_nonempty_output_directory(
    tmp_path: Path,
) -> None:
    output = tmp_path / "holdout"
    output.mkdir()
    (output / "metadata.json").write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="must be empty"):
        prepare_final_holdout_collection(
            development_metadata=development_metadata(),
            artifact_metadata=artifact_metadata(),
            artifact_sha256="e" * 64,
            holdout_snapshot_id="NEW02",
            holdout_snapshot_date="2026-09-26",
            development_snapshot_dir=tmp_path / "development",
            output_dir=output,
        )


def test_final_holdout_metadata_records_protocol_identity(
    tmp_path: Path,
) -> None:
    context = prepare_final_holdout_collection(
        development_metadata=development_metadata(),
        artifact_metadata=artifact_metadata(),
        artifact_sha256="f" * 64,
        holdout_snapshot_id="NEW02",
        holdout_snapshot_date="2026-09-26",
        development_snapshot_dir=tmp_path / "development",
        output_dir=tmp_path / "holdout",
    )

    metadata = final_holdout_experiment_metadata(context)

    assert metadata["collection_purpose"] == "final_holdout"
    assert metadata["evaluation_protocol"] == "fresh_collection_disjoint"
    assert metadata["development_benign_snapshot_date"] == "2026-09-23"
    assert metadata["holdout_benign_snapshot_date"] == "2026-09-26"
    assert metadata["frozen_model_name"] == (
        "lr_char_2_6_sublinear_balanced"
    )
    assert metadata["frozen_artifact_sha256"] == "f" * 64
