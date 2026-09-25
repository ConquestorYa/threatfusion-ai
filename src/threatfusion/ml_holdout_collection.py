from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .ml_artifact import MLArtifactMetadata
from .ml_holdout import validate_fresh_snapshot_dates
from .ml_snapshot import DatasetSnapshotMetadata


@dataclass(frozen=True)
class FinalHoldoutCollectionContext:
    development_snapshot_id: str | None
    development_snapshot_date: str
    holdout_snapshot_id: str
    holdout_snapshot_date: str
    model_name: str
    artifact_sha256: str


def prepare_final_holdout_collection(
    *,
    development_metadata: DatasetSnapshotMetadata,
    artifact_metadata: MLArtifactMetadata,
    artifact_sha256: str,
    holdout_snapshot_id: str,
    holdout_snapshot_date: str,
    development_snapshot_dir: Path,
    output_dir: Path,
) -> FinalHoldoutCollectionContext:
    """Validate one fresh final-holdout collection before any networking."""

    development_date = development_metadata.benign_snapshot_date
    validate_fresh_snapshot_dates(
        development_date,
        holdout_snapshot_date,
    )
    if development_date is None:
        raise ValueError("development snapshot date is required")

    holdout_id = holdout_snapshot_id.strip()
    if not holdout_id:
        raise ValueError("holdout snapshot ID must not be empty")
    if (
        development_metadata.benign_snapshot_id is not None
        and holdout_id == development_metadata.benign_snapshot_id
    ):
        raise ValueError(
            "final holdout requires a different benign snapshot ID"
        )

    checksum = artifact_sha256.strip().casefold()
    if len(checksum) != 64 or any(
        character not in "0123456789abcdef"
        for character in checksum
    ):
        raise ValueError("artifact_sha256 must be a SHA-256 hex digest")

    development_path = Path(development_snapshot_dir).resolve()
    output_path = Path(output_dir).resolve()
    if development_path == output_path:
        raise ValueError(
            "final holdout output directory must differ from development snapshot"
        )
    if output_path.exists() and any(output_path.iterdir()):
        raise FileExistsError(
            "final holdout output directory must be empty or not exist"
        )

    return FinalHoldoutCollectionContext(
        development_snapshot_id=development_metadata.benign_snapshot_id,
        development_snapshot_date=development_date,
        holdout_snapshot_id=holdout_id,
        holdout_snapshot_date=holdout_snapshot_date,
        model_name=artifact_metadata.model_name,
        artifact_sha256=checksum,
    )


def final_holdout_experiment_metadata(
    context: FinalHoldoutCollectionContext,
) -> dict[str, object]:
    """Return non-secret protocol metadata stored with a final holdout."""

    return {
        "collection_purpose": "final_holdout",
        "evaluation_protocol": "fresh_collection_disjoint",
        "development_benign_snapshot_id": context.development_snapshot_id,
        "development_benign_snapshot_date": context.development_snapshot_date,
        "holdout_benign_snapshot_id": context.holdout_snapshot_id,
        "holdout_benign_snapshot_date": context.holdout_snapshot_date,
        "frozen_model_name": context.model_name,
        "frozen_artifact_sha256": context.artifact_sha256,
    }
