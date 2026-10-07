from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .cti_cache import (
    CTICacheStatus,
    list_cti_cache_status,
    load_ioc_records,
    finalize_for_read_only,
    replace_source_records,
)
from .ml_artifact import compute_ml_artifact_checksum, load_trusted_ml_artifact
from .ml_evaluation_report import read_frozen_holdout_report
from .models import IOCRecord


@dataclass(frozen=True)
class DeploymentBundle:
    output_dir: Path
    db_path: Path
    model_dir: Path
    evaluation_report_path: Path | None
    cti_status: tuple[CTICacheStatus, ...]


def _parse_refresh_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("CTI refresh timestamp is invalid") from error

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("CTI refresh timestamp must be timezone-aware")
    return parsed


def _validate_output_location(
    source_db: Path,
    source_model_dir: Path,
    output_dir: Path,
    source_evaluation_report: Path | None,
) -> None:
    output = output_dir.resolve()
    source_db_resolved = source_db.resolve()
    source_model_resolved = source_model_dir.resolve()

    if source_db_resolved.is_relative_to(output):
        raise ValueError("output directory must not contain the source database")
    if source_model_resolved.is_relative_to(output):
        raise ValueError("output directory must not contain the source model")
    if source_evaluation_report is not None:
        report_resolved = source_evaluation_report.resolve()
        if report_resolved.is_relative_to(output):
            raise ValueError(
                "output directory must not contain the source evaluation report"
            )


def create_deployment_bundle(
    source_db: Path,
    source_model_dir: Path,
    output_dir: Path,
    *,
    source_evaluation_report: Path | None = None,
    overwrite: bool = False,
) -> DeploymentBundle:
    """Create a sanitized CTI + model runtime directory for hosted deployment."""
    source_db = Path(source_db)
    source_model_dir = Path(source_model_dir)
    output_dir = Path(output_dir)
    evaluation_source = (
        Path(source_evaluation_report)
        if source_evaluation_report is not None
        else None
    )

    _validate_output_location(
        source_db,
        source_model_dir,
        output_dir,
        evaluation_source,
    )

    if not source_db.is_file():
        raise FileNotFoundError("source CTI database does not exist")

    load_trusted_ml_artifact(source_model_dir)
    if evaluation_source is not None:
        if not evaluation_source.is_file():
            raise FileNotFoundError("source evaluation report does not exist")
        read_frozen_holdout_report(evaluation_source)

    records = load_ioc_records(source_db)
    statuses = list_cti_cache_status(source_db)
    status_by_source = {status.source: status for status in statuses}

    records_by_source: dict[str, list[IOCRecord]] = {}
    for record in records:
        records_by_source.setdefault(record.source, []).append(record)

    missing_status = sorted(set(records_by_source) - set(status_by_source))
    if missing_status:
        raise ValueError("cached CTI source is missing refresh metadata")

    if output_dir.exists():
        if any(output_dir.iterdir()) and not overwrite:
            raise FileExistsError(
                "deployment bundle directory is not empty; use overwrite=True"
            )
        if overwrite:
            shutil.rmtree(output_dir)

    target_db = output_dir / "threatfusion.sqlite"
    target_model_dir = output_dir / "models" / "development-001"
    target_model_dir.mkdir(parents=True, exist_ok=True)

    for status in statuses:
        replace_source_records(
            target_db,
            status.source,
            records_by_source.get(status.source, []),
            refreshed_at=_parse_refresh_time(status.refreshed_at),
        )
    if target_db.exists():
        finalize_for_read_only(target_db)

    shutil.copy2(
        source_model_dir / "model.joblib",
        target_model_dir / "model.joblib",
    )
    shutil.copy2(
        source_model_dir / "metadata.json",
        target_model_dir / "metadata.json",
    )
    (target_model_dir / "artifact.sha256").write_text(
        compute_ml_artifact_checksum(target_model_dir) + "\n",
        encoding="ascii",
    )

    target_evaluation_report: Path | None = None
    if evaluation_source is not None:
        target_evaluation_report = (
            output_dir / "evaluation" / "final_holdout.json"
        )
        target_evaluation_report.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        shutil.copy2(
            evaluation_source,
            target_evaluation_report,
        )

    return DeploymentBundle(
        output_dir=output_dir,
        db_path=target_db,
        model_dir=target_model_dir,
        evaluation_report_path=target_evaluation_report,
        cti_status=tuple(list_cti_cache_status(target_db)),
    )
