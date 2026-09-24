from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .cti_cache import (
    CTICacheStatus,
    list_cti_cache_status,
    load_ioc_records,
    replace_source_records,
)
from .ml_artifact import load_trusted_ml_artifact
from .models import IOCRecord


@dataclass(frozen=True)
class DeploymentBundle:
    output_dir: Path
    db_path: Path
    model_dir: Path
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
) -> None:
    output = output_dir.resolve()
    source_db_resolved = source_db.resolve()
    source_model_resolved = source_model_dir.resolve()

    if source_db_resolved.is_relative_to(output):
        raise ValueError("output directory must not contain the source database")
    if source_model_resolved.is_relative_to(output):
        raise ValueError("output directory must not contain the source model")


def create_deployment_bundle(
    source_db: Path,
    source_model_dir: Path,
    output_dir: Path,
    *,
    overwrite: bool = False,
) -> DeploymentBundle:
    """Create a sanitized CTI + model runtime directory for hosted deployment."""
    source_db = Path(source_db)
    source_model_dir = Path(source_model_dir)
    output_dir = Path(output_dir)

    _validate_output_location(source_db, source_model_dir, output_dir)

    if not source_db.is_file():
        raise FileNotFoundError("source CTI database does not exist")

    load_trusted_ml_artifact(source_model_dir)

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

    shutil.copy2(
        source_model_dir / "model.joblib",
        target_model_dir / "model.joblib",
    )
    shutil.copy2(
        source_model_dir / "metadata.json",
        target_model_dir / "metadata.json",
    )

    return DeploymentBundle(
        output_dir=output_dir,
        db_path=target_db,
        model_dir=target_model_dir,
        cti_status=tuple(list_cti_cache_status(target_db)),
    )
