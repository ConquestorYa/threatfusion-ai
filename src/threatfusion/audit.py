from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .cti_cache import CTICacheStatus
from .hybrid_assessment import MLThresholds
from .ml_artifact import TrainedMLArtifact, compute_ml_artifact_checksum

AUDIT_SCHEMA_VERSION = 1
_DEFAULT_CTI_STALE_AFTER = timedelta(hours=24)


@dataclass(frozen=True)
class CTISourceAudit:
    source: str
    refreshed_at: str
    record_count: int
    freshness: str


@dataclass(frozen=True)
class AnalysisAuditMetadata:
    captured_at: str
    model_name: str
    artifact_checksum: str
    artifact_schema_version: int
    high_threshold: float
    medium_threshold: float
    low_threshold: float
    cti_sources: tuple[CTISourceAudit, ...]
    audit_schema_version: int = AUDIT_SCHEMA_VERSION


def _captured_time_text(value: datetime | None) -> tuple[datetime, str]:
    captured = value or datetime.now(timezone.utc)
    if captured.tzinfo is None or captured.utcoffset() is None:
        raise ValueError("captured_at must be timezone-aware")
    captured_utc = captured.astimezone(timezone.utc)
    return captured_utc, captured_utc.isoformat()


def _freshness(
    refreshed_at: str,
    *,
    captured_at: datetime,
    stale_after: timedelta,
) -> str:
    try:
        refreshed = datetime.fromisoformat(refreshed_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return "unknown"

    if refreshed.tzinfo is None or refreshed.utcoffset() is None:
        return "unknown"

    age = max(
        timedelta(0),
        captured_at - refreshed.astimezone(timezone.utc),
    )
    return "stale" if age > stale_after else "fresh"


def capture_analysis_audit_metadata(
    model_dir: Path,
    artifact: TrainedMLArtifact,
    cti_statuses: list[CTICacheStatus],
    *,
    captured_at: datetime | None = None,
    stale_after: timedelta = _DEFAULT_CTI_STALE_AFTER,
    stale_after_by_source: Mapping[str, timedelta] | None = None,
) -> AnalysisAuditMetadata:
    """Capture reproducibility metadata without persisting raw telemetry."""
    if stale_after.total_seconds() <= 0:
        raise ValueError("stale_after must be positive")

    source_thresholds = dict(stale_after_by_source or {})
    if any(
        threshold.total_seconds() <= 0
        for threshold in source_thresholds.values()
    ):
        raise ValueError("source-specific stale_after values must be positive")

    captured, captured_text = _captured_time_text(captured_at)
    thresholds: MLThresholds = artifact.thresholds
    source_context = tuple(
        CTISourceAudit(
            source=status.source,
            refreshed_at=status.refreshed_at,
            record_count=status.record_count,
            freshness=_freshness(
                status.refreshed_at,
                captured_at=captured,
                stale_after=source_thresholds.get(
                    status.source,
                    stale_after,
                ),
            ),
        )
        for status in sorted(cti_statuses, key=lambda item: item.source)
    )

    return AnalysisAuditMetadata(
        captured_at=captured_text,
        model_name=artifact.metadata.model_name,
        artifact_checksum=compute_ml_artifact_checksum(model_dir),
        artifact_schema_version=artifact.metadata.schema_version,
        high_threshold=thresholds.high_confidence,
        medium_threshold=thresholds.medium_confidence,
        low_threshold=thresholds.low_confidence,
        cti_sources=source_context,
    )
