from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .ml_holdout import FrozenHoldoutEvaluation

_SCHEMA_VERSION = 1
_PROTOCOL = "fresh_collection_disjoint"


@dataclass(frozen=True)
class HoldoutMetricReport:
    threshold: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int


@dataclass(frozen=True)
class HoldoutSourceRecallReport:
    source: str
    total: int
    high_recall: float
    medium_recall: float
    low_recall: float


@dataclass(frozen=True)
class FrozenHoldoutReport:
    schema_version: int
    protocol: str
    generated_at: str
    model_name: str
    development_snapshot_date: str
    holdout_snapshot_date: str
    input_count: int
    retained_count: int
    overlap_removed: int
    malicious_count: int
    benign_count: int
    high: HoldoutMetricReport
    medium: HoldoutMetricReport
    low: HoldoutMetricReport
    source_recalls: tuple[HoldoutSourceRecallReport, ...]


def _metric_report(metrics) -> HoldoutMetricReport:
    return HoldoutMetricReport(
        threshold=float(metrics.threshold),
        precision=float(metrics.precision),
        recall=float(metrics.recall),
        f1=float(metrics.f1),
        false_positive_rate=float(metrics.false_positive_rate),
        true_negative=int(metrics.true_negative),
        false_positive=int(metrics.false_positive),
        false_negative=int(metrics.false_negative),
        true_positive=int(metrics.true_positive),
    )


def build_frozen_holdout_report(
    evaluation: FrozenHoldoutEvaluation,
    *,
    model_name: str,
    development_snapshot_date: str,
    holdout_snapshot_date: str,
    generated_at: datetime | None = None,
) -> FrozenHoldoutReport:
    """Build an aggregate-only report from a frozen holdout evaluation."""
    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")

    return FrozenHoldoutReport(
        schema_version=_SCHEMA_VERSION,
        protocol=_PROTOCOL,
        generated_at=timestamp.astimezone(timezone.utc).isoformat(),
        model_name=model_name,
        development_snapshot_date=development_snapshot_date,
        holdout_snapshot_date=holdout_snapshot_date,
        input_count=evaluation.input_count,
        retained_count=evaluation.retained_count,
        overlap_removed=evaluation.overlap_removed,
        malicious_count=evaluation.malicious_count,
        benign_count=evaluation.benign_count,
        high=_metric_report(evaluation.high),
        medium=_metric_report(evaluation.medium),
        low=_metric_report(evaluation.low),
        source_recalls=tuple(
            HoldoutSourceRecallReport(
                source=item.source,
                total=item.total,
                high_recall=float(item.high_recall),
                medium_recall=float(item.medium_recall),
                low_recall=float(item.low_recall),
            )
            for item in evaluation.source_recalls
        ),
    )


def write_frozen_holdout_report(
    report: FrozenHoldoutReport,
    path: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Write a deterministic JSON holdout report containing no domain rows."""
    output = Path(path)
    if output.exists() and not overwrite:
        raise FileExistsError(
            "holdout report already exists; pass overwrite=True to replace it"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(asdict(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def _metric_from_mapping(raw: object) -> HoldoutMetricReport:
    if not isinstance(raw, dict):
        raise ValueError("holdout metric report must be an object")
    try:
        return HoldoutMetricReport(**raw)
    except TypeError as error:
        raise ValueError("holdout metric report schema is invalid") from error


def _source_from_mapping(raw: object) -> HoldoutSourceRecallReport:
    if not isinstance(raw, dict):
        raise ValueError("holdout source recall must be an object")
    try:
        return HoldoutSourceRecallReport(**raw)
    except TypeError as error:
        raise ValueError("holdout source recall schema is invalid") from error


def read_frozen_holdout_report(path: Path) -> FrozenHoldoutReport:
    """Read and validate an aggregate frozen-holdout JSON report."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("holdout report is invalid JSON") from error

    if not isinstance(raw, dict):
        raise ValueError("holdout report must be a JSON object")

    if raw.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("unsupported holdout report schema version")
    if raw.get("protocol") != _PROTOCOL:
        raise ValueError("unexpected holdout evaluation protocol")

    source_raw = raw.get("source_recalls")
    if not isinstance(source_raw, list):
        raise ValueError("holdout source recalls must be a list")

    try:
        report = FrozenHoldoutReport(
            schema_version=int(raw["schema_version"]),
            protocol=str(raw["protocol"]),
            generated_at=str(raw["generated_at"]),
            model_name=str(raw["model_name"]),
            development_snapshot_date=str(raw["development_snapshot_date"]),
            holdout_snapshot_date=str(raw["holdout_snapshot_date"]),
            input_count=int(raw["input_count"]),
            retained_count=int(raw["retained_count"]),
            overlap_removed=int(raw["overlap_removed"]),
            malicious_count=int(raw["malicious_count"]),
            benign_count=int(raw["benign_count"]),
            high=_metric_from_mapping(raw["high"]),
            medium=_metric_from_mapping(raw["medium"]),
            low=_metric_from_mapping(raw["low"]),
            source_recalls=tuple(
                _source_from_mapping(item)
                for item in source_raw
            ),
        )
    except KeyError as error:
        raise ValueError("holdout report schema is incomplete") from error

    if report.retained_count != report.malicious_count + report.benign_count:
        raise ValueError("holdout retained/class counts are inconsistent")

    return report
