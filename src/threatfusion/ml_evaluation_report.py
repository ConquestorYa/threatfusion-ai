from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .ml_holdout import FrozenHoldoutEvaluation, HoldoutSourceMetrics

_SCHEMA_VERSION = 2
_SUPPORTED_SCHEMA_VERSIONS = {1, 2}
_PROTOCOL = "fresh_collection_disjoint"
_WILSON_Z_95 = 1.959963984540054


@dataclass(frozen=True)
class RateIntervalReport:
    lower: float
    upper: float
    confidence_level: float = 0.95


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
    precision_ci: RateIntervalReport | None = None
    recall_ci: RateIntervalReport | None = None
    false_positive_rate_ci: RateIntervalReport | None = None


@dataclass(frozen=True)
class HoldoutSourceRecallReport:
    source: str
    total: int
    high_recall: float
    medium_recall: float
    low_recall: float


@dataclass(frozen=True)
class HoldoutSourceOperatingPointReport:
    recall: float | None
    recall_ci: RateIntervalReport | None
    false_positive_rate: float | None
    false_positive_rate_ci: RateIntervalReport | None


@dataclass(frozen=True)
class HoldoutSourceMetricReport:
    source: str
    malicious_total: int
    benign_total: int
    high: HoldoutSourceOperatingPointReport
    medium: HoldoutSourceOperatingPointReport
    low: HoldoutSourceOperatingPointReport


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
    source_metrics: tuple[HoldoutSourceMetricReport, ...] = ()


def _wilson_interval(
    successes: int,
    total: int,
) -> RateIntervalReport | None:
    if total <= 0:
        return None
    if successes < 0 or successes > total:
        raise ValueError("rate successes must be between zero and total")

    proportion = successes / total
    z_squared = _WILSON_Z_95**2
    denominator = 1.0 + z_squared / total
    center = (
        proportion + z_squared / (2.0 * total)
    ) / denominator
    margin = (
        _WILSON_Z_95
        * math.sqrt(
            (
                proportion * (1.0 - proportion)
                + z_squared / (4.0 * total)
            )
            / total
        )
        / denominator
    )

    return RateIntervalReport(
        lower=max(0.0, center - margin),
        upper=min(1.0, center + margin),
    )


def _rate(successes: int, total: int) -> float | None:
    if total <= 0:
        return None
    return successes / total


def _metric_report(metrics) -> HoldoutMetricReport:
    precision_total = int(metrics.true_positive + metrics.false_positive)
    recall_total = int(metrics.true_positive + metrics.false_negative)
    fpr_total = int(metrics.false_positive + metrics.true_negative)

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
        precision_ci=_wilson_interval(
            int(metrics.true_positive),
            precision_total,
        ),
        recall_ci=_wilson_interval(
            int(metrics.true_positive),
            recall_total,
        ),
        false_positive_rate_ci=_wilson_interval(
            int(metrics.false_positive),
            fpr_total,
        ),
    )


def _source_operating_point(
    *,
    detected: int,
    false_positive: int,
    malicious_total: int,
    benign_total: int,
) -> HoldoutSourceOperatingPointReport:
    return HoldoutSourceOperatingPointReport(
        recall=_rate(detected, malicious_total),
        recall_ci=_wilson_interval(detected, malicious_total),
        false_positive_rate=_rate(false_positive, benign_total),
        false_positive_rate_ci=_wilson_interval(
            false_positive,
            benign_total,
        ),
    )


def _source_metric_report(
    item: HoldoutSourceMetrics,
) -> HoldoutSourceMetricReport:
    return HoldoutSourceMetricReport(
        source=item.source,
        malicious_total=item.malicious_total,
        benign_total=item.benign_total,
        high=_source_operating_point(
            detected=item.high_detected,
            false_positive=item.high_false_positive,
            malicious_total=item.malicious_total,
            benign_total=item.benign_total,
        ),
        medium=_source_operating_point(
            detected=item.medium_detected,
            false_positive=item.medium_false_positive,
            malicious_total=item.malicious_total,
            benign_total=item.benign_total,
        ),
        low=_source_operating_point(
            detected=item.low_detected,
            false_positive=item.low_false_positive,
            malicious_total=item.malicious_total,
            benign_total=item.benign_total,
        ),
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
        source_metrics=tuple(
            _source_metric_report(item)
            for item in evaluation.source_metrics
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


def _interval_from_mapping(
    raw: object,
) -> RateIntervalReport | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise TypeError("rate confidence interval must be an object")
    try:
        interval = RateIntervalReport(**raw)
    except TypeError as error:
        raise ValueError("rate confidence interval schema is invalid") from error

    if not (
        0.0 <= interval.lower <= interval.upper <= 1.0
        and 0.0 < interval.confidence_level < 1.0
    ):
        raise ValueError("rate confidence interval values are invalid")
    return interval


def _metric_from_mapping(raw: object) -> HoldoutMetricReport:
    if not isinstance(raw, dict):
        raise TypeError("holdout metric report must be an object")

    values = dict(raw)
    for key in (
        "precision_ci",
        "recall_ci",
        "false_positive_rate_ci",
    ):
        if key in values:
            values[key] = _interval_from_mapping(values[key])

    try:
        return HoldoutMetricReport(**values)
    except TypeError as error:
        raise ValueError("holdout metric report schema is invalid") from error


def _source_from_mapping(raw: object) -> HoldoutSourceRecallReport:
    if not isinstance(raw, dict):
        raise TypeError("holdout source recall must be an object")
    try:
        return HoldoutSourceRecallReport(**raw)
    except TypeError as error:
        raise ValueError("holdout source recall schema is invalid") from error


def _source_operating_point_from_mapping(
    raw: object,
) -> HoldoutSourceOperatingPointReport:
    if not isinstance(raw, dict):
        raise TypeError("holdout source operating point must be an object")
    values = dict(raw)
    values["recall_ci"] = _interval_from_mapping(values.get("recall_ci"))
    values["false_positive_rate_ci"] = _interval_from_mapping(
        values.get("false_positive_rate_ci")
    )
    try:
        return HoldoutSourceOperatingPointReport(**values)
    except TypeError as error:
        raise ValueError(
            "holdout source operating point schema is invalid"
        ) from error


def _source_metric_from_mapping(raw: object) -> HoldoutSourceMetricReport:
    if not isinstance(raw, dict):
        raise TypeError("holdout source metric must be an object")
    try:
        return HoldoutSourceMetricReport(
            source=str(raw["source"]),
            malicious_total=int(raw["malicious_total"]),
            benign_total=int(raw["benign_total"]),
            high=_source_operating_point_from_mapping(raw["high"]),
            medium=_source_operating_point_from_mapping(raw["medium"]),
            low=_source_operating_point_from_mapping(raw["low"]),
        )
    except KeyError as error:
        raise ValueError("holdout source metric schema is incomplete") from error


def read_frozen_holdout_report(path: Path) -> FrozenHoldoutReport:
    """Read and validate an aggregate frozen-holdout JSON report."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("holdout report is invalid JSON") from error

    if not isinstance(raw, dict):
        raise TypeError("holdout report must be a JSON object")

    schema_version = raw.get("schema_version")
    if schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError("unsupported holdout report schema version")
    if raw.get("protocol") != _PROTOCOL:
        raise ValueError("unexpected holdout evaluation protocol")

    source_raw = raw.get("source_recalls")
    if not isinstance(source_raw, list):
        raise TypeError("holdout source recalls must be a list")

    source_metrics_raw = raw.get("source_metrics", [])
    if not isinstance(source_metrics_raw, list):
        raise TypeError("holdout source metrics must be a list")

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
            source_metrics=tuple(
                _source_metric_from_mapping(item)
                for item in source_metrics_raw
            ),
        )
    except KeyError as error:
        raise ValueError("holdout report schema is incomplete") from error

    if report.retained_count != report.malicious_count + report.benign_count:
        raise ValueError("holdout retained/class counts are inconsistent")

    return report
