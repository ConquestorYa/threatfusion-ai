from __future__ import annotations

from dataclasses import dataclass

from .ml_evaluation_report import FrozenHoldoutReport, RateIntervalReport


@dataclass(frozen=True)
class HoldoutDashboardSummary:
    model_name: str
    development_snapshot_date: str
    holdout_snapshot_date: str
    input_count: int
    retained_count: int
    overlap_removed: int
    malicious_count: int
    benign_count: int


def summarize_holdout_report(
    report: FrozenHoldoutReport,
) -> HoldoutDashboardSummary:
    return HoldoutDashboardSummary(
        model_name=report.model_name,
        development_snapshot_date=report.development_snapshot_date,
        holdout_snapshot_date=report.holdout_snapshot_date,
        input_count=report.input_count,
        retained_count=report.retained_count,
        overlap_removed=report.overlap_removed,
        malicious_count=report.malicious_count,
        benign_count=report.benign_count,
    )


def _interval_text(interval: RateIntervalReport | None) -> str:
    if interval is None:
        return "n/a"
    confidence = interval.confidence_level * 100
    return (
        f"{interval.lower:.2%}–{interval.upper:.2%} "
        f"({confidence:.0f}% CI)"
    )


def operating_point_rows(
    report: FrozenHoldoutReport,
) -> list[dict[str, object]]:
    return [
        {
            "Operating point": label,
            "Threshold": metric.threshold,
            "Precision": metric.precision,
            "Precision interval": _interval_text(metric.precision_ci),
            "Recall": metric.recall,
            "Recall interval": _interval_text(metric.recall_ci),
            "F1": metric.f1,
            "False-positive rate": metric.false_positive_rate,
            "FPR interval": _interval_text(
                metric.false_positive_rate_ci
            ),
            "TN": metric.true_negative,
            "FP": metric.false_positive,
            "FN": metric.false_negative,
            "TP": metric.true_positive,
        }
        for label, metric in (
            ("High", report.high),
            ("Medium", report.medium),
            ("Low", report.low),
        )
    ]


def source_recall_rows(
    report: FrozenHoldoutReport,
) -> list[dict[str, object]]:
    return [
        {
            "Source": item.source,
            "Malicious samples": item.total,
            "High recall": item.high_recall,
            "Medium recall": item.medium_recall,
            "Low recall": item.low_recall,
        }
        for item in report.source_recalls
    ]


def source_metric_rows(
    report: FrozenHoldoutReport,
) -> list[dict[str, object]]:
    if not report.source_metrics:
        return [
            {
                "Source": item.source,
                "Malicious samples": item.total,
                "Benign samples": 0,
                "High recall": item.high_recall,
                "High recall interval": "n/a",
                "High FPR": None,
                "High FPR interval": "n/a",
                "Medium recall": item.medium_recall,
                "Medium recall interval": "n/a",
                "Medium FPR": None,
                "Medium FPR interval": "n/a",
                "Low recall": item.low_recall,
                "Low recall interval": "n/a",
                "Low FPR": None,
                "Low FPR interval": "n/a",
            }
            for item in report.source_recalls
        ]

    rows: list[dict[str, object]] = []
    for item in report.source_metrics:
        rows.append(
            {
                "Source": item.source,
                "Malicious samples": item.malicious_total,
                "Benign samples": item.benign_total,
                "High recall": item.high.recall,
                "High recall interval": _interval_text(
                    item.high.recall_ci
                ),
                "High FPR": item.high.false_positive_rate,
                "High FPR interval": _interval_text(
                    item.high.false_positive_rate_ci
                ),
                "Medium recall": item.medium.recall,
                "Medium recall interval": _interval_text(
                    item.medium.recall_ci
                ),
                "Medium FPR": item.medium.false_positive_rate,
                "Medium FPR interval": _interval_text(
                    item.medium.false_positive_rate_ci
                ),
                "Low recall": item.low.recall,
                "Low recall interval": _interval_text(
                    item.low.recall_ci
                ),
                "Low FPR": item.low.false_positive_rate,
                "Low FPR interval": _interval_text(
                    item.low.false_positive_rate_ci
                ),
            }
        )
    return rows
