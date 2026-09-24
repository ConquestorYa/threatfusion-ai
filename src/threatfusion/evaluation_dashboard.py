from __future__ import annotations

from dataclasses import dataclass

from .ml_evaluation_report import FrozenHoldoutReport


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


def operating_point_rows(
    report: FrozenHoldoutReport,
) -> list[dict[str, object]]:
    return [
        {
            "Operating point": label,
            "Threshold": metric.threshold,
            "Precision": metric.precision,
            "Recall": metric.recall,
            "F1": metric.f1,
            "False-positive rate": metric.false_positive_rate,
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
