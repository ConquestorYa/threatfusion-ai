from __future__ import annotations

from threatfusion.evaluation_dashboard import (
    operating_point_rows,
    source_recall_rows,
    summarize_holdout_report,
)
from threatfusion.ml_evaluation_report import (
    FrozenHoldoutReport,
    HoldoutMetricReport,
    HoldoutSourceRecallReport,
)


def metric(threshold: float, recall: float) -> HoldoutMetricReport:
    return HoldoutMetricReport(
        threshold=threshold,
        precision=0.5,
        recall=recall,
        f1=0.55,
        false_positive_rate=0.05,
        true_negative=95,
        false_positive=5,
        false_negative=10,
        true_positive=10,
    )


def report() -> FrozenHoldoutReport:
    return FrozenHoldoutReport(
        schema_version=1,
        protocol="fresh_collection_disjoint",
        generated_at="2026-09-25T12:00:00+00:00",
        model_name="model-a",
        development_snapshot_date="2026-09-23",
        holdout_snapshot_date="2026-09-25",
        input_count=140,
        retained_count=120,
        overlap_removed=20,
        malicious_count=20,
        benign_count=100,
        high=metric(0.80, 0.40),
        medium=metric(0.60, 0.60),
        low=metric(0.50, 0.75),
        source_recalls=(
            HoldoutSourceRecallReport(
                source="ThreatFox",
                total=12,
                high_recall=0.4,
                medium_recall=0.6,
                low_recall=0.8,
            ),
        ),
    )


def test_holdout_dashboard_summary() -> None:
    summary = summarize_holdout_report(report())

    assert summary.model_name == "model-a"
    assert summary.retained_count == 120
    assert summary.overlap_removed == 20
    assert summary.malicious_count == 20
    assert summary.benign_count == 100


def test_operating_point_rows_have_stable_order() -> None:
    rows = operating_point_rows(report())

    assert [row["Operating point"] for row in rows] == [
        "High",
        "Medium",
        "Low",
    ]
    assert rows[0]["Threshold"] == 0.80
    assert rows[2]["Recall"] == 0.75


def test_source_recall_rows() -> None:
    rows = source_recall_rows(report())

    assert rows == [
        {
            "Source": "ThreatFox",
            "Malicious samples": 12,
            "High recall": 0.4,
            "Medium recall": 0.6,
            "Low recall": 0.8,
        }
    ]
