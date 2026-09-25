from __future__ import annotations

from threatfusion.evaluation_dashboard import (
    operating_point_rows,
    source_metric_rows,
    source_recall_rows,
    summarize_holdout_report,
)
from threatfusion.ml_evaluation_report import (
    FrozenHoldoutReport,
    HoldoutMetricReport,
    HoldoutSourceMetricReport,
    HoldoutSourceOperatingPointReport,
    HoldoutSourceRecallReport,
    RateIntervalReport,
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
        source_metrics=(
            HoldoutSourceMetricReport(
                source="ThreatFox",
                malicious_total=12,
                benign_total=0,
                high=HoldoutSourceOperatingPointReport(
                    recall=0.4,
                    recall_ci=RateIntervalReport(0.2, 0.65),
                    false_positive_rate=None,
                    false_positive_rate_ci=None,
                ),
                medium=HoldoutSourceOperatingPointReport(
                    recall=0.6,
                    recall_ci=RateIntervalReport(0.35, 0.8),
                    false_positive_rate=None,
                    false_positive_rate_ci=None,
                ),
                low=HoldoutSourceOperatingPointReport(
                    recall=0.8,
                    recall_ci=RateIntervalReport(0.55, 0.93),
                    false_positive_rate=None,
                    false_positive_rate_ci=None,
                ),
            ),
            HoldoutSourceMetricReport(
                source="Tranco",
                malicious_total=0,
                benign_total=100,
                high=HoldoutSourceOperatingPointReport(
                    recall=None,
                    recall_ci=None,
                    false_positive_rate=0.01,
                    false_positive_rate_ci=RateIntervalReport(0.002, 0.054),
                ),
                medium=HoldoutSourceOperatingPointReport(
                    recall=None,
                    recall_ci=None,
                    false_positive_rate=0.05,
                    false_positive_rate_ci=RateIntervalReport(0.022, 0.112),
                ),
                low=HoldoutSourceOperatingPointReport(
                    recall=None,
                    recall_ci=None,
                    false_positive_rate=0.1,
                    false_positive_rate_ci=RateIntervalReport(0.055, 0.174),
                ),
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
    assert rows[0]["Recall interval"] == "n/a"


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


def test_source_metric_rows_include_class_specific_rates() -> None:
    rows = source_metric_rows(report())

    assert rows[0]["Source"] == "ThreatFox"
    assert rows[0]["Malicious samples"] == 12
    assert rows[0]["Benign samples"] == 0
    assert rows[0]["High recall"] == 0.4
    assert rows[0]["High FPR"] is None
    assert "95% CI" in rows[0]["High recall interval"]

    assert rows[1]["Source"] == "Tranco"
    assert rows[1]["Malicious samples"] == 0
    assert rows[1]["Benign samples"] == 100
    assert rows[1]["High recall"] is None
    assert rows[1]["High FPR"] == 0.01
    assert "95% CI" in rows[1]["High FPR interval"]
