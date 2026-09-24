from __future__ import annotations

from datetime import datetime, timezone

import pytest

from threatfusion.ml_evaluation_report import (
    build_frozen_holdout_report,
    read_frozen_holdout_report,
    write_frozen_holdout_report,
)
from threatfusion.ml_high_recall import ThresholdMetrics
from threatfusion.ml_holdout import (
    FrozenHoldoutEvaluation,
    HoldoutSourceRecall,
)


def metric(threshold: float, *, tp: int, fp: int, fn: int, tn: int):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return ThresholdMetrics(
        threshold=threshold,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
        true_positive=tp,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
    )


def evaluation() -> FrozenHoldoutEvaluation:
    return FrozenHoldoutEvaluation(
        input_count=120,
        retained_count=100,
        overlap_removed=20,
        malicious_count=20,
        benign_count=80,
        high=metric(0.80, tp=8, fp=1, fn=12, tn=79),
        medium=metric(0.60, tp=12, fp=4, fn=8, tn=76),
        low=metric(0.50, tp=15, fp=8, fn=5, tn=72),
        source_recalls=(
            HoldoutSourceRecall(
                source="ThreatFox",
                total=12,
                high_detected=5,
                high_recall=5 / 12,
                medium_detected=8,
                medium_recall=8 / 12,
                low_detected=10,
                low_recall=10 / 12,
            ),
            HoldoutSourceRecall(
                source="URLhaus",
                total=8,
                high_detected=3,
                high_recall=3 / 8,
                medium_detected=4,
                medium_recall=4 / 8,
                low_detected=5,
                low_recall=5 / 8,
            ),
        ),
    )


def test_report_roundtrip_is_deterministic_and_aggregate_only(tmp_path) -> None:
    report = build_frozen_holdout_report(
        evaluation(),
        model_name="model-a",
        development_snapshot_date="2026-09-23",
        holdout_snapshot_date="2026-09-25",
        generated_at=datetime(
            2026, 9, 25, 12, 0, tzinfo=timezone.utc
        ),
    )

    path = write_frozen_holdout_report(
        report,
        tmp_path / "evaluation" / "final_holdout.json",
    )
    loaded = read_frozen_holdout_report(path)
    text = path.read_text(encoding="utf-8")

    assert loaded == report
    assert loaded.protocol == "fresh_collection_disjoint"
    assert loaded.retained_count == 100
    assert loaded.high.threshold == pytest.approx(0.80)
    assert loaded.source_recalls[0].source == "ThreatFox"
    assert "evil.example" not in text
    assert '"generated_at": "2026-09-25T12:00:00+00:00"' in text


def test_report_refuses_overwrite_by_default(tmp_path) -> None:
    report = build_frozen_holdout_report(
        evaluation(),
        model_name="model-a",
        development_snapshot_date="2026-09-23",
        holdout_snapshot_date="2026-09-25",
    )
    path = tmp_path / "report.json"
    write_frozen_holdout_report(report, path)

    with pytest.raises(FileExistsError, match="already exists"):
        write_frozen_holdout_report(report, path)


def test_naive_generated_time_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        build_frozen_holdout_report(
            evaluation(),
            model_name="model-a",
            development_snapshot_date="2026-09-23",
            holdout_snapshot_date="2026-09-25",
            generated_at=datetime(
                2026, 9, 25, 12, 0, tzinfo=timezone.utc
            ).replace(tzinfo=None),
        )


def test_invalid_protocol_is_rejected(tmp_path) -> None:
    path = tmp_path / "report.json"
    path.write_text(
        '{"schema_version": 1, "protocol": "wrong", "source_recalls": []}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="protocol"):
        read_frozen_holdout_report(path)
