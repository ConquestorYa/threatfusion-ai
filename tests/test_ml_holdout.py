from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from threatfusion.hybrid_assessment import MLThresholds
from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_holdout import (
    evaluate_frozen_artifact_on_holdout,
    prepare_disjoint_holdout,
    validate_fresh_snapshot_dates,
)


class FakeProbabilityModel:
    def __init__(self, probabilities: dict[str, float]) -> None:
        self.classes_ = [0, 1]
        self.probabilities = probabilities

    def predict_proba(self, domains: list[str]) -> list[list[float]]:
        return [
            [1.0 - self.probabilities[domain], self.probabilities[domain]]
            for domain in domains
        ]


def artifact(probabilities: dict[str, float]):
    return SimpleNamespace(
        model=FakeProbabilityModel(probabilities),
        thresholds=MLThresholds(
            high_confidence=0.80,
            medium_confidence=0.60,
            low_confidence=0.50,
        ),
    )


def test_fresh_snapshot_date_must_be_later() -> None:
    validate_fresh_snapshot_dates("2026-09-23", "2026-09-25")

    with pytest.raises(ValueError, match="later"):
        validate_fresh_snapshot_dates("2026-09-23", "2026-09-23")

    with pytest.raises(ValueError, match="dates"):
        validate_fresh_snapshot_dates(None, "2026-09-25")


def test_prepare_disjoint_holdout_removes_all_development_overlap() -> None:
    development = [
        DomainSample("Seen.Example.", 0, "Tranco"),
        DomainSample("old-bad.example", 1, "ThreatFox"),
    ]
    holdout = [
        DomainSample("seen.example", 0, "Tranco"),
        DomainSample("new-good.example", 0, "Tranco"),
        DomainSample("new-bad.example", 1, "URLhaus"),
    ]

    prepared = prepare_disjoint_holdout(development, holdout)

    assert prepared.input_count == 3
    assert prepared.overlap_removed == 1
    assert [sample.domain for sample in prepared.samples] == [
        "new-good.example",
        "new-bad.example",
    ]


def test_prepare_disjoint_holdout_preserves_timing_metadata() -> None:
    first_seen = datetime(2026, 9, 25, 9, 0, tzinfo=timezone.utc)
    last_seen = datetime(2026, 9, 26, 9, 0, tzinfo=timezone.utc)
    holdout = [
        DomainSample("new-good.example", 0, "Tranco"),
        DomainSample(
            "new-bad.example",
            1,
            "ThreatFox",
            first_seen=first_seen,
            last_seen=last_seen,
        ),
    ]

    prepared = prepare_disjoint_holdout([], holdout)

    malicious = next(sample for sample in prepared.samples if sample.label == 1)
    assert malicious.first_seen == first_seen
    assert malicious.last_seen == last_seen


def test_prepare_disjoint_holdout_accepts_legacy_ineligible_development_rows() -> None:
    development = [
        DomainSample("legacy-single-label", 1, "ThreatFox"),
        DomainSample("Seen.Example.", 0, "Tranco"),
    ]
    holdout = [
        DomainSample("seen.example", 0, "Tranco"),
        DomainSample("new-good.example", 0, "Tranco"),
        DomainSample("new-bad.example", 1, "URLhaus"),
    ]

    prepared = prepare_disjoint_holdout(development, holdout)

    assert prepared.overlap_removed == 1
    assert [sample.domain for sample in prepared.samples] == [
        "new-good.example",
        "new-bad.example",
    ]


def test_prepare_disjoint_holdout_keeps_strict_holdout_validation() -> None:
    with pytest.raises(ValueError, match="holdout snapshot contains an invalid domain"):
        prepare_disjoint_holdout(
            [DomainSample("legacy-single-label", 1, "ThreatFox")],
            [
                DomainSample("invalid_holdout", 0, "Tranco"),
                DomainSample("new-bad.example", 1, "URLhaus"),
            ],
        )


def test_holdout_must_retain_both_classes() -> None:
    with pytest.raises(ValueError, match="both malicious and benign"):
        prepare_disjoint_holdout(
            [DomainSample("old.example", 0, "Tranco")],
            [
                DomainSample("old.example", 0, "Tranco"),
                DomainSample("new-bad.example", 1, "ThreatFox"),
            ],
        )


def test_frozen_holdout_uses_exact_artifact_thresholds() -> None:
    development = [
        DomainSample("old-good.example", 0, "Tranco"),
        DomainSample("old-bad.example", 1, "ThreatFox"),
    ]
    holdout = [
        DomainSample("old-good.example", 0, "Tranco"),
        DomainSample("evil-one.example", 1, "ThreatFox"),
        DomainSample("evil-two.example", 1, "ThreatFox"),
        DomainSample("good-one.example", 0, "Tranco"),
        DomainSample("good-two.example", 0, "Tranco"),
    ]
    model = artifact(
        {
            "evil-one.example": 0.90,
            "evil-two.example": 0.65,
            "good-one.example": 0.20,
            "good-two.example": 0.55,
        }
    )

    result = evaluate_frozen_artifact_on_holdout(
        model,
        development,
        holdout,
    )

    assert result.input_count == 5
    assert result.retained_count == 4
    assert result.overlap_removed == 1
    assert result.malicious_count == 2
    assert result.benign_count == 2

    assert result.high.threshold == pytest.approx(0.80)
    assert result.high.true_positive == 1
    assert result.high.false_positive == 0
    assert result.high.recall == pytest.approx(0.5)
    assert result.high.false_positive_rate == pytest.approx(0.0)

    assert result.medium.threshold == pytest.approx(0.60)
    assert result.medium.true_positive == 2
    assert result.medium.false_positive == 0
    assert result.medium.recall == pytest.approx(1.0)

    assert result.low.threshold == pytest.approx(0.50)
    assert result.low.true_positive == 2
    assert result.low.false_positive == 1
    assert result.low.false_positive_rate == pytest.approx(0.5)

    assert result.source_recalls[0].source == "ThreatFox"
    assert result.source_recalls[0].total == 2
    assert result.source_recalls[0].high_recall == pytest.approx(0.5)
    assert result.source_recalls[0].medium_recall == pytest.approx(1.0)
    assert result.source_recalls[0].low_recall == pytest.approx(1.0)

    assert [item.source for item in result.source_metrics] == [
        "ThreatFox",
        "Tranco",
    ]
    threatfox = result.source_metrics[0]
    assert threatfox.malicious_total == 2
    assert threatfox.benign_total == 0
    assert threatfox.high_detected == 1
    assert threatfox.low_detected == 2

    tranco = result.source_metrics[1]
    assert tranco.malicious_total == 0
    assert tranco.benign_total == 2
    assert tranco.high_false_positive == 0
    assert tranco.low_false_positive == 1
