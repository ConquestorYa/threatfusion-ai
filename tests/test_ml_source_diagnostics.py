from __future__ import annotations

import socket

import pytest

from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_fpr_comparison import run_fpr_budget_comparison
from threatfusion.ml_source_diagnostics import (
    build_source_diagnostic_report,
    calculate_source_recall,
)


def make_samples(count_per_source: int = 30, benign_count: int = 90) -> list[DomainSample]:
    malicious = [
        *[
            DomainSample(f"tf-{index:03d}.bad-example.test", 1, "ThreatFox")
            for index in range(count_per_source)
        ],
        *[
            DomainSample(f"uh-{index:03d}.bad-example.test", 1, "URLhaus")
            for index in range(count_per_source)
        ],
        *[
            DomainSample(f"sgb-{index:03d}.bad-example.test", 1, "SGB")
            for index in range(count_per_source)
        ],
    ]
    benign = [
        DomainSample(f"good-{index:03d}.example.test", 0, "Tranco")
        for index in range(benign_count)
    ]
    return [*malicious, *benign]


def test_calculate_source_recall_groups_malicious_samples_only() -> None:
    samples = [
        DomainSample("a.test", 1, "ThreatFox"),
        DomainSample("b.test", 1, "ThreatFox"),
        DomainSample("c.test", 1, "URLhaus"),
        DomainSample("d.test", 0, "Tranco"),
    ]

    result = calculate_source_recall(samples, [1, 0, 1, 1])

    assert [item.source for item in result] == ["ThreatFox", "URLhaus"]
    assert result[0].total == 2
    assert result[0].detected == 1
    assert result[0].missed == 1
    assert result[0].recall == pytest.approx(0.5)
    assert result[1].total == 1
    assert result[1].detected == 1
    assert result[1].missed == 0
    assert result[1].recall == pytest.approx(1.0)


def test_calculate_source_recall_rejects_invalid_lengths() -> None:
    with pytest.raises(ValueError, match="same length"):
        calculate_source_recall(
            [DomainSample("a.test", 1, "ThreatFox")],
            [],
        )


def test_calculate_source_recall_rejects_invalid_predictions() -> None:
    with pytest.raises(ValueError, match="0 or 1"):
        calculate_source_recall(
            [DomainSample("a.test", 1, "ThreatFox")],
            [2],
        )


def test_source_diagnostic_report_covers_candidates_budgets_and_sources() -> None:
    comparison = run_fpr_budget_comparison(
        make_samples(),
        fpr_budgets=(0.01, 0.10),
    )

    report = build_source_diagnostic_report(comparison)

    assert len(report.candidates) == 3
    for candidate in report.candidates:
        assert [item.max_false_positive_rate for item in candidate.budgets] == [
            0.01,
            0.10,
        ]
        for budget in candidate.budgets:
            assert [item.source for item in budget.sources] == [
                "SGB",
                "ThreatFox",
                "URLhaus",
            ]
            for source in budget.sources:
                assert source.total > 0
                assert source.detected + source.missed == source.total
                assert 0.0 <= source.recall <= 1.0


def test_source_diagnostic_report_uses_validation_selected_threshold() -> None:
    comparison = run_fpr_budget_comparison(
        make_samples(),
        fpr_budgets=(0.05,),
    )

    report = build_source_diagnostic_report(comparison)

    for candidate_result, candidate_report in zip(
        comparison.candidates,
        report.candidates,
        strict=True,
    ):
        assert candidate_report.budgets[0].threshold == pytest.approx(
            candidate_result.budget_evaluations[0].validation.threshold
        )


def test_source_diagnostics_do_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("source diagnostics must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    comparison = run_fpr_budget_comparison(
        make_samples(),
        fpr_budgets=(0.05,),
    )
    report = build_source_diagnostic_report(comparison)

    assert report.candidates
