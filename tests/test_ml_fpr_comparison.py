from __future__ import annotations

import socket

import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier

from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_fpr_comparison import (
    build_candidate_pipelines,
    run_fpr_budget_comparison,
    select_threshold_for_fpr_budget,
)


def make_samples(count_per_label: int = 50) -> list[DomainSample]:
    return [
        *[
            DomainSample(f"malware-{index:03d}.bad-example.test", 1, "ThreatFox")
            for index in range(count_per_label)
        ],
        *[
            DomainSample(f"popular-{index:03d}.good-example.test", 0, "Tranco")
            for index in range(count_per_label)
        ],
    ]


def test_candidate_set_is_small_and_predefined() -> None:
    candidates = build_candidate_pipelines()

    assert list(candidates) == [
        "lr_char_3_5_balanced",
        "lr_char_2_6_sublinear_balanced",
        "sgd_char_3_5_balanced",
    ]


def test_logistic_candidates_have_expected_features() -> None:
    candidates = build_candidate_pipelines()

    baseline = candidates["lr_char_3_5_balanced"]
    wider = candidates["lr_char_2_6_sublinear_balanced"]

    baseline_vectorizer = baseline.named_steps["tfidf"]
    baseline_classifier = baseline.named_steps["classifier"]
    wider_vectorizer = wider.named_steps["tfidf"]
    wider_classifier = wider.named_steps["classifier"]

    assert isinstance(baseline_vectorizer, TfidfVectorizer)
    assert baseline_vectorizer.ngram_range == (3, 5)
    assert isinstance(baseline_classifier, LogisticRegression)
    assert baseline_classifier.class_weight == "balanced"

    assert isinstance(wider_vectorizer, TfidfVectorizer)
    assert wider_vectorizer.ngram_range == (2, 6)
    assert wider_vectorizer.sublinear_tf is True
    assert isinstance(wider_classifier, LogisticRegression)
    assert wider_classifier.class_weight == "balanced"


def test_sgd_candidate_uses_log_loss_and_balanced_classes() -> None:
    candidate = build_candidate_pipelines()["sgd_char_3_5_balanced"]
    classifier = candidate.named_steps["classifier"]

    assert isinstance(classifier, SGDClassifier)
    assert classifier.loss == "log_loss"
    assert classifier.class_weight == "balanced"
    assert classifier.random_state == 42


def test_fpr_budget_selector_maximizes_recall_within_budget() -> None:
    metrics = select_threshold_for_fpr_budget(
        [0, 0, 0, 1, 1, 1],
        [0.95, 0.40, 0.10, 0.90, 0.60, 0.20],
        max_false_positive_rate=1 / 3,
    )

    assert metrics.false_positive_rate <= pytest.approx(1 / 3)
    assert metrics.recall == pytest.approx(2 / 3)
    assert metrics.threshold == pytest.approx(0.40)


def test_zero_fpr_budget_can_select_conservative_threshold() -> None:
    metrics = select_threshold_for_fpr_budget(
        [0, 0, 1, 1],
        [0.30, 0.20, 0.90, 0.40],
        max_false_positive_rate=0.0,
    )

    assert metrics.false_positive == 0
    assert metrics.recall == pytest.approx(1.0)
    assert metrics.threshold == pytest.approx(0.40)


def test_comparison_uses_shared_split_and_reports_all_budgets() -> None:
    result = run_fpr_budget_comparison(
        make_samples(),
        fpr_budgets=(0.0, 0.10),
    )

    assert len(result.split.train) == 60
    assert len(result.split.validation) == 20
    assert len(result.split.test) == 20
    assert len(result.candidates) == 3

    for candidate in result.candidates:
        assert [item.max_false_positive_rate for item in candidate.budget_evaluations] == [
            0.0,
            0.10,
        ]
        for item in candidate.budget_evaluations:
            assert item.validation.false_positive_rate <= item.max_false_positive_rate + 1e-12
            assert 0.0 <= item.test.recall <= 1.0
            assert 0.0 <= item.test.false_positive_rate <= 1.0


def test_comparison_is_deterministic() -> None:
    samples = make_samples()

    first = run_fpr_budget_comparison(samples, fpr_budgets=(0.05,))
    second = run_fpr_budget_comparison(samples, fpr_budgets=(0.05,))

    first_metrics = [
        candidate.budget_evaluations
        for candidate in first.candidates
    ]
    second_metrics = [
        candidate.budget_evaluations
        for candidate in second.candidates
    ]

    assert first.split == second.split
    assert first_metrics == second_metrics


def test_progress_callback_reports_candidate_names() -> None:
    seen: list[str] = []

    run_fpr_budget_comparison(
        make_samples(),
        fpr_budgets=(0.05,),
        progress_callback=seen.append,
    )

    assert seen == [
        "lr_char_3_5_balanced",
        "lr_char_2_6_sublinear_balanced",
        "sgd_char_3_5_balanced",
    ]


def test_comparison_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("ML comparison must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    result = run_fpr_budget_comparison(
        make_samples(),
        fpr_budgets=(0.05,),
    )

    assert result.candidates
