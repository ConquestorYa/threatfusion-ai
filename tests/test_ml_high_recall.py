from __future__ import annotations

import socket

import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import threatfusion.ml_high_recall as high_recall
from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_high_recall import (
    build_high_recall_pipeline,
    calculate_threshold_metrics,
    run_high_recall_experiment,
    select_threshold_for_recall,
    split_train_validation_test,
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


def test_high_recall_pipeline_uses_balanced_logistic_regression() -> None:
    pipeline = build_high_recall_pipeline()

    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["classifier"]

    assert isinstance(vectorizer, TfidfVectorizer)
    assert vectorizer.analyzer == "char"
    assert vectorizer.ngram_range == (3, 5)
    assert isinstance(classifier, LogisticRegression)
    assert classifier.class_weight == "balanced"
    assert classifier.random_state == 42


def test_three_way_split_is_60_20_20_and_preserves_objects() -> None:
    samples = make_samples()
    split = split_train_validation_test(samples)

    assert len(split.train) == 60
    assert len(split.validation) == 20
    assert len(split.test) == 20

    combined = split.train + split.validation + split.test
    assert {id(sample) for sample in combined} == {id(sample) for sample in samples}


def test_three_way_split_has_no_domain_overlap() -> None:
    split = split_train_validation_test(make_samples())

    train = {sample.domain for sample in split.train}
    validation = {sample.domain for sample in split.validation}
    test = {sample.domain for sample in split.test}

    assert not train & validation
    assert not train & test
    assert not validation & test


def test_three_way_split_is_deterministic() -> None:
    samples = make_samples()

    first = split_train_validation_test(samples)
    second = split_train_validation_test(samples)

    assert first == second


def test_invalid_combined_split_sizes_are_rejected() -> None:
    with pytest.raises(ValueError, match="less than 1"):
        split_train_validation_test(
            make_samples(),
            test_size=0.5,
            validation_size=0.5,
        )


def test_threshold_metrics_match_expected_confusion_counts() -> None:
    metrics = calculate_threshold_metrics(
        [0, 0, 1, 1],
        [0.10, 0.70, 0.40, 0.90],
        threshold=0.50,
    )

    assert metrics.true_negative == 1
    assert metrics.false_positive == 1
    assert metrics.false_negative == 1
    assert metrics.true_positive == 1
    assert metrics.precision == pytest.approx(0.5)
    assert metrics.recall == pytest.approx(0.5)
    assert metrics.false_positive_rate == pytest.approx(0.5)


def test_threshold_selection_meets_recall_and_minimizes_false_positive_rate() -> None:
    metrics = select_threshold_for_recall(
        [0, 0, 1, 1],
        [0.20, 0.80, 0.60, 0.90],
        target_recall=1.0,
    )

    assert metrics.recall == pytest.approx(1.0)
    assert metrics.threshold == pytest.approx(0.60)
    assert metrics.false_positive == 1


def test_high_recall_experiment_reports_default_and_target_metrics() -> None:
    result = run_high_recall_experiment(make_samples())

    assert result.default_test.threshold == pytest.approx(0.5)
    assert [item.target_recall for item in result.target_evaluations] == [
        0.80,
        0.90,
        0.95,
        0.99,
    ]
    for item in result.target_evaluations:
        assert item.validation.recall + 1e-12 >= item.target_recall
        assert 0.0 <= item.test.precision <= 1.0
        assert 0.0 <= item.test.recall <= 1.0
        assert 0.0 <= item.test.false_positive_rate <= 1.0


def test_high_recall_experiment_is_deterministic() -> None:
    samples = make_samples()

    first = run_high_recall_experiment(samples)
    second = run_high_recall_experiment(samples)

    assert first.split == second.split
    assert first.default_test == second.default_test
    assert first.target_evaluations == second.target_evaluations


def test_threshold_is_selected_from_validation_not_test() -> None:
    result = run_high_recall_experiment(make_samples(), recall_targets=(0.90,))

    selected = result.target_evaluations[0]
    assert selected.validation.recall >= 0.90
    assert selected.test.threshold == pytest.approx(selected.validation.threshold)


def test_high_recall_training_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("high-recall ML evaluation must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    result = run_high_recall_experiment(make_samples(), recall_targets=(0.90,))

    assert result.target_evaluations


def test_optimized_threshold_selection_matches_brute_force_semantics() -> None:
    labels = [0, 1, 0, 1, 0, 1]
    probabilities = [0.95, 0.90, 0.70, 0.65, 0.30, 0.20]
    target_recall = 2 / 3

    candidates = sorted({0.0, 1.0, *probabilities}, reverse=True)
    feasible = [
        calculate_threshold_metrics(
            labels,
            probabilities,
            threshold=threshold,
        )
        for threshold in candidates
    ]
    feasible = [
        metrics
        for metrics in feasible
        if metrics.recall + 1e-12 >= target_recall
    ]
    expected = min(
        feasible,
        key=lambda metrics: (
            metrics.false_positive_rate,
            -metrics.precision,
            -metrics.recall,
            -metrics.threshold,
        ),
    )

    actual = select_threshold_for_recall(
        labels,
        probabilities,
        target_recall=target_recall,
    )

    assert actual.threshold == expected.threshold
    assert actual.true_negative == expected.true_negative
    assert actual.false_positive == expected.false_positive
    assert actual.false_negative == expected.false_negative
    assert actual.true_positive == expected.true_positive
    assert actual.precision == pytest.approx(expected.precision)
    assert actual.recall == pytest.approx(expected.recall)
    assert actual.f1 == pytest.approx(expected.f1)
    assert actual.false_positive_rate == pytest.approx(expected.false_positive_rate)


def test_threshold_selection_does_not_recompute_full_predictions_per_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError(
            "threshold selection must not rebuild full predictions for each candidate"
        )

    monkeypatch.setattr(high_recall, "calculate_threshold_metrics", fail)

    labels = [index % 2 for index in range(2000)]
    probabilities = [(index + 1) / 2001 for index in range(2000)]

    result = high_recall.select_threshold_for_recall(
        labels,
        probabilities,
        target_recall=0.90,
    )

    assert result.recall >= 0.90
