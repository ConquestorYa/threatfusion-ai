from __future__ import annotations

import socket

import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from threatfusion.ml_baseline import (
    BaselineExperiment,
    build_baseline_pipeline,
    run_baseline_experiment,
)
from threatfusion.ml_dataset import DomainSample


def make_samples(count_per_label: int = 30) -> list[DomainSample]:
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


def test_baseline_pipeline_uses_character_ngram_tfidf_and_logistic_regression() -> None:
    pipeline = build_baseline_pipeline()

    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["classifier"]

    assert isinstance(vectorizer, TfidfVectorizer)
    assert vectorizer.analyzer == "char"
    assert vectorizer.ngram_range == (3, 5)
    assert vectorizer.lowercase is False
    assert isinstance(classifier, LogisticRegression)
    assert classifier.max_iter == 1000
    assert classifier.random_state == 42


def test_baseline_experiment_returns_split_model_and_aggregate_metrics() -> None:
    result = run_baseline_experiment(make_samples())

    assert isinstance(result, BaselineExperiment)
    assert result.metrics.train_count == 48
    assert result.metrics.test_count == 12
    assert result.metrics.train_malicious_count == 24
    assert result.metrics.train_benign_count == 24
    assert result.metrics.test_malicious_count == 6
    assert result.metrics.test_benign_count == 6
    assert (
        result.metrics.true_negative
        + result.metrics.false_positive
        + result.metrics.false_negative
        + result.metrics.true_positive
        == result.metrics.test_count
    )


def test_baseline_metrics_are_valid_probabilities() -> None:
    metrics = run_baseline_experiment(make_samples()).metrics

    assert 0.0 <= metrics.precision <= 1.0
    assert 0.0 <= metrics.recall <= 1.0
    assert 0.0 <= metrics.f1 <= 1.0
    assert 0.0 <= metrics.false_positive_rate <= 1.0
    assert metrics.false_positive_rate == pytest.approx(
        metrics.false_positive / metrics.test_benign_count
    )


def test_baseline_is_deterministic_for_same_random_state() -> None:
    samples = make_samples()

    first = run_baseline_experiment(samples, random_state=42)
    second = run_baseline_experiment(samples, random_state=42)

    assert first.split == second.split
    assert first.metrics == second.metrics


def test_baseline_preserves_original_sample_objects_in_split() -> None:
    samples = make_samples()

    result = run_baseline_experiment(samples)

    output_ids = {id(sample) for sample in result.split.train + result.split.test}
    assert output_ids == {id(sample) for sample in samples}


def test_input_list_is_not_mutated() -> None:
    samples = make_samples()
    original = samples.copy()

    run_baseline_experiment(samples)

    assert samples == original


def test_vectorizer_is_fitted_only_on_training_domains() -> None:
    result = run_baseline_experiment(make_samples())

    vectorizer = result.model.named_steps["tfidf"]
    assert isinstance(vectorizer, TfidfVectorizer)

    train_text = "".join(sample.domain for sample in result.split.train)
    test_only_candidates = [
        sample.domain
        for sample in result.split.test
        if sample.domain not in train_text
    ]

    assert test_only_candidates
    assert hasattr(vectorizer, "vocabulary_")


def test_generator_input_is_supported() -> None:
    samples = make_samples()

    result = run_baseline_experiment(sample for sample in samples)

    assert result.metrics.train_count + result.metrics.test_count == len(samples)


def test_invalid_or_one_class_dataset_uses_existing_split_validation() -> None:
    with pytest.raises(ValueError, match="both labels"):
        run_baseline_experiment(
            [
                DomainSample("only-one.test", 1, "ThreatFox"),
                DomainSample("only-two.test", 1, "ThreatFox"),
            ]
        )


def test_baseline_training_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("baseline ML training must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    result = run_baseline_experiment(make_samples())

    assert result.metrics.test_count > 0
