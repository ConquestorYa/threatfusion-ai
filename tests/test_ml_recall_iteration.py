from __future__ import annotations

import socket

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_recall_iteration import (
    build_recall_iteration_candidates,
    run_simple_recall_iteration,
)


def _samples(count_per_label: int = 80) -> list[DomainSample]:
    return [
        *[
            DomainSample(
                f"malware-{index:03d}.bad-example.test",
                1,
                "ThreatFox",
            )
            for index in range(count_per_label)
        ],
        *[
            DomainSample(
                f"popular-{index:03d}.good-example.test",
                0,
                "Tranco",
            )
            for index in range(count_per_label)
        ],
    ]


def test_recall_iteration_candidates_only_change_regularization() -> None:
    candidates = build_recall_iteration_candidates()

    assert set(candidates) == {
        "lr_char_2_6_balanced_c0.5",
        "lr_char_2_6_balanced_c1",
        "lr_char_2_6_balanced_c2",
        "lr_char_2_6_balanced_c4",
    }

    c_values = []
    for pipeline in candidates.values():
        vectorizer = pipeline.named_steps["tfidf"]
        classifier = pipeline.named_steps["classifier"]

        assert isinstance(vectorizer, TfidfVectorizer)
        assert vectorizer.ngram_range == (2, 6)
        assert vectorizer.sublinear_tf is True
        assert isinstance(classifier, LogisticRegression)
        assert classifier.class_weight == "balanced"
        c_values.append(classifier.C)

    assert c_values == [0.5, 1.0, 2.0, 4.0]


def test_recall_iteration_uses_shared_split_and_requested_budgets() -> None:
    split, candidates = run_simple_recall_iteration(
        _samples(),
        fpr_budgets=(0.001, 0.005, 0.01),
    )

    assert len(split.train) == 96
    assert len(split.validation) == 32
    assert len(split.test) == 32
    assert len(candidates) == 4
    assert all(
        tuple(item.max_false_positive_rate for item in candidate.budget_evaluations)
        == (0.001, 0.005, 0.01)
        for candidate in candidates
    )


def test_recall_iteration_does_not_use_networking(monkeypatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("recall iteration must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    split, candidates = run_simple_recall_iteration(
        _samples(60),
        fpr_budgets=(0.01,),
    )

    assert split.test
    assert candidates
