from __future__ import annotations

import socket

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_feature_iteration import (
    build_feature_iteration_candidates,
    build_lexical_feature_pipeline,
    run_feature_iteration,
)
from threatfusion.ml_lexical_features import DomainLexicalFeatures


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
                "CESNET",
            )
            for index in range(count_per_label)
        ],
    ]


def test_feature_iteration_keeps_baseline_and_three_enhanced_candidates() -> None:
    candidates = build_feature_iteration_candidates()

    assert tuple(candidates) == (
        "lr_char_2_6_balanced_c4",
        "lr_char_2_6_plus_lexical_c1",
        "lr_char_2_6_plus_lexical_c2",
        "lr_char_2_6_plus_lexical_c4",
    )


def test_reusable_lexical_pipeline_builder_uses_requested_c() -> None:
    pipeline = build_lexical_feature_pipeline(
        c_value=4.0,
        random_state=42,
    )

    classifier = pipeline.named_steps["classifier"]
    assert isinstance(classifier, LogisticRegression)
    assert classifier.C == 4.0
    assert "features" in pipeline.named_steps


def test_enhanced_candidates_combine_tfidf_and_scaled_lexical_features() -> None:
    candidates = build_feature_iteration_candidates()

    for name, pipeline in candidates.items():
        classifier = pipeline.named_steps["classifier"]
        assert isinstance(classifier, LogisticRegression)
        assert classifier.class_weight == "balanced"

        if name == "lr_char_2_6_balanced_c4":
            continue

        features = pipeline.named_steps["features"]
        assert isinstance(features, FeatureUnion)
        transformers = dict(features.transformer_list)

        tfidf = transformers["char_tfidf"]
        assert isinstance(tfidf, TfidfVectorizer)
        assert tfidf.ngram_range == (2, 6)
        assert tfidf.sublinear_tf is True

        lexical = transformers["lexical"]
        assert isinstance(lexical, Pipeline)
        assert isinstance(
            lexical.named_steps["extract"],
            DomainLexicalFeatures,
        )
        assert isinstance(lexical.named_steps["scale"], StandardScaler)


def test_feature_iteration_uses_shared_split_and_requested_budgets() -> None:
    split, candidates = run_feature_iteration(
        _samples(),
        fpr_budgets=(0.001, 0.005, 0.01),
    )

    assert len(split.train) == 96
    assert len(split.validation) == 32
    assert len(split.test) == 32
    assert len(candidates) == 4
    assert all(
        tuple(
            item.max_false_positive_rate
            for item in candidate.budget_evaluations
        )
        == (0.001, 0.005, 0.01)
        for candidate in candidates
    )


def test_feature_iteration_does_not_use_networking(monkeypatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("feature iteration must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    split, candidates = run_feature_iteration(
        _samples(60),
        fpr_budgets=(0.01,),
    )

    assert split.test
    assert candidates
