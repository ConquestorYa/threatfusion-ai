from __future__ import annotations

import socket

import numpy as np

from threatfusion.ml_lexical_features import (
    LEXICAL_FEATURE_NAMES,
    DomainLexicalFeatures,
    domain_lexical_feature_matrix,
    domain_lexical_feature_vector,
)


def test_lexical_feature_vector_is_bounded_and_complete() -> None:
    vector = domain_lexical_feature_vector(
        "xn--bcher-kva.secure-login-8833.example"
    )

    assert len(vector) == len(LEXICAL_FEATURE_NAMES) == 14
    assert all(0.0 <= value <= 1.0 for value in vector)


def test_lexical_features_capture_structural_differences() -> None:
    plain = domain_lexical_feature_vector("example.com")
    structured = domain_lexical_feature_vector(
        "a99-zzzz.secure-883311.example"
    )

    by_name_plain = dict(zip(LEXICAL_FEATURE_NAMES, plain, strict=True))
    by_name_structured = dict(
        zip(LEXICAL_FEATURE_NAMES, structured, strict=True)
    )

    assert (
        by_name_structured["digit_ratio"]
        > by_name_plain["digit_ratio"]
    )
    assert (
        by_name_structured["hyphen_ratio"]
        > by_name_plain["hyphen_ratio"]
    )
    assert (
        by_name_structured["label_count_ratio"]
        > by_name_plain["label_count_ratio"]
    )


def test_lexical_feature_matrix_is_deterministic() -> None:
    domains = ["example.com", "cdn-829.example", "xn--bcher-kva.example"]

    first = domain_lexical_feature_matrix(domains)
    second = domain_lexical_feature_matrix(domains)

    assert first.shape == (3, 14)
    assert np.array_equal(first, second)
    assert np.isfinite(first).all()


def test_transformer_exposes_stable_feature_names() -> None:
    transformer = DomainLexicalFeatures()
    matrix = transformer.fit_transform(["example.com", "safe.example"])

    assert matrix.shape == (2, 14)
    assert tuple(transformer.get_feature_names_out()) == LEXICAL_FEATURE_NAMES


def test_lexical_features_do_not_use_networking(monkeypatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("lexical feature extraction must be local")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    result = domain_lexical_feature_matrix(["offline.example"])

    assert result.shape == (1, 14)
