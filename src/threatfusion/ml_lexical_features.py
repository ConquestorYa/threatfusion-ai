from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

LEXICAL_FEATURE_NAMES = (
    "domain_length_ratio",
    "label_count_ratio",
    "max_label_length_ratio",
    "mean_label_length_ratio",
    "digit_ratio",
    "hyphen_ratio",
    "vowel_ratio",
    "unique_char_ratio",
    "entropy_ratio",
    "longest_digit_run_ratio",
    "longest_consonant_run_ratio",
    "longest_repeat_run_ratio",
    "punycode_label_ratio",
    "numeric_label_ratio",
)

_VOWELS = frozenset("aeiou")
_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")
_MAX_DOMAIN_LENGTH = 253.0
_MAX_LABEL_LENGTH = 63.0
_MAX_LABEL_COUNT = 10.0
_MAX_ASCII_DOMAIN_ENTROPY = math.log2(37.0)


def _longest_run(value: str, predicate) -> int:
    longest = 0
    current = 0
    for character in value:
        if predicate(character):
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _longest_repeat_run(value: str) -> int:
    if not value:
        return 0

    longest = 1
    current = 1
    previous = value[0]
    for character in value[1:]:
        if character == previous:
            current += 1
            longest = max(longest, current)
        else:
            current = 1
            previous = character
    return longest


def _entropy_ratio(value: str) -> float:
    if not value:
        return 0.0

    length = len(value)
    counts = Counter(value)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return min(entropy / _MAX_ASCII_DOMAIN_ENTROPY, 1.0)


def domain_lexical_feature_vector(domain: str) -> tuple[float, ...]:
    """Return bounded lexical features derived only from a normalized domain."""
    value = str(domain).strip().casefold().rstrip(".")
    labels = [label for label in value.split(".") if label]
    compact = "".join(labels)

    compact_length = max(len(compact), 1)
    label_count = max(len(labels), 1)
    label_lengths = [len(label) for label in labels] or [0]

    digit_count = sum(character.isdigit() for character in compact)
    hyphen_count = compact.count("-")
    vowel_count = sum(character in _VOWELS for character in compact)

    return (
        min(len(value) / _MAX_DOMAIN_LENGTH, 1.0),
        min(len(labels) / _MAX_LABEL_COUNT, 1.0),
        min(max(label_lengths) / _MAX_LABEL_LENGTH, 1.0),
        min(
            (sum(label_lengths) / label_count) / _MAX_LABEL_LENGTH,
            1.0,
        ),
        digit_count / compact_length,
        hyphen_count / compact_length,
        vowel_count / compact_length,
        len(set(compact)) / compact_length,
        _entropy_ratio(compact),
        _longest_run(compact, str.isdigit) / compact_length,
        _longest_run(compact, lambda character: character in _CONSONANTS)
        / compact_length,
        _longest_repeat_run(compact) / compact_length,
        sum(label.startswith("xn--") for label in labels) / label_count,
        sum(label.isdigit() for label in labels) / label_count,
    )


def domain_lexical_feature_matrix(domains: Iterable[str]) -> np.ndarray:
    """Build a deterministic dense feature matrix without external lookups."""
    rows = [domain_lexical_feature_vector(domain) for domain in domains]
    if not rows:
        return np.empty((0, len(LEXICAL_FEATURE_NAMES)), dtype=float)
    return np.asarray(rows, dtype=float)


class DomainLexicalFeatures(TransformerMixin, BaseEstimator):
    """scikit-learn transformer for bounded domain-string lexical features."""

    def fit(self, domains, y=None):
        return self

    def transform(self, domains):
        return domain_lexical_feature_matrix(domains)

    def get_feature_names_out(self, input_features=None):
        return np.asarray(LEXICAL_FEATURE_NAMES, dtype=object)
