from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from sklearn.model_selection import train_test_split

from .ml_dataset import DomainSample
from .models import IOCType
from .normalization import normalize_ioc_value


@dataclass(frozen=True)
class DomainDatasetSplit:
    train: list[DomainSample]
    test: list[DomainSample]


def _normalized_domain(sample: DomainSample) -> str:
    try:
        return normalize_ioc_value(sample.domain, IOCType.DOMAIN)
    except (AttributeError, TypeError) as error:
        raise ValueError("every sample must contain a valid domain string") from error


def _validate_samples(samples: list[DomainSample]) -> list[str]:
    if not samples:
        raise ValueError("cannot split an empty dataset")

    if not all(isinstance(sample, DomainSample) for sample in samples):
        raise ValueError("every dataset entry must be a DomainSample")

    labels = [sample.label for sample in samples]
    if not set(labels).issubset({0, 1}):
        raise ValueError("DomainSample labels must be 0 or 1")
    if len(set(labels)) < 2:
        raise ValueError("stratified splitting requires both labels")

    normalized_domains: list[str] = []
    seen_domains: dict[str, DomainSample] = {}
    for sample in samples:
        normalized = _normalized_domain(sample)
        if not normalized:
            raise ValueError("every sample must contain a non-empty domain")
        if normalized in seen_domains:
            previous = seen_domains[normalized]
            if previous.label != sample.label:
                raise ValueError(
                    f"conflicting labels for normalized domain: {normalized}"
                )
            raise ValueError(
                f"duplicate normalized domain: {normalized}"
            )

        seen_domains[normalized] = sample
        normalized_domains.append(normalized)

    return normalized_domains


def _validate_test_size(test_size: float) -> None:
    if isinstance(test_size, bool) or not isinstance(test_size, (int, float)):
        raise ValueError(  # noqa: TRY004
            "test_size must be a number strictly between 0 and 1"
        )
    if not math.isfinite(test_size) or not 0 < test_size < 1:
        raise ValueError("test_size must be strictly between 0 and 1")


def _validate_stratification_capacity(
    labels: list[int],
    test_size: float,
) -> None:
    class_counts = {label: labels.count(label) for label in set(labels)}
    test_count = math.ceil(test_size * len(labels))
    train_count = len(labels) - test_count

    if min(class_counts.values()) < 2 or test_count < 2 or train_count < 2:
        raise ValueError(
            "too few samples for stratified splitting; each class must occur "
            "in both train and test sets"
        )


def split_domain_dataset(
    samples: Iterable[DomainSample],
    test_size: float = 0.20,
    random_state: int = 42,
) -> DomainDatasetSplit:
    """Create a deterministic baseline stratified development split."""
    materialized = list(samples)
    _validate_test_size(test_size)
    _validate_samples(materialized)
    labels = [sample.label for sample in materialized]
    _validate_stratification_capacity(labels, test_size)

    train, test = train_test_split(
        materialized,
        test_size=test_size,
        random_state=random_state,
        stratify=labels,
    )

    train_domains = {_normalized_domain(sample) for sample in train}
    test_domains = {_normalized_domain(sample) for sample in test}
    if train_domains & test_domains:
        raise ValueError("normalized domains overlap between train and test sets")
    if {sample.label for sample in train} != {0, 1} or {
        sample.label for sample in test
    } != {0, 1}:
        raise ValueError("both train and test sets must contain both labels")

    return DomainDatasetSplit(train=list(train), test=list(test))
