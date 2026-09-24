from __future__ import annotations

import math

import pytest

from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_split import DomainDatasetSplit, split_domain_dataset
from threatfusion.models import IOCType
from threatfusion.normalization import normalize_ioc_value


def make_samples(count_per_label: int = 10) -> list[DomainSample]:
    return [
        *[
            DomainSample(f"malicious-{index}.example", 1, "ThreatFox")
            for index in range(count_per_label)
        ],
        *[
            DomainSample(f"benign-{index}.example", 0, "Tranco")
            for index in range(count_per_label)
        ],
    ]


def domains(samples: list[DomainSample]) -> set[str]:
    return {
        normalize_ioc_value(sample.domain, IOCType.DOMAIN) for sample in samples
    }


def test_default_split_is_80_20_and_stratified() -> None:
    samples = make_samples()

    result = split_domain_dataset(samples)

    assert isinstance(result, DomainDatasetSplit)
    assert len(result.train) == 16
    assert len(result.test) == 4
    assert {sample.label for sample in result.train} == {0, 1}
    assert {sample.label for sample in result.test} == {0, 1}


def test_default_split_is_deterministic() -> None:
    samples = make_samples()

    first = split_domain_dataset(samples)
    second = split_domain_dataset(samples)

    assert first == second


def test_changing_random_state_can_change_split() -> None:
    samples = make_samples()

    first = split_domain_dataset(samples, random_state=42)
    second = split_domain_dataset(samples, random_state=7)

    assert first != second


def test_generator_input_is_materialized_and_split() -> None:
    samples = make_samples()

    result = split_domain_dataset(sample for sample in samples)

    assert len(result.train) + len(result.test) == len(samples)
    assert {sample.label for sample in result.train} == {0, 1}
    assert {sample.label for sample in result.test} == {0, 1}


def test_input_objects_are_preserved_by_identity() -> None:
    samples = make_samples()

    result = split_domain_dataset(samples)

    output_objects = result.train + result.test
    assert {id(sample) for sample in output_objects} == {id(sample) for sample in samples}


def test_input_list_is_not_mutated() -> None:
    samples = make_samples()
    original = samples.copy()

    split_domain_dataset(samples)

    assert samples == original
    assert samples is not original


def test_train_and_test_have_no_normalized_domain_overlap() -> None:
    result = split_domain_dataset(make_samples())

    assert not domains(result.train) & domains(result.test)


def test_duplicate_normalized_domain_raises_value_error() -> None:
    samples = make_samples()
    samples.append(DomainSample("malicious-0.example", 1, "SGB"))

    with pytest.raises(ValueError, match="duplicate normalized domain"):
        split_domain_dataset(samples)


def test_case_and_trailing_dot_duplicate_raises_value_error() -> None:
    samples = make_samples()
    samples.append(DomainSample("MALICIOUS-0.EXAMPLE.", 1, "SGB"))

    with pytest.raises(ValueError, match="duplicate normalized domain"):
        split_domain_dataset(samples)


def test_conflicting_labels_for_normalized_domain_raise_value_error() -> None:
    samples = make_samples()
    samples.append(DomainSample("MALICIOUS-0.EXAMPLE.", 0, "Tranco"))

    with pytest.raises(ValueError, match="conflicting labels"):
        split_domain_dataset(samples)


def test_one_class_dataset_raises_value_error() -> None:
    with pytest.raises(ValueError, match="both labels"):
        split_domain_dataset([DomainSample("only.example", 1, "ThreatFox")])


def test_empty_dataset_raises_value_error() -> None:
    with pytest.raises(ValueError, match="empty dataset"):
        split_domain_dataset([])


@pytest.mark.parametrize("test_size", [0, 1, -0.1, 1.1, math.nan, math.inf, -math.inf])
def test_invalid_test_size_raises_value_error(test_size: float) -> None:
    with pytest.raises(ValueError, match="test_size"):
        split_domain_dataset(make_samples(), test_size=test_size)


def test_non_numeric_test_size_raises_value_error() -> None:
    with pytest.raises(ValueError, match="test_size"):
        split_domain_dataset(make_samples(), test_size="0.2")  # type: ignore[arg-type]


def test_too_few_samples_for_stratification_raises_clear_value_error() -> None:
    samples = [
        DomainSample("malicious.example", 1, "ThreatFox"),
        DomainSample("benign-one.example", 0, "Tranco"),
        DomainSample("benign-two.example", 0, "Tranco"),
        DomainSample("benign-three.example", 0, "Tranco"),
    ]

    with pytest.raises(ValueError, match="too few samples for stratified splitting"):
        split_domain_dataset(samples)
