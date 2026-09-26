from __future__ import annotations

import socket

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.ml_augmented_development import (
    build_augmented_development_snapshot,
    calculate_benign_source_fpr,
    prepare_augmented_development_samples,
)
from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_fpr_comparison import run_fpr_budget_comparison
from threatfusion.ml_snapshot import (
    DatasetSnapshotMetadata,
    DatasetSnapshotStatistics,
    DomainDatasetSnapshot,
)


def test_prepare_augmented_development_samples_filters_and_deduplicates() -> None:
    base = [
        DomainSample("seen-benign.example", 0, "Tranco"),
        DomainSample("seen-malicious.example", 1, "ThreatFox"),
    ]
    events = [
        DNSEvent(query_name="seen-benign.example"),
        DNSEvent(query_name="seen-malicious.example"),
        DNSEvent(query_name="new-one.example"),
        DNSEvent(query_name="NEW-ONE.EXAMPLE."),
        DNSEvent(query_name="new-two.example"),
        DNSEvent(query_name="printer.local"),
        DNSEvent(query_name="invalid domain"),
    ]

    prepared = prepare_augmented_development_samples(base, events)

    assert prepared.input_event_count == 7
    assert prepared.public_candidate_event_count == 5
    assert prepared.unique_candidate_count == 4
    assert prepared.overlap_with_base_removed == 2
    assert prepared.added_benign_count == 2
    assert prepared.samples[-2:] == (
        DomainSample("new-one.example", 0, "CESNET"),
        DomainSample("new-two.example", 0, "CESNET"),
    )


def test_prepare_augmented_development_samples_requires_new_domains() -> None:
    base = [DomainSample("seen.example", 0, "Tranco")]

    with pytest.raises(ValueError, match="added no new public domains"):
        prepare_augmented_development_samples(
            base,
            [DNSEvent(query_name="seen.example")],
        )


def test_build_augmented_development_snapshot_preserves_provenance() -> None:
    base = DomainDatasetSnapshot(
        samples=[
            DomainSample("bad.example", 1, "ThreatFox"),
            DomainSample("safe.example", 0, "Tranco"),
        ],
        metadata=DatasetSnapshotMetadata(
            benign_source="Tranco",
            benign_snapshot_id="L5PV4",
            benign_snapshot_date="2026-09-23",
        ),
        statistics=DatasetSnapshotStatistics(
            malicious_input_count=1,
            benign_input_count=1,
            malicious_unique_count=1,
            benign_unique_count=1,
            final_malicious_count=1,
            final_benign_count=1,
            final_total_count=2,
            overlap_removed_from_benign=0,
            malicious_by_source={"ThreatFox": 1},
        ),
    )

    snapshot, preparation = build_augmented_development_snapshot(
        base,
        [
            DNSEvent(query_name="safe.example"),
            DNSEvent(query_name="longtail.example"),
        ],
        source="CESNET",
        source_snapshot_id="zenodo-14332167-first20k",
    )

    assert preparation.added_benign_count == 1
    assert snapshot.metadata.benign_source == "Tranco+CESNET"
    assert (
        snapshot.metadata.benign_snapshot_id
        == "L5PV4+zenodo-14332167-first20k"
    )
    assert snapshot.metadata.benign_snapshot_date == "2026-09-23"
    assert snapshot.statistics.final_total_count == 3
    assert snapshot.statistics.final_malicious_count == 1
    assert snapshot.statistics.final_benign_count == 2
    assert snapshot.statistics.malicious_by_source == {"ThreatFox": 1}


def test_calculate_benign_source_fpr_groups_only_benign_sources() -> None:
    samples = [
        DomainSample("a.example", 0, "Tranco"),
        DomainSample("b.example", 0, "Tranco"),
        DomainSample("c.example", 0, "CESNET"),
        DomainSample("bad.example", 1, "ThreatFox"),
    ]

    result = calculate_benign_source_fpr(samples, [0, 1, 1, 1])

    assert [item.source for item in result] == ["CESNET", "Tranco"]
    assert result[0].total == 1
    assert result[0].false_positive == 1
    assert result[0].false_positive_rate == pytest.approx(1.0)
    assert result[1].total == 2
    assert result[1].false_positive == 1
    assert result[1].true_negative == 1
    assert result[1].false_positive_rate == pytest.approx(0.5)


def test_calculate_benign_source_fpr_rejects_invalid_inputs() -> None:
    sample = DomainSample("a.example", 0, "Tranco")

    with pytest.raises(ValueError, match="same length"):
        calculate_benign_source_fpr([sample], [])

    with pytest.raises(ValueError, match="0 or 1"):
        calculate_benign_source_fpr([sample], [2])


def test_augmented_samples_support_low_fpr_comparison() -> None:
    base = [
        *[
            DomainSample(f"bad-{index:03d}.malicious.test", 1, "ThreatFox")
            for index in range(60)
        ],
        *[
            DomainSample(f"popular-{index:03d}.benign.test", 0, "Tranco")
            for index in range(60)
        ],
    ]
    events = [
        DNSEvent(query_name=f"longtail-{index:03d}.benign.test")
        for index in range(60)
    ]
    prepared = prepare_augmented_development_samples(base, events)

    result = run_fpr_budget_comparison(
        prepared.samples,
        fpr_budgets=(0.001, 0.005, 0.01),
    )

    assert len(result.candidates) == 3
    assert any(
        sample.source == "CESNET"
        for sample in result.split.test
        if sample.label == 0
    )


def test_augmented_development_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("augmented development must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    base = [
        DomainSample("bad-one.example", 1, "ThreatFox"),
        DomainSample("bad-two.example", 1, "ThreatFox"),
        DomainSample("good-one.example", 0, "Tranco"),
        DomainSample("good-two.example", 0, "Tranco"),
    ]
    prepared = prepare_augmented_development_samples(
        base,
        [
            DNSEvent(query_name="long-one.example"),
            DNSEvent(query_name="long-two.example"),
        ],
    )

    assert prepared.added_benign_count == 2
