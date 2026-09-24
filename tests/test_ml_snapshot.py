from __future__ import annotations

import socket

import pytest

from threatfusion.ml_snapshot import (
    DatasetSnapshotMetadata,
    DatasetSnapshotStatistics,
    DomainDatasetSnapshot,
    build_domain_snapshot,
    parse_tranco_csv,
)
from threatfusion.models import IOCRecord, IOCType


def test_parse_tranco_csv_reads_rank_domain_rows_in_order() -> None:
    content = "1, first.example\n2,second.example\n3,third.example\n"

    assert parse_tranco_csv(content) == [
        "first.example",
        "second.example",
        "third.example",
    ]


def test_parse_tranco_csv_ignores_blank_and_malformed_rows() -> None:
    content = "rank,domain\n\n1, first.example \nmalformed\n,missing-rank.example\n2,second.example\n"

    assert parse_tranco_csv(content) == ["first.example", "second.example"]


def test_parse_tranco_csv_tolerates_extra_columns() -> None:
    content = "1,first.example,ignored\n2,second.example,also-ignored\n"

    assert parse_tranco_csv(content) == ["first.example", "second.example"]


def test_parse_tranco_csv_limit_returns_maximum_valid_rows() -> None:
    content = "1,first.example\nmalformed\n2,second.example\n3,third.example\n"

    assert parse_tranco_csv(content, limit=2) == ["first.example", "second.example"]


@pytest.mark.parametrize("limit", [0, -1, True, "2"])
def test_parse_tranco_csv_rejects_invalid_limit(limit: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        parse_tranco_csv("1,example.com\n", limit=limit)  # type: ignore[arg-type]


def test_parse_tranco_csv_empty_content_is_safe() -> None:
    assert parse_tranco_csv("") == []


def test_parse_tranco_csv_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access should not occur during CSV parsing")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    assert parse_tranco_csv("1,example.com\n") == ["example.com"]


def snapshot_indicators() -> list[IOCRecord]:
    return [
        IOCRecord("evil.example", IOCType.DOMAIN, "ThreatFox"),
        IOCRecord("EVIL.EXAMPLE.", IOCType.DOMAIN, "SGB"),
        IOCRecord("https://url.example/path", IOCType.URL, "URLhaus"),
        IOCRecord("https://shared.example/path", IOCType.URL, "URLhaus"),
        IOCRecord("203.0.113.7", IOCType.IPV4, "ThreatFox"),
        IOCRecord("hash-value", IOCType.SHA256, "SGB"),
    ]


def test_snapshot_integrates_iocs_benign_domains_and_statistics() -> None:
    snapshot = build_domain_snapshot(
        snapshot_indicators(),
        ["shared.example", "Safe.Example.", "safe.example", ""],
        benign_source="Tranco",
        benign_snapshot_id="ABCDE",
        benign_snapshot_date="2026-09-24",
    )

    assert [sample.domain for sample in snapshot.samples] == [
        "evil.example",
        "url.example",
        "shared.example",
        "safe.example",
    ]
    assert [sample.label for sample in snapshot.samples] == [1, 1, 1, 0]
    assert snapshot.statistics == DatasetSnapshotStatistics(
        malicious_input_count=4,
        benign_input_count=4,
        malicious_unique_count=3,
        benign_unique_count=2,
        final_malicious_count=3,
        final_benign_count=1,
        final_total_count=4,
        overlap_removed_from_benign=1,
        malicious_by_source={"ThreatFox": 1, "URLhaus": 2},
    )


def test_snapshot_preserves_metadata_exactly() -> None:
    snapshot = build_domain_snapshot(
        [],
        [],
        benign_source="custom-benign",
        benign_snapshot_id="snapshot-1",
        benign_snapshot_date="2026-09-24",
    )

    assert snapshot.metadata == DatasetSnapshotMetadata(
        benign_source="custom-benign",
        benign_snapshot_id="snapshot-1",
        benign_snapshot_date="2026-09-24",
    )
    assert isinstance(snapshot, DomainDatasetSnapshot)


def test_snapshot_uses_benign_normalization_and_deduplication() -> None:
    snapshot = build_domain_snapshot(
        [],
        [" Example.COM. ", "example.com", "safe.example"],
    )

    assert [sample.domain for sample in snapshot.samples] == [
        "example.com",
        "safe.example",
    ]
    assert snapshot.statistics.benign_input_count == 3
    assert snapshot.statistics.benign_unique_count == 2


def test_snapshot_excludes_overlap_from_benign_side() -> None:
    indicators = [IOCRecord("Example.COM.", IOCType.DOMAIN, "ThreatFox")]

    snapshot = build_domain_snapshot(indicators, ["example.com", "safe.example"])

    assert [sample.domain for sample in snapshot.samples] == [
        "example.com",
        "safe.example",
    ]
    assert snapshot.statistics.overlap_removed_from_benign == 1
    assert snapshot.statistics.final_benign_count == 1


def test_snapshot_source_counts_use_retained_malicious_sources() -> None:
    indicators = [
        IOCRecord("same.example", IOCType.DOMAIN, "ThreatFox"),
        IOCRecord("SAME.EXAMPLE.", IOCType.DOMAIN, "SGB"),
        IOCRecord("other.example", IOCType.DOMAIN, "SGB"),
    ]

    snapshot = build_domain_snapshot(indicators, [])

    assert snapshot.statistics.malicious_by_source == {"ThreatFox": 1, "SGB": 1}


def test_snapshot_accepts_generator_inputs() -> None:
    indicators = (indicator for indicator in snapshot_indicators())
    benign_domains = (
        domain for domain in ["shared.example", "safe.example", "safe.example"]
    )

    snapshot = build_domain_snapshot(indicators, benign_domains)

    assert snapshot.statistics.malicious_input_count == 4
    assert snapshot.statistics.benign_input_count == 3
    assert [sample.domain for sample in snapshot.samples] == [
        "evil.example",
        "url.example",
        "shared.example",
        "safe.example",
    ]


def test_snapshot_does_not_mutate_ioc_records() -> None:
    indicators = snapshot_indicators()
    original_values = [indicator.value for indicator in indicators]

    build_domain_snapshot(indicators, ["safe.example"])

    assert [indicator.value for indicator in indicators] == original_values


def test_snapshot_output_is_deterministic() -> None:
    indicators = snapshot_indicators()
    benign_domains = ["safe.example", "shared.example"]

    first = build_domain_snapshot(indicators, benign_domains)
    second = build_domain_snapshot(indicators, benign_domains)

    assert first == second


def test_empty_indicators_with_valid_benign_data() -> None:
    snapshot = build_domain_snapshot([], ["safe.example", "popular.example"])

    assert snapshot.statistics.final_malicious_count == 0
    assert snapshot.statistics.final_benign_count == 2
    assert snapshot.statistics.final_total_count == 2


def test_empty_benign_data_with_valid_malicious_data() -> None:
    snapshot = build_domain_snapshot(
        [IOCRecord("evil.example", IOCType.DOMAIN, "ThreatFox")], []
    )

    assert snapshot.statistics.final_malicious_count == 1
    assert snapshot.statistics.final_benign_count == 0
    assert snapshot.statistics.final_total_count == 1


def test_both_inputs_empty_are_handled() -> None:
    snapshot = build_domain_snapshot([], [])

    assert snapshot.samples == []
    assert snapshot.statistics == DatasetSnapshotStatistics(
        malicious_input_count=0,
        benign_input_count=0,
        malicious_unique_count=0,
        benign_unique_count=0,
        final_malicious_count=0,
        final_benign_count=0,
        final_total_count=0,
        overlap_removed_from_benign=0,
        malicious_by_source={},
    )
