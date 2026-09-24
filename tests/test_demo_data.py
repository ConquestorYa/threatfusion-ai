from __future__ import annotations

import csv
import io
import socket

import pytest

from threatfusion.demo_data import build_demo_dns_csv
from threatfusion.models import IOCRecord, IOCType


def parse_rows(content: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(content)))


def test_demo_dataset_includes_one_cached_domain_ioc() -> None:
    dataset = build_demo_dns_csv(
        [
            IOCRecord("known.example", IOCType.DOMAIN, "ThreatFox"),
            IOCRecord("https://not-used.example/path", IOCType.URL, "URLhaus"),
        ]
    )
    rows = parse_rows(dataset.content)

    assert dataset.includes_known_ioc is True
    assert dataset.row_count == 24
    assert rows[0]["query_name"] == "known.example"


def test_demo_dataset_has_deterministic_behavior_burst() -> None:
    dataset = build_demo_dns_csv([])
    rows = parse_rows(dataset.content)

    burst_rows = [
        row for row in rows if row["query_name"] == "demo-burst.example"
    ]

    assert dataset.includes_known_ioc is False
    assert dataset.synthetic_burst_rows == 20
    assert dataset.row_count == 23
    assert len(burst_rows) == 20
    assert len({row["client_ip"] for row in burst_rows}) == 3
    assert len({row["response_ip"] for row in burst_rows}) == 3
    assert {row["query_type"] for row in burst_rows} == {"A", "AAAA", "TXT"}


def test_demo_dataset_uses_reserved_example_networks_for_synthetic_rows() -> None:
    dataset = build_demo_dns_csv([])
    rows = parse_rows(dataset.content)

    assert all(
        row["client_ip"].startswith("192.0.2.")
        for row in rows
    )
    assert all(
        row["response_ip"].startswith(
            ("198.51.100.", "203.0.113.", "2001:db8:")
        )
        for row in rows
    )


def test_known_domain_selection_is_deterministic() -> None:
    dataset = build_demo_dns_csv(
        [
            IOCRecord("z.example", IOCType.DOMAIN, "ThreatFox"),
            IOCRecord("a.example", IOCType.DOMAIN, "SGB"),
        ]
    )
    rows = parse_rows(dataset.content)

    assert rows[0]["query_name"] == "a.example"


def test_demo_generator_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("demo dataset generation must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    dataset = build_demo_dns_csv(
        [IOCRecord("known.example", IOCType.DOMAIN, "ThreatFox")]
    )

    assert dataset.row_count == 24
