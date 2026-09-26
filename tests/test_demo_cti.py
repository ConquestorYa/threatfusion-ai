from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from threatfusion.cti_cache import list_cti_cache_status, load_ioc_records
from threatfusion.demo_cti import (
    build_public_demo_iocs,
    write_public_demo_cti_cache,
)
from threatfusion.models import IOCType


def test_public_demo_iocs_use_only_synthetic_documentation_values() -> None:
    records = build_public_demo_iocs()

    assert {record.source for record in records} == {"ThreatFusion Demo"}
    assert {record.ioc_type for record in records} == {
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.IPV4,
        IOCType.IPV6_NETWORK,
    }
    assert any(record.value == "known-threat.example" for record in records)
    assert any(record.value == "203.0.113.66" for record in records)
    assert all("documentation-only" in record.tags for record in records)


def test_public_demo_cache_is_fresh_and_contains_only_demo_source(tmp_path) -> None:
    db_path = tmp_path / "public_demo.sqlite"
    refreshed_at = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)

    count = write_public_demo_cti_cache(
        db_path,
        refreshed_at=refreshed_at,
    )

    records = load_ioc_records(db_path)
    statuses = list_cti_cache_status(db_path)

    assert count == 4
    assert len(records) == 4
    assert {record.source for record in records} == {"ThreatFusion Demo"}
    assert len(statuses) == 1
    assert statuses[0].source == "ThreatFusion Demo"
    assert statuses[0].record_count == 4
    assert statuses[0].refreshed_at == refreshed_at.isoformat()


def test_public_demo_cache_generation_does_not_use_network(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("public demo cache generation must not network")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    count = write_public_demo_cti_cache(tmp_path / "demo.sqlite")

    assert count == 4
