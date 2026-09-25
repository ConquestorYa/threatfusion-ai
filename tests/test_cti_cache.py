from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from threatfusion.cti_cache import (
    initialize_cti_cache,
    list_cti_cache_status,
    load_ioc_records,
    replace_source_records,
    validate_nonempty_refresh_batch,
)
from threatfusion.models import IOCRecord, IOCType


def make_records() -> list[IOCRecord]:
    return [
        IOCRecord(
            value="Example.Bad.",
            ioc_type=IOCType.DOMAIN,
            source="ThreatFox",
            first_seen=datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc),
            last_seen=datetime(2026, 9, 24, 11, 0, tzinfo=timezone.utc),
            threat_type="botnet_cc",
            confidence=0.9,
            tags=["tag-a", "tag-b"],
        ),
        IOCRecord(
            value="203.0.113.9",
            ioc_type=IOCType.IPV4,
            source="ThreatFox",
            tags=[],
        ),
    ]


def test_replace_and_load_source_records_roundtrip(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    refresh_time = datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc)

    count = replace_source_records(
        db_path,
        "ThreatFox",
        make_records(),
        refreshed_at=refresh_time,
    )
    loaded = load_ioc_records(db_path)

    assert count == 2
    assert len(loaded) == 2
    assert loaded[0].value == "Example.Bad."
    assert loaded[0].ioc_type is IOCType.DOMAIN
    assert loaded[0].source == "ThreatFox"
    assert loaded[0].first_seen == make_records()[0].first_seen
    assert loaded[0].last_seen == make_records()[0].last_seen
    assert loaded[0].threat_type == "botnet_cc"
    assert loaded[0].confidence == pytest.approx(0.9)
    assert loaded[0].tags == ["tag-a", "tag-b"]


def test_replace_is_atomic_per_source_and_does_not_touch_other_sources(
    tmp_path,
) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(db_path, "ThreatFox", make_records())
    replace_source_records(
        db_path,
        "SGB",
        [IOCRecord("sgb.example", IOCType.DOMAIN, "SGB")],
    )

    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("new.example", IOCType.DOMAIN, "ThreatFox")],
    )

    all_records = load_ioc_records(db_path)
    assert [(item.source, item.value) for item in all_records] == [
        ("SGB", "sgb.example"),
        ("ThreatFox", "new.example"),
    ]


def test_source_filtering_is_supported(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(db_path, "ThreatFox", make_records())
    replace_source_records(
        db_path,
        "SGB",
        [IOCRecord("sgb.example", IOCType.DOMAIN, "SGB")],
    )

    loaded = load_ioc_records(db_path, sources=["SGB"])

    assert len(loaded) == 1
    assert loaded[0].source == "SGB"


def test_refresh_status_records_count_and_time(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    refresh_time = datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc)

    replace_source_records(
        db_path,
        "ThreatFox",
        make_records(),
        refreshed_at=refresh_time,
    )

    status = list_cti_cache_status(db_path)

    assert status[0].source == "ThreatFox"
    assert status[0].refreshed_at == refresh_time.isoformat()
    assert status[0].record_count == 2




def test_refresh_batch_rejects_empty_source_before_cache_write() -> None:
    with pytest.raises(ValueError, match="URLhaus"):
        validate_nonempty_refresh_batch(
            {
                "ThreatFox": make_records(),
                "URLhaus": [],
                "SGB": [IOCRecord("sgb.example", IOCType.DOMAIN, "SGB")],
            }
        )


def test_refresh_batch_accepts_nonempty_sources() -> None:
    validate_nonempty_refresh_batch(
        {
            "ThreatFox": make_records(),
            "URLhaus": [
                IOCRecord(
                    "https://example.invalid/path",
                    IOCType.URL,
                    "URLhaus",
                )
            ],
            "SGB": [IOCRecord("sgb.example", IOCType.DOMAIN, "SGB")],
        }
    )

def test_mismatched_source_is_rejected_without_replacing_cache(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(db_path, "ThreatFox", make_records())

    with pytest.raises(ValueError, match="source"):
        replace_source_records(
            db_path,
            "ThreatFox",
            [IOCRecord("wrong.example", IOCType.DOMAIN, "SGB")],
        )

    assert len(load_ioc_records(db_path, sources=["ThreatFox"])) == 2


def test_naive_refresh_time_is_rejected(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"

    with pytest.raises(ValueError, match="timezone-aware"):
        replace_source_records(
            db_path,
            "ThreatFox",
            make_records(),
            refreshed_at=datetime(
                2026, 9, 24, 18, 0, tzinfo=timezone.utc
            ).replace(tzinfo=None),
        )


def test_empty_source_filter_returns_empty_list(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    initialize_cti_cache(db_path)

    assert load_ioc_records(db_path, sources=[]) == []


def test_cti_cache_does_not_perform_networking(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("CTI cache must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(db_path, "ThreatFox", make_records())

    assert load_ioc_records(db_path)
