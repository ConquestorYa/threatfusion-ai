from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from threatfusion.cti_cache import (
    initialize_cti_cache,
    list_cti_cache_status,
    list_cti_lifecycle_records,
    load_ioc_records,
    lookup_ioc_records,
    prune_inactive_records,
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


def test_load_normalizes_legacy_naive_cache_timestamp_to_utc(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(
        db_path,
        "SGB",
        [
            IOCRecord(
                "legacy.example",
                IOCType.DOMAIN,
                "SGB",
                first_seen=datetime(2026, 9, 28, 19, 22, 20, tzinfo=timezone.utc),
            )
        ],
    )

    with __import__("sqlite3").connect(db_path) as connection:
        connection.execute(
            "UPDATE cti_records SET first_seen = ? WHERE source = ?",
            ("2026-09-28T19:22:20", "SGB"),
        )

    loaded = load_ioc_records(db_path, sources=["SGB"])

    assert loaded[0].first_seen == datetime(
        2026, 9, 28, 19, 22, 20, tzinfo=timezone.utc
    )


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


def test_indexed_lookup_returns_only_matching_domain_and_url_candidates(
    tmp_path,
) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(
        db_path,
        "ThreatFox",
        [
            IOCRecord("target.example", IOCType.DOMAIN, "ThreatFox"),
            IOCRecord("other.example", IOCType.DOMAIN, "ThreatFox"),
        ],
    )
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "https://target.example/payload",
                IOCType.URL,
                "URLhaus",
            ),
            IOCRecord(
                "https://unrelated.example/payload",
                IOCType.URL,
                "URLhaus",
            ),
        ],
    )

    matches = lookup_ioc_records(
        db_path,
        domain="TARGET.EXAMPLE.",
        normalized_url="https://target.example/payload",
    )

    assert [(item.source, item.value) for item in matches] == [
        ("ThreatFox", "target.example"),
        ("URLhaus", "https://target.example/payload"),
    ]


def test_indexed_lookup_supports_exact_ipv4_and_ip_hosted_url(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("143.20.185.213", IOCType.IPV4, "ThreatFox")],
    )
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "http://143.20.185.213/armv7",
                IOCType.URL,
                "URLhaus",
            ),
        ],
    )

    matches = lookup_ioc_records(
        db_path,
        domain="143.20.185.213",
        ip_address="143.20.185.213",
        normalized_url="http://143.20.185.213/armv7",
    )

    assert {(item.ioc_type, item.value) for item in matches} == {
        (IOCType.IPV4, "143.20.185.213"),
        (IOCType.URL, "http://143.20.185.213/armv7"),
    }


def test_indexed_lookup_supports_ipv6_url_normalization(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("2001:4860:4860::8888", IOCType.IPV6, "ThreatFox")],
    )
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "http://[2001:4860:4860::8888]/payload",
                IOCType.URL,
                "URLhaus",
            ),
        ],
    )

    matches = lookup_ioc_records(
        db_path,
        domain="2001:4860:4860::8888",
        ip_address="2001:4860:4860::8888",
        normalized_url="http://[2001:4860:4860::8888]/payload",
    )

    assert len(matches) == 2


def test_indexed_lookup_excludes_inactive_indicators(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("old.example", IOCType.DOMAIN, "ThreatFox")],
    )
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("current.example", IOCType.DOMAIN, "ThreatFox")],
    )

    assert lookup_ioc_records(db_path, domain="old.example") == []


def test_inactive_retention_prunes_only_old_history(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    second = datetime(2026, 1, 2, tzinfo=timezone.utc)
    reference = datetime(2026, 5, 1, tzinfo=timezone.utc)

    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("old.example", IOCType.DOMAIN, "ThreatFox")],
        refreshed_at=first,
    )
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("current.example", IOCType.DOMAIN, "ThreatFox")],
        refreshed_at=second,
    )

    removed = prune_inactive_records(
        db_path,
        older_than_days=90,
        now=reference,
    )

    assert removed == 1
    assert [item.value for item in load_ioc_records(db_path, include_inactive=True)] == [
        "current.example"
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

def test_refresh_preserves_inactive_ioc_lifecycle_history(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"
    first_refresh = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
    second_refresh = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)

    replace_source_records(
        db_path,
        "ThreatFox",
        [
            IOCRecord("stays.example", IOCType.DOMAIN, "ThreatFox"),
            IOCRecord("expires.example", IOCType.DOMAIN, "ThreatFox"),
        ],
        refreshed_at=first_refresh,
    )
    replace_source_records(
        db_path,
        "ThreatFox",
        [
            IOCRecord("stays.example", IOCType.DOMAIN, "ThreatFox"),
            IOCRecord("new.example", IOCType.DOMAIN, "ThreatFox"),
        ],
        refreshed_at=second_refresh,
    )

    assert [record.value for record in load_ioc_records(db_path)] == [
        "stays.example",
        "new.example",
    ]
    assert [
        record.value
        for record in load_ioc_records(db_path, include_inactive=True)
    ] == [
        "stays.example",
        "expires.example",
        "new.example",
    ]

    lifecycle = {
        item.indicator.value: item
        for item in list_cti_lifecycle_records(db_path)
    }
    assert lifecycle["stays.example"].active is True
    assert lifecycle["stays.example"].first_seen_in_cache == first_refresh.isoformat()
    assert lifecycle["stays.example"].last_seen_in_refresh == second_refresh.isoformat()
    assert lifecycle["expires.example"].active is False
    assert lifecycle["expires.example"].last_seen_in_refresh == first_refresh.isoformat()
    assert lifecycle["new.example"].active is True
    assert lifecycle["new.example"].first_seen_in_cache == second_refresh.isoformat()

    status = list_cti_cache_status(db_path)[0]
    assert status.record_count == 2
    assert status.inactive_record_count == 1


def test_lifecycle_refresh_deduplicates_same_indicator_identity(tmp_path) -> None:
    db_path = tmp_path / "threatfusion.sqlite"

    count = replace_source_records(
        db_path,
        "SGB",
        [
            IOCRecord("same.example", IOCType.DOMAIN, "SGB"),
            IOCRecord("same.example", IOCType.DOMAIN, "SGB"),
        ],
    )

    assert count == 1
    assert len(load_ioc_records(db_path)) == 1
    assert list_cti_cache_status(db_path)[0].record_count == 1


def test_existing_pre_lifecycle_database_is_migrated_in_place(tmp_path) -> None:
    import sqlite3

    db_path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE cti_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                threat_type TEXT,
                confidence REAL,
                tags_json TEXT NOT NULL
            );
            CREATE TABLE cti_refreshes (
                source TEXT PRIMARY KEY,
                refreshed_at TEXT NOT NULL,
                record_count INTEGER NOT NULL
            );
            INSERT INTO cti_records (
                value, ioc_type, source, tags_json
            ) VALUES (
                'legacy.example', 'domain', 'ThreatFox', '[]'
            );
            INSERT INTO cti_refreshes (
                source, refreshed_at, record_count
            ) VALUES (
                'ThreatFox', '2026-09-24T10:00:00+00:00', 1
            );
            """
        )

    initialize_cti_cache(db_path)

    assert [item.value for item in load_ioc_records(db_path)] == [
        "legacy.example"
    ]
    lifecycle = list_cti_lifecycle_records(db_path)
    assert lifecycle[0].active is True
    assert lifecycle[0].first_seen_in_cache is None
    assert lifecycle[0].last_seen_in_refresh is None

    refresh_time = datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc)
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("legacy.example", IOCType.DOMAIN, "ThreatFox")],
        refreshed_at=refresh_time,
    )
    migrated = list_cti_lifecycle_records(db_path)[0]
    assert migrated.first_seen_in_cache == refresh_time.isoformat()
    assert migrated.last_seen_in_refresh == refresh_time.isoformat()

