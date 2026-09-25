import sqlite3
from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_pihole import (
    parse_pihole_query_db,
    parse_pihole_query_db_with_diagnostics,
)


def make_pihole_database(tmp_path, rows) -> bytes:
    path = tmp_path / "pihole-FTL.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE queries (
                id INTEGER PRIMARY KEY,
                timestamp,
                type,
                domain,
                client
            )
            """
        )
        connection.executemany(
            """
            INSERT INTO queries (
                id,
                timestamp,
                type,
                domain,
                client
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            rows,
        )
    return path.read_bytes()


def test_parse_pihole_database_maps_query_view(tmp_path) -> None:
    content = make_pihole_database(
        tmp_path,
        [
            (1, 1700000000, 1, "Example.COM", "10.0.0.5"),
            (2, 1700000001, 166, "type66.example", "10.0.0.6"),
        ],
    )

    events = parse_pihole_query_db(content)

    assert events == [
        DNSEvent(
            query_name="Example.COM",
            timestamp=datetime.fromtimestamp(1700000000, tz=timezone.utc),
            client_ip="10.0.0.5",
            query_type="A",
            response_ip=None,
        ),
        DNSEvent(
            query_name="type66.example",
            timestamp=datetime.fromtimestamp(1700000001, tz=timezone.utc),
            client_ip="10.0.0.6",
            query_type="TYPE66",
            response_ip=None,
        ),
    ]


def test_pihole_diagnostics_report_bad_rows(tmp_path) -> None:
    content = make_pihole_database(
        tmp_path,
        [
            (1, "bad-time", 1, "valid.example", "10.0.0.5"),
            (2, 1700000001, 2, "", "10.0.0.6"),
        ],
    )

    parsed = parse_pihole_query_db_with_diagnostics(content)

    assert parsed.diagnostics.total_rows == 2
    assert parsed.diagnostics.accepted_rows == 1
    assert parsed.diagnostics.skipped_missing_query_name == 1
    assert parsed.diagnostics.invalid_timestamps == 1
    assert parsed.diagnostics.invalid_response_ips == 0


def test_pihole_import_does_not_treat_forwarding_as_response_ip(tmp_path) -> None:
    path = tmp_path / "pihole-FTL.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE queries (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER,
                type INTEGER,
                domain TEXT,
                client TEXT,
                forward TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO queries
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                1700000000,
                1,
                "example.com",
                "10.0.0.5",
                "203.0.113.53#53",
            ),
        )

    event = parse_pihole_query_db(path.read_bytes())[0]

    assert event.response_ip is None


def test_pihole_database_requires_standard_query_columns(tmp_path) -> None:
    path = tmp_path / "bad.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE queries (id INTEGER, domain TEXT)")

    with pytest.raises(ValueError, match="missing required columns"):
        parse_pihole_query_db(path.read_bytes())


def test_invalid_or_empty_pihole_database_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        parse_pihole_query_db(b"")

    with pytest.raises(ValueError, match="SQLite|database"):
        parse_pihole_query_db(b"not-a-sqlite-database")
