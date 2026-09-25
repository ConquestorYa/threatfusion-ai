from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult

MAX_PIHOLE_EVENTS = 100_000

_QUERY_TYPE_NAMES = {
    1: "A",
    2: "AAAA",
    3: "ANY",
    4: "SRV",
    5: "SOA",
    6: "PTR",
    7: "TXT",
    8: "NAPTR",
    9: "MX",
    10: "DS",
    11: "RRSIG",
    12: "DNSKEY",
    13: "NS",
    14: "OTHER",
    15: "SVCB",
    16: "HTTPS",
}


def _query_type_name(value: object) -> str | None:
    try:
        query_type = int(value)
    except (TypeError, ValueError):
        return None

    if query_type in _QUERY_TYPE_NAMES:
        return _QUERY_TYPE_NAMES[query_type]
    if query_type >= 100:
        return f"TYPE{query_type - 100}"
    return f"TYPE{query_type}"


def _timestamp(value: object) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (OverflowError, OSError, TypeError, ValueError):
        return None


def _open_uploaded_database(content: bytes) -> sqlite3.Connection:
    if not isinstance(content, bytes) or not content:
        raise ValueError("Pi-hole database upload is empty")

    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(content)
    except (AttributeError, sqlite3.DatabaseError) as error:
        connection.close()
        raise ValueError("uploaded file is not a readable SQLite database") from error
    return connection


def parse_pihole_query_db_with_diagnostics(content: bytes) -> DNSParseResult:
    """Parse an uploaded Pi-hole FTL query database entirely in memory."""
    connection = _open_uploaded_database(content)
    try:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(queries)").fetchall()
        }
        required = {"id", "timestamp", "type", "domain", "client"}
        missing = sorted(required - columns)
        if missing:
            raise ValueError(
                "Pi-hole queries view is missing required columns: "
                + ", ".join(missing)
            )

        cursor = connection.execute(
            """
            SELECT id, timestamp, type, domain, client
            FROM queries
            ORDER BY id ASC
            LIMIT ?
            """,
            (MAX_PIHOLE_EVENTS + 1,),
        )
        rows = cursor.fetchall()
    except sqlite3.DatabaseError as error:
        raise ValueError("Pi-hole query database could not be read") from error
    finally:
        connection.close()

    if len(rows) > MAX_PIHOLE_EVENTS:
        raise ValueError(
            f"Pi-hole input exceeds the {MAX_PIHOLE_EVENTS} event import limit"
        )

    events: list[DNSEvent] = []
    skipped_missing_query_name = 0
    invalid_timestamps = 0

    for _, raw_timestamp, raw_type, raw_domain, raw_client in rows:
        domain = str(raw_domain).strip() if raw_domain is not None else ""
        if not domain:
            skipped_missing_query_name += 1
            continue

        timestamp = _timestamp(raw_timestamp)
        if timestamp is None:
            invalid_timestamps += 1

        client = str(raw_client).strip() if raw_client is not None else ""
        events.append(
            DNSEvent(
                query_name=domain,
                timestamp=timestamp,
                client_ip=client or None,
                query_type=_query_type_name(raw_type),
                response_ip=None,
            )
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=len(rows),
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_query_name,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=0,
        ),
    )


def parse_pihole_query_db(content: bytes) -> list[DNSEvent]:
    """Parse an uploaded Pi-hole FTL database into DNS events."""
    return list(parse_pihole_query_db_with_diagnostics(content).events)
