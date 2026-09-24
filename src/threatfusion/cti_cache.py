from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import IOCRecord, IOCType


@dataclass(frozen=True)
class CTICacheStatus:
    source: str
    refreshed_at: str
    record_count: int


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cti_records (
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

CREATE INDEX IF NOT EXISTS idx_cti_records_source
    ON cti_records(source);

CREATE INDEX IF NOT EXISTS idx_cti_records_type_value
    ON cti_records(ioc_type, value);

CREATE TABLE IF NOT EXISTS cti_refreshes (
    source TEXT PRIMARY KEY,
    refreshed_at TEXT NOT NULL,
    record_count INTEGER NOT NULL
);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(Path(db_path))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_cti_cache(db_path: Path) -> None:
    """Create CTI cache tables if they do not exist."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _connect(path) as connection:
        connection.executescript(_SCHEMA)


def _datetime_text(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _refresh_time_text(value: datetime | None) -> str:
    refresh_time = value or datetime.now(timezone.utc)
    if refresh_time.tzinfo is None or refresh_time.utcoffset() is None:
        raise ValueError("refreshed_at must be timezone-aware")
    return refresh_time.isoformat()


def _tags_json(tags: Sequence[str]) -> str:
    return json.dumps(list(tags), ensure_ascii=True, separators=(",", ":"))


def replace_source_records(
    db_path: Path,
    source: str,
    records: Iterable[IOCRecord],
    *,
    refreshed_at: datetime | None = None,
) -> int:
    """Atomically replace the cached records for one source."""
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")

    source_name = source.strip()
    record_list = list(records)
    if any(record.source != source_name for record in record_list):
        raise ValueError("every IOCRecord source must match the target source")

    initialize_cti_cache(db_path)
    refresh_text = _refresh_time_text(refreshed_at)

    rows = [
        (
            record.value,
            record.ioc_type.value,
            record.source,
            _datetime_text(record.first_seen),
            _datetime_text(record.last_seen),
            record.threat_type,
            record.confidence,
            _tags_json(record.tags),
        )
        for record in record_list
    ]

    with _connect(Path(db_path)) as connection:
        connection.execute(
            "DELETE FROM cti_records WHERE source = ?",
            (source_name,),
        )
        connection.executemany(
            """
            INSERT INTO cti_records (
                value,
                ioc_type,
                source,
                first_seen,
                last_seen,
                threat_type,
                confidence,
                tags_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        connection.execute(
            """
            INSERT INTO cti_refreshes (
                source,
                refreshed_at,
                record_count
            )
            VALUES (?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                refreshed_at = excluded.refreshed_at,
                record_count = excluded.record_count
            """,
            (source_name, refresh_text, len(record_list)),
        )

    return len(record_list)


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _parse_tags(value: str) -> list[str]:
    decoded = json.loads(value)
    if not isinstance(decoded, list) or not all(
        isinstance(item, str) for item in decoded
    ):
        raise ValueError("persisted CTI tags are invalid")
    return list(decoded)


def load_ioc_records(
    db_path: Path,
    *,
    sources: Sequence[str] | None = None,
) -> list[IOCRecord]:
    """Load cached IOC records in deterministic insertion order."""
    initialize_cti_cache(db_path)

    parameters: tuple[str, ...] = ()
    where_clause = ""

    if sources is not None:
        cleaned_sources = tuple(
            source.strip()
            for source in sources
            if isinstance(source, str) and source.strip()
        )
        if not cleaned_sources:
            return []

        placeholders = ",".join("?" for _ in cleaned_sources)
        where_clause = f"WHERE source IN ({placeholders})"
        parameters = cleaned_sources

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT *
            FROM cti_records
            {where_clause}
            ORDER BY id ASC
            """,
            parameters,
        ).fetchall()

    records: list[IOCRecord] = []
    for row in rows:
        try:
            ioc_type = IOCType(str(row["ioc_type"]))
        except ValueError:
            ioc_type = IOCType.UNKNOWN

        records.append(
            IOCRecord(
                value=str(row["value"]),
                ioc_type=ioc_type,
                source=str(row["source"]),
                first_seen=_parse_datetime(row["first_seen"]),
                last_seen=_parse_datetime(row["last_seen"]),
                threat_type=row["threat_type"],
                confidence=(
                    float(row["confidence"])
                    if row["confidence"] is not None
                    else None
                ),
                tags=_parse_tags(str(row["tags_json"])),
            )
        )

    return records


def list_cti_cache_status(db_path: Path) -> list[CTICacheStatus]:
    """List source refresh metadata in stable source order."""
    initialize_cti_cache(db_path)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT source, refreshed_at, record_count
            FROM cti_refreshes
            ORDER BY source ASC
            """
        ).fetchall()

    return [
        CTICacheStatus(
            source=str(row["source"]),
            refreshed_at=str(row["refreshed_at"]),
            record_count=int(row["record_count"]),
        )
        for row in rows
    ]
