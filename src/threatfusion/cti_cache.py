from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import IOCRecord, IOCType
from .normalization import normalize_domain_name, normalize_url_for_lookup


@dataclass(frozen=True)
class CTICacheStatus:
    source: str
    refreshed_at: str
    record_count: int
    inactive_record_count: int = 0


@dataclass(frozen=True)
class CTILifecycleRecord:
    indicator: IOCRecord
    first_seen_in_cache: str | None
    last_seen_in_refresh: str | None
    active: bool


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
    tags_json TEXT NOT NULL,
    first_seen_in_cache TEXT,
    last_seen_in_refresh TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    normalized_domain TEXT,
    normalized_url TEXT
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


def _migrate_cti_records(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(cti_records)").fetchall()
    }
    additions = {
        "first_seen_in_cache": "TEXT",
        "last_seen_in_refresh": "TEXT",
        "active": "INTEGER NOT NULL DEFAULT 1",
        "normalized_domain": "TEXT",
        "normalized_url": "TEXT",
    }
    added_lookup_columns = False
    for name, declaration in additions.items():
        if name not in columns:
            connection.execute(
                f"ALTER TABLE cti_records ADD COLUMN {name} {declaration}"
            )
            if name in {"normalized_domain", "normalized_url"}:
                added_lookup_columns = True

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cti_records_source_active
        ON cti_records(source, active)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cti_records_active_domain
        ON cti_records(active, normalized_domain)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_cti_records_active_url
        ON cti_records(active, normalized_url)
        """
    )

    if added_lookup_columns:
        rows = connection.execute(
            "SELECT id, value, ioc_type FROM cti_records"
        ).fetchall()
        for row_id, value, ioc_type_text in rows:
            try:
                ioc_type = IOCType(str(ioc_type_text))
            except ValueError:
                ioc_type = IOCType.UNKNOWN
            domain_key, url_key = _lookup_keys(str(value), ioc_type)
            connection.execute(
                """
                UPDATE cti_records
                SET normalized_domain = ?, normalized_url = ?
                WHERE id = ?
                """,
                (domain_key, url_key, int(row_id)),
            )


def initialize_cti_cache(db_path: Path) -> None:
    """Create or migrate local CTI cache tables."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _connect(path) as connection:
        connection.executescript(_SCHEMA)
        _migrate_cti_records(connection)


def _datetime_text(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _refresh_time_text(value: datetime | None) -> str:
    refresh_time = value or datetime.now(timezone.utc)
    if refresh_time.tzinfo is None or refresh_time.utcoffset() is None:
        raise ValueError("refreshed_at must be timezone-aware")
    return refresh_time.isoformat()


def _tags_json(tags: Sequence[str]) -> str:
    return json.dumps(list(tags), ensure_ascii=True, separators=(",", ":"))


def validate_nonempty_refresh_batch(
    source_records: Mapping[str, Sequence[IOCRecord]],
) -> None:
    """Reject a refresh batch if any expected source returned no records."""
    empty_sources = sorted(
        source
        for source, records in source_records.items()
        if not records
    )
    if empty_sources:
        joined = ", ".join(empty_sources)
        raise ValueError(
            "refusing to replace CTI cache with empty refresh data for: "
            f"{joined}"
        )


def _record_identity(record: IOCRecord) -> tuple[str, str]:
    return record.ioc_type.value, record.value


def _lookup_keys(value: str, ioc_type: IOCType) -> tuple[str | None, str | None]:
    try:
        if ioc_type is IOCType.DOMAIN:
            return normalize_domain_name(value, strict=True), None
        if ioc_type is IOCType.URL:
            normalized_url, hostname = normalize_url_for_lookup(value)
            return hostname, normalized_url
    except (TypeError, ValueError):
        return None, None
    return None, None


def replace_source_records(
    db_path: Path,
    source: str,
    records: Iterable[IOCRecord],
    *,
    refreshed_at: datetime | None = None,
) -> int:
    """Synchronize one source while preserving inactive IOC lifecycle history."""
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")

    source_name = source.strip()
    record_list = list(records)
    if any(record.source != source_name for record in record_list):
        raise ValueError("every IOCRecord source must match the target source")

    initialize_cti_cache(db_path)
    refresh_text = _refresh_time_text(refreshed_at)

    unique_records: dict[tuple[str, str], IOCRecord] = {}
    for record in record_list:
        unique_records.setdefault(_record_identity(record), record)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE cti_records SET active = 0 WHERE source = ?",
            (source_name,),
        )

        for record in unique_records.values():
            existing = connection.execute(
                """
                SELECT id, first_seen_in_cache
                FROM cti_records
                WHERE source = ? AND ioc_type = ? AND value = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (source_name, record.ioc_type.value, record.value),
            ).fetchone()

            normalized_domain, normalized_url = _lookup_keys(
                record.value,
                record.ioc_type,
            )
            values = (
                _datetime_text(record.first_seen),
                _datetime_text(record.last_seen),
                record.threat_type,
                record.confidence,
                _tags_json(record.tags),
                normalized_domain,
                normalized_url,
                refresh_text,
            )
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO cti_records (
                        value,
                        ioc_type,
                        source,
                        first_seen,
                        last_seen,
                        threat_type,
                        confidence,
                        tags_json,
                        normalized_domain,
                        normalized_url,
                        first_seen_in_cache,
                        last_seen_in_refresh,
                        active
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        record.value,
                        record.ioc_type.value,
                        source_name,
                        *values[:-1],
                        refresh_text,
                        refresh_text,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE cti_records
                    SET
                        first_seen = ?,
                        last_seen = ?,
                        threat_type = ?,
                        confidence = ?,
                        tags_json = ?,
                        normalized_domain = ?,
                        normalized_url = ?,
                        first_seen_in_cache = COALESCE(
                            first_seen_in_cache,
                            ?
                        ),
                        last_seen_in_refresh = ?,
                        active = 1
                    WHERE id = ?
                    """,
                    (
                        *values[:-1],
                        refresh_text,
                        refresh_text,
                        int(existing["id"]),
                    ),
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
            (source_name, refresh_text, len(unique_records)),
        )

    return len(unique_records)


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


def _ioc_from_row(row: sqlite3.Row) -> IOCRecord:
    try:
        ioc_type = IOCType(str(row["ioc_type"]))
    except ValueError:
        ioc_type = IOCType.UNKNOWN

    return IOCRecord(
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


def _source_filter(
    sources: Sequence[str] | None,
) -> tuple[tuple[str, ...], str]:
    if sources is None:
        return (), ""

    cleaned_sources = tuple(
        source.strip()
        for source in sources
        if isinstance(source, str) and source.strip()
    )
    if not cleaned_sources:
        return (), "EMPTY"

    placeholders = ",".join("?" for _ in cleaned_sources)
    return cleaned_sources, f"source IN ({placeholders})"


def load_ioc_records(
    db_path: Path,
    *,
    sources: Sequence[str] | None = None,
    include_inactive: bool = False,
) -> list[IOCRecord]:
    """Load active cached IOC records unless lifecycle history is requested."""
    initialize_cti_cache(db_path)

    parameters, source_clause = _source_filter(sources)
    if source_clause == "EMPTY":
        return []

    clauses: list[str] = []
    if source_clause:
        clauses.append(source_clause)
    if not include_inactive:
        clauses.append("active = 1")
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""

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

    return [_ioc_from_row(row) for row in rows]


def lookup_ioc_records(
    db_path: Path,
    *,
    domain: str,
    normalized_url: str | None = None,
) -> list[IOCRecord]:
    """Return only active IOC rows relevant to one domain/URL lookup."""
    initialize_cti_cache(db_path)
    domain_key = normalize_domain_name(domain, strict=True)

    clauses = ["normalized_domain = ?"]
    parameters: list[object] = [domain_key]
    if normalized_url:
        clauses.append("normalized_url = ?")
        parameters.append(normalized_url)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT *
            FROM cti_records
            WHERE active = 1 AND ({' OR '.join(clauses)})
            ORDER BY id ASC
            """,
            tuple(parameters),
        ).fetchall()

    return [_ioc_from_row(row) for row in rows]


def has_active_ioc_records(db_path: Path) -> bool:
    """Return whether the cache has at least one active IOC."""
    initialize_cti_cache(db_path)
    with _connect(Path(db_path)) as connection:
        row = connection.execute(
            "SELECT 1 FROM cti_records WHERE active = 1 LIMIT 1"
        ).fetchone()
    return row is not None


def prune_inactive_records(
    db_path: Path,
    *,
    older_than_days: int = 90,
    now: datetime | None = None,
) -> int:
    """Delete inactive lifecycle history older than the retention window."""
    if isinstance(older_than_days, bool) or older_than_days < 1:
        raise ValueError("older_than_days must be at least 1")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    initialize_cti_cache(db_path)
    cutoff = (current - timedelta(days=older_than_days)).isoformat()
    with _connect(Path(db_path)) as connection:
        cursor = connection.execute(
            """
            DELETE FROM cti_records
            WHERE active = 0
              AND last_seen_in_refresh IS NOT NULL
              AND last_seen_in_refresh < ?
            """,
            (cutoff,),
        )
        return max(int(cursor.rowcount), 0)


def compact_cti_cache(db_path: Path) -> None:
    """Reclaim SQLite pages after lifecycle pruning."""
    initialize_cti_cache(db_path)
    with _connect(Path(db_path)) as connection:
        connection.execute("VACUUM")


def list_cti_lifecycle_records(
    db_path: Path,
    *,
    sources: Sequence[str] | None = None,
) -> list[CTILifecycleRecord]:
    """Return active and inactive IOC cache state for audit/maintenance views."""
    initialize_cti_cache(db_path)

    parameters, source_clause = _source_filter(sources)
    if source_clause == "EMPTY":
        return []
    where_clause = f"WHERE {source_clause}" if source_clause else ""

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

    return [
        CTILifecycleRecord(
            indicator=_ioc_from_row(row),
            first_seen_in_cache=(
                str(row["first_seen_in_cache"])
                if row["first_seen_in_cache"] is not None
                else None
            ),
            last_seen_in_refresh=(
                str(row["last_seen_in_refresh"])
                if row["last_seen_in_refresh"] is not None
                else None
            ),
            active=bool(row["active"]),
        )
        for row in rows
    ]


def list_cti_cache_status(db_path: Path) -> list[CTICacheStatus]:
    """List source refresh metadata and retained inactive-history counts."""
    initialize_cti_cache(db_path)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                refreshes.source,
                refreshes.refreshed_at,
                refreshes.record_count,
                COALESCE(history.inactive_record_count, 0)
                    AS inactive_record_count
            FROM cti_refreshes AS refreshes
            LEFT JOIN (
                SELECT
                    source,
                    SUM(CASE WHEN active = 0 THEN 1 ELSE 0 END)
                        AS inactive_record_count
                FROM cti_records
                GROUP BY source
            ) AS history
                ON history.source = refreshes.source
            ORDER BY refreshes.source ASC
            """
        ).fetchall()

    return [
        CTICacheStatus(
            source=str(row["source"]),
            refreshed_at=str(row["refreshed_at"]),
            record_count=int(row["record_count"]),
            inactive_record_count=int(row["inactive_record_count"]),
        )
        for row in rows
    ]
