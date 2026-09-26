from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .cti_cache import _normalize_url, initialize_cti_cache


@dataclass(frozen=True)
class CTILookupCoverage:
    source: str
    total_url_records: int
    audited_url_records: int
    exact_url_hits: int
    exact_url_misses: int
    hostname_hits: int
    hostname_misses: int
    ip_hosted_records: int
    ip_hosted_exact_hits: int

    @property
    def exact_url_coverage(self) -> float:
        if self.audited_url_records == 0:
            return 0.0
        return self.exact_url_hits / self.audited_url_records

    @property
    def hostname_coverage(self) -> float:
        if self.audited_url_records == 0:
            return 0.0
        return self.hostname_hits / self.audited_url_records


def _is_ip_hosted(url: str) -> bool:
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return False
    if not parsed.hostname:
        return False
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return False
    return True


def audit_exact_url_lookup_coverage(
    db_path: Path,
    *,
    source: str = "URLhaus",
    limit: int | None = None,
) -> CTILookupCoverage:
    """Audit exact-URL lookup coverage with one local SQLite scan.

    The old audit executed one indexed lookup per URL record. With a large live
    URLhaus cache that meant thousands of repeated SQLite opens/migrations and
    could take many minutes. This version initializes once, reads only the
    indexed lookup fields, and validates them in memory.

    It performs no DNS resolution, HTTP requests, or IOC destination visits.
    """
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")

    path = Path(db_path)
    initialize_cti_cache(path)

    with sqlite3.connect(path) as connection:
        total_row = connection.execute(
            """
            SELECT COUNT(*)
            FROM cti_records
            WHERE source = ?
              AND active = 1
              AND ioc_type = 'url'
            """,
            (source,),
        ).fetchone()
        total = int(total_row[0]) if total_row is not None else 0

        sql = """
            SELECT value, normalized_value, url_hostname
            FROM cti_records
            WHERE source = ?
              AND active = 1
              AND ioc_type = 'url'
            ORDER BY id ASC
        """
        parameters: list[object] = [source]
        if limit is not None:
            sql += " LIMIT ?"
            parameters.append(limit)

        rows = connection.execute(sql, parameters).fetchall()

    exact_hits = 0
    exact_misses = 0
    hostname_hits = 0
    hostname_misses = 0
    ip_hosted = 0
    ip_hosted_hits = 0

    for value, normalized_value, url_hostname in rows:
        raw_value = str(value)
        expected = _normalize_url(raw_value)
        ip_hosted_record = _is_ip_hosted(raw_value)
        if ip_hosted_record:
            ip_hosted += 1

        if expected is None:
            exact_misses += 1
            continue

        expected_url, expected_host = expected
        hostname_exact = str(url_hostname) == expected_host
        if hostname_exact:
            hostname_hits += 1
        else:
            hostname_misses += 1

        exact = (
            str(normalized_value) == expected_url
            and hostname_exact
        )
        if exact:
            exact_hits += 1
            if ip_hosted_record:
                ip_hosted_hits += 1
        else:
            exact_misses += 1

    return CTILookupCoverage(
        source=source,
        total_url_records=total,
        audited_url_records=len(rows),
        exact_url_hits=exact_hits,
        exact_url_misses=exact_misses,
        hostname_hits=hostname_hits,
        hostname_misses=hostname_misses,
        ip_hosted_records=ip_hosted,
        ip_hosted_exact_hits=ip_hosted_hits,
    )
