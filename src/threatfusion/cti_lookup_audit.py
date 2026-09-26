from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .cti_cache import load_ioc_records, lookup_ioc_records
from .models import IOCType
from .normalization import normalize_domain_name


@dataclass(frozen=True)
class CTILookupCoverage:
    source: str
    total_url_records: int
    audited_url_records: int
    exact_url_hits: int
    exact_url_misses: int
    ip_hosted_records: int
    ip_hosted_exact_hits: int

    @property
    def exact_url_coverage(self) -> float:
        if self.audited_url_records == 0:
            return 0.0
        return self.exact_url_hits / self.audited_url_records


def _normalized_lookup_host(url: str) -> tuple[str, str | None] | None:
    try:
        parsed = urlsplit(url.strip())
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return None

    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        try:
            return normalize_domain_name(parsed.hostname, strict=True), None
        except (TypeError, ValueError):
            return None
    return str(address), str(address)


def audit_exact_url_lookup_coverage(
    db_path: Path,
    *,
    source: str = "URLhaus",
    limit: int | None = None,
) -> CTILookupCoverage:
    """Measure whether active cached URLs are retrievable by indexed quick lookup.

    This is a local cache integrity audit. It performs no DNS resolution or HTTP
    requests and never visits any IOC destination.
    """
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")

    records = [
        item
        for item in load_ioc_records(db_path, sources=[source])
        if item.ioc_type is IOCType.URL
    ]
    total = len(records)
    selected = records if limit is None else records[:limit]

    exact_hits = 0
    exact_misses = 0
    ip_hosted = 0
    ip_hosted_hits = 0

    for record in selected:
        host_data = _normalized_lookup_host(record.value)
        if host_data is None:
            exact_misses += 1
            continue

        host, normalized_ip = host_data
        if normalized_ip is not None:
            ip_hosted += 1

        candidates = lookup_ioc_records(
            db_path,
            domain=host,
            normalized_url=record.value,
            ip_address=normalized_ip,
        )
        exact = any(
            candidate.source == source
            and candidate.ioc_type is IOCType.URL
            and candidate.value == record.value
            for candidate in candidates
        )
        if exact:
            exact_hits += 1
            if normalized_ip is not None:
                ip_hosted_hits += 1
        else:
            exact_misses += 1

    return CTILookupCoverage(
        source=source,
        total_url_records=total,
        audited_url_records=len(selected),
        exact_url_hits=exact_hits,
        exact_url_misses=exact_misses,
        ip_hosted_records=ip_hosted,
        ip_hosted_exact_hits=ip_hosted_hits,
    )
