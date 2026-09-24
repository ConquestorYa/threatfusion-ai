from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .models import IOCRecord, IOCType


@dataclass(frozen=True)
class DemoDNSDataset:
    content: str
    row_count: int
    includes_known_ioc: bool
    synthetic_burst_rows: int


def _select_known_domain(indicators: Iterable[IOCRecord]) -> str | None:
    candidates = sorted(
        {
            record.value.strip()
            for record in indicators
            if record.ioc_type is IOCType.DOMAIN
            and isinstance(record.value, str)
            and record.value.strip()
        }
    )
    return candidates[0] if candidates else None


def build_demo_dns_csv(indicators: Iterable[IOCRecord]) -> DemoDNSDataset:
    """Build a deterministic local-only DNS demo dataset.

    Cached IOC values are treated as inert text for matching only. The function
    performs no network activity and uses reserved documentation IP ranges for
    synthetic DNS responses and clients.
    """
    known_domain = _select_known_domain(indicators)

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        [
            "timestamp",
            "client_ip",
            "query_name",
            "query_type",
            "response_ip",
        ]
    )

    row_count = 0
    start = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)

    if known_domain is not None:
        writer.writerow(
            [
                start.isoformat().replace("+00:00", "Z"),
                "192.0.2.21",
                known_domain,
                "A",
                "198.51.100.10",
            ]
        )
        row_count += 1

    burst_domain = "demo-burst.example"
    query_types = ("A", "AAAA", "TXT")
    response_ips = (
        "198.51.100.21",
        "198.51.100.22",
        "198.51.100.23",
    )
    client_ips = (
        "192.0.2.21",
        "192.0.2.22",
        "192.0.2.23",
    )

    for index in range(20):
        timestamp = start + timedelta(seconds=index * 2)
        writer.writerow(
            [
                timestamp.isoformat().replace("+00:00", "Z"),
                client_ips[index % len(client_ips)],
                burst_domain,
                query_types[index % len(query_types)],
                response_ips[index % len(response_ips)],
            ]
        )
        row_count += 1

    normal_rows = (
        ("www.example.com", "A", "203.0.113.10"),
        ("docs.example.net", "AAAA", "2001:db8::10"),
        ("status.example.org", "A", "203.0.113.11"),
    )

    for offset, (domain, query_type, response_ip) in enumerate(normal_rows, start=30):
        timestamp = start + timedelta(seconds=offset)
        writer.writerow(
            [
                timestamp.isoformat().replace("+00:00", "Z"),
                "192.0.2.30",
                domain,
                query_type,
                response_ip,
            ]
        )
        row_count += 1

    return DemoDNSDataset(
        content=output.getvalue(),
        row_count=row_count,
        includes_known_ioc=known_domain is not None,
        synthetic_burst_rows=20,
    )
