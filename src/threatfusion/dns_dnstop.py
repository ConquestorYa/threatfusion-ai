from __future__ import annotations

import ipaddress
import re

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult
from .normalization import normalize_domain_name


def _domain_from_tokens(line: str) -> str | None:
    for token in re.split(r"\s+", line.strip()):
        candidate = token.strip("[](){}<>,;:'\"").rstrip(".")
        if "." not in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            pass
        else:
            continue
        try:
            normalized = normalize_domain_name(candidate, strict=True)
        except (TypeError, ValueError):
            continue
        return normalized
    return None


def parse_dnstop_with_diagnostics(content: str) -> DNSParseResult:
    """Parse common dnstop text summaries into unique domain observations.

    dnstop reports are aggregate summaries rather than packet-level telemetry,
    so query counts/timestamps/client addresses are intentionally not invented.
    """
    if content is None or not content.strip():
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    seen: set[str] = set()
    events: list[DNSEvent] = []
    total_rows = 0
    skipped = 0

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        total_rows += 1
        domain = _domain_from_tokens(line)
        if domain is None:
            skipped += 1
            continue
        if domain in seen:
            continue
        seen.add(domain)
        events.append(
            DNSEvent(
                query_name=domain,
                query_type="DNSTOP",
            )
        )

    if not events:
        raise ValueError(
            "dnstop text contains no recognizable domain names"
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total_rows,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped,
            invalid_timestamps=0,
            invalid_response_ips=0,
        ),
    )
