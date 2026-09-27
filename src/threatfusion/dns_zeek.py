from __future__ import annotations

import ipaddress
import io
from datetime import datetime, timezone

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult


_MAX_ZEEK_FIELDS = 512
_MAX_ZEEK_ROWS = 100_000
_MAX_ZEEK_CELLS = 5_000_000


def _optional_zeek_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text or text in {"-", "(empty)"}:
        return None
    return text


def _separator_from_directive(line: str) -> str:
    value = line[len("#separator") :].strip()
    if value == r"\x09":
        return "\t"
    if len(value) == 1:
        return value
    raise ValueError("unsupported Zeek field separator")


def _parse_epoch_timestamp(value: str | None) -> datetime | None:
    text = _optional_zeek_text(value)
    if text is None:
        return None
    try:
        seconds = float(text)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _first_response_ip(value: str | None, set_separator: str) -> str | None:
    text = _optional_zeek_text(value)
    if text is None:
        return None

    for candidate in text.split(set_separator):
        candidate = candidate.strip()
        if not candidate:
            continue
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _response_code(row: dict[str, str]) -> str | None:
    rcode_name = _optional_zeek_text(row.get("rcode_name"))
    if rcode_name is not None:
        return rcode_name.upper()
    rcode = _optional_zeek_text(row.get("rcode"))
    if rcode is not None:
        return rcode.upper()
    return None


def parse_zeek_dns_log_with_diagnostics(content: str) -> DNSParseResult:
    """Parse a Zeek dns.log text export without networking."""
    if content is None or not content.strip():
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    separator = "\t"
    set_separator = ","
    fields: list[str] | None = None
    events: list[DNSEvent] = []
    total_rows = 0
    skipped_missing_query_name = 0
    invalid_timestamps = 0
    cell_count = 0

    for raw_line in io.StringIO(content):
        raw_line = raw_line.rstrip("\r\n")
        if not raw_line:
            continue

        if raw_line.startswith("#separator"):
            separator = _separator_from_directive(raw_line)
            continue
        if raw_line.startswith("#set_separator"):
            value = raw_line[len("#set_separator") :].strip()
            if value:
                set_separator = value
            continue
        if raw_line.startswith("#fields"):
            remainder = raw_line[len("#fields") :]
            if remainder.startswith(separator):
                remainder = remainder[len(separator) :]
            else:
                remainder = remainder.lstrip()
            fields = remainder.split(separator, _MAX_ZEEK_FIELDS)
            if len(fields) > _MAX_ZEEK_FIELDS:
                raise ValueError("Zeek dns.log exceeds the safe field import limit")
            continue
        if raw_line.startswith("#"):
            continue

        if fields is None:
            raise ValueError("Zeek dns.log is missing a #fields header")

        values = raw_line.split(separator, _MAX_ZEEK_FIELDS)
        if len(values) > _MAX_ZEEK_FIELDS:
            raise ValueError("Zeek dns.log exceeds the safe field import limit")
        if total_rows >= _MAX_ZEEK_ROWS:
            raise ValueError("Zeek dns.log exceeds the safe row import limit")

        cell_count += max(len(fields), len(values))
        if cell_count > _MAX_ZEEK_CELLS:
            raise ValueError("Zeek dns.log exceeds the safe cell import limit")

        if len(values) < len(fields):
            values.extend([""] * (len(fields) - len(values)))
        row = dict(zip(fields, values, strict=False))
        total_rows += 1

        query_name = _optional_zeek_text(row.get("query"))
        if query_name is None:
            skipped_missing_query_name += 1
            continue

        timestamp_text = _optional_zeek_text(row.get("ts"))
        timestamp = _parse_epoch_timestamp(timestamp_text)
        if timestamp_text is not None and timestamp is None:
            invalid_timestamps += 1

        query_type = _optional_zeek_text(row.get("qtype_name"))
        if query_type is None:
            query_type = _optional_zeek_text(row.get("qtype"))

        events.append(
            DNSEvent(
                query_name=query_name,
                timestamp=timestamp,
                client_ip=_optional_zeek_text(row.get("id.orig_h")),
                query_type=query_type.upper() if query_type else None,
                response_ip=_first_response_ip(
                    row.get("answers"),
                    set_separator,
                ),
                response_code=_response_code(row),
            )
        )

    if fields is None:
        raise ValueError("Zeek dns.log is missing a #fields header")
    if "query" not in fields:
        raise ValueError("Zeek dns.log must include the query field")

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total_rows,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_query_name,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=0,
        ),
    )


def parse_zeek_dns_log(content: str) -> list[DNSEvent]:
    """Parse Zeek dns.log text and return accepted DNS events."""
    return list(parse_zeek_dns_log_with_diagnostics(content).events)
