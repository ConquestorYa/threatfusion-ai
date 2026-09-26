from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult


def _optional_text(value: str | None) -> str | None:
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


def _parse_timestamp(value: str | None) -> datetime | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def parse_zeek_conn_log_with_diagnostics(content: str) -> DNSParseResult:
    """Parse Zeek/Bro conn.log as connection-target telemetry.

    The existing DNSEvent container is reused only as a transport object:
    query_name and response_ip both carry the observed destination IP.
    Dataset label/det_label columns are intentionally ignored.
    """
    if content is None or not content.strip():
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    separator = "\t"
    fields: list[str] | None = None
    events: list[DNSEvent] = []
    total_rows = 0
    skipped_missing_target = 0
    invalid_timestamps = 0
    invalid_response_ips = 0

    for raw_line in content.splitlines():
        if not raw_line:
            continue
        if raw_line.startswith("#separator"):
            separator = _separator_from_directive(raw_line)
            continue
        if raw_line.startswith("#fields"):
            remainder = raw_line[len("#fields") :]
            if remainder.startswith(separator):
                remainder = remainder[len(separator) :]
            else:
                remainder = remainder.lstrip()
            fields = remainder.split(separator)
            continue
        if raw_line.startswith("#"):
            continue

        if fields is None:
            raise ValueError("Zeek conn.log is missing a #fields header")

        values = raw_line.split(separator)
        if len(values) < len(fields):
            values.extend([""] * (len(fields) - len(values)))
        row = dict(zip(fields, values, strict=False))
        total_rows += 1

        target_text = _optional_text(row.get("id.resp_h"))
        if target_text is None:
            skipped_missing_target += 1
            continue
        try:
            target_ip = str(ipaddress.ip_address(target_text))
        except ValueError:
            invalid_response_ips += 1
            continue

        timestamp_text = _optional_text(row.get("ts"))
        timestamp = _parse_timestamp(timestamp_text)
        if timestamp_text is not None and timestamp is None:
            invalid_timestamps += 1

        proto = (_optional_text(row.get("proto")) or "").upper()
        port = _optional_text(row.get("id.resp_p"))
        service = _optional_text(row.get("service"))
        context_parts = [part for part in (proto, port, service) if part]
        connection_type = "CONNECTION"
        if context_parts:
            connection_type += ":" + "/".join(context_parts)

        events.append(
            DNSEvent(
                query_name=target_ip,
                timestamp=timestamp,
                client_ip=_optional_text(row.get("id.orig_h")),
                query_type=connection_type,
                response_ip=target_ip,
                response_code=_optional_text(row.get("conn_state")),
            )
        )

    if fields is None:
        raise ValueError("Zeek conn.log is missing a #fields header")
    required = {"id.orig_h", "id.resp_h"}
    if not required.issubset(fields):
        raise ValueError(
            "Zeek conn.log must include id.orig_h and id.resp_h fields"
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total_rows,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_target,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=invalid_response_ips,
        ),
    )
