from __future__ import annotations

import ipaddress
import json
from datetime import datetime

from .dns import DNSEvent, DNSParseDiagnostics, DNSParseResult


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _timestamp(value: object) -> datetime | None:
    text = _optional_text(value)
    if text is None:
        return None

    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _first_answer_ip(answer: object) -> str | None:
    if not isinstance(answer, list):
        return None

    for item in answer:
        if not isinstance(item, dict):
            continue
        value = _optional_text(item.get("value"))
        if value is None:
            continue
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            continue

    return None


def _entries_from_content(content: str) -> list[dict[str, object]]:
    if content is None or not content.strip():
        return []

    stripped = content.strip()
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        entries: list[dict[str, object]] = []
        for line_number, raw_line in enumerate(content.splitlines(), start=1):
            if not raw_line.strip():
                continue
            try:
                item = json.loads(raw_line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"AdGuard query log contains invalid JSON at line {line_number}"
                ) from error
            if not isinstance(item, dict):
                raise TypeError("AdGuard query-log entries must be JSON objects")
            entries.append(item)
        return entries

    if isinstance(parsed, dict) and isinstance(parsed.get("data"), list):
        raw_entries = parsed["data"]
    elif isinstance(parsed, list):
        raw_entries = parsed
    elif isinstance(parsed, dict):
        raw_entries = [parsed]
    else:
        raise TypeError("AdGuard query log must contain JSON objects")

    if any(not isinstance(item, dict) for item in raw_entries):
        raise ValueError("AdGuard query-log entries must be JSON objects")

    return list(raw_entries)


def _query_fields(entry: dict[str, object]) -> tuple[
    object,
    object,
    object,
    object,
    object,
]:
    question = entry.get("question")
    if isinstance(question, dict):
        return (
            question.get("host"),
            entry.get("time"),
            entry.get("client"),
            question.get("type"),
            entry.get("answer"),
        )

    return (
        entry.get("QH"),
        entry.get("T"),
        entry.get("IP"),
        entry.get("QT"),
        None,
    )


def parse_adguard_query_log_with_diagnostics(content: str) -> DNSParseResult:
    """Parse AdGuard Home query-log JSON without networking."""
    entries = _entries_from_content(content)
    events: list[DNSEvent] = []
    skipped_missing_query_name = 0
    invalid_timestamps = 0

    for entry in entries:
        raw_query, raw_time, raw_client, raw_type, raw_answer = _query_fields(entry)
        query_name = _optional_text(raw_query)
        if query_name is None:
            skipped_missing_query_name += 1
            continue

        timestamp = _timestamp(raw_time)
        if _optional_text(raw_time) is not None and timestamp is None:
            invalid_timestamps += 1

        query_type = _optional_text(raw_type)
        events.append(
            DNSEvent(
                query_name=query_name,
                timestamp=timestamp,
                client_ip=_optional_text(raw_client),
                query_type=query_type.upper() if query_type else None,
                response_ip=_first_answer_ip(raw_answer),
            )
        )

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=len(entries),
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_query_name,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=0,
        ),
    )


def parse_adguard_query_log(content: str) -> list[DNSEvent]:
    """Parse AdGuard Home query-log JSON into DNS events."""
    return list(parse_adguard_query_log_with_diagnostics(content).events)
