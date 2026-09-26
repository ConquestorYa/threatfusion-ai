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


def _parse_timestamp(value: object) -> datetime | None:
    text = _optional_text(value)
    if text is None:
        return None
    candidate = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _first_answer_ip(dns: dict[str, object]) -> str | None:
    answers = dns.get("answers")
    if isinstance(answers, dict):
        answers = [answers]
    if not isinstance(answers, list):
        return None

    for answer in answers:
        if not isinstance(answer, dict):
            continue
        value = _optional_text(answer.get("rdata"))
        if value is None:
            continue
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            continue
    return None


def _iter_json_records(content: str):
    stripped = content.lstrip()
    if stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise ValueError("Suricata EVE JSON array is malformed") from error
        if not isinstance(payload, list):
            raise ValueError("Suricata EVE JSON must contain objects")
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Suricata EVE JSON is malformed at line {line_number}"
            ) from error
        if isinstance(item, dict):
            yield item


def parse_suricata_eve_dns_with_diagnostics(content: str) -> DNSParseResult:
    """Parse DNS events from Suricata EVE JSON/JSONL exports."""
    if content is None or not content.strip():
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    events: list[DNSEvent] = []
    total_rows = 0
    skipped_missing_query_name = 0
    invalid_timestamps = 0
    invalid_response_ips = 0
    saw_eve_record = False

    for record in _iter_json_records(content):
        saw_eve_record = True
        if str(record.get("event_type", "")).casefold() != "dns":
            continue
        dns = record.get("dns")
        if not isinstance(dns, dict):
            continue
        total_rows += 1

        query_name = _optional_text(
            dns.get("rrname")
            or dns.get("query")
            or dns.get("name")
        )
        if query_name is None:
            skipped_missing_query_name += 1
            continue

        timestamp_text = _optional_text(record.get("timestamp"))
        timestamp = _parse_timestamp(timestamp_text)
        if timestamp_text is not None and timestamp is None:
            invalid_timestamps += 1

        response_ip = _first_answer_ip(dns)
        answers = dns.get("answers")
        if response_ip is None and answers:
            has_ip_like_answer = False
            answer_items = [answers] if isinstance(answers, dict) else answers
            if isinstance(answer_items, list):
                for answer in answer_items:
                    if isinstance(answer, dict) and answer.get("rdata"):
                        has_ip_like_answer = True
                        break
            if has_ip_like_answer:
                invalid_response_ips += 1

        event_type = str(dns.get("type", "")).casefold()
        client_ip = (
            _optional_text(record.get("dest_ip"))
            if event_type in {"answer", "response"}
            else _optional_text(record.get("src_ip"))
        )

        query_type = _optional_text(
            dns.get("rrtype")
            or dns.get("qtype_name")
            or dns.get("qtype")
        )
        response_code = _optional_text(
            dns.get("rcode")
            or dns.get("rcode_name")
        )

        events.append(
            DNSEvent(
                query_name=query_name,
                timestamp=timestamp,
                client_ip=client_ip,
                query_type=query_type.upper() if query_type else None,
                response_ip=response_ip,
                response_code=(
                    response_code.upper() if response_code else None
                ),
            )
        )

    if not saw_eve_record:
        raise ValueError("Suricata EVE input contains no JSON records")
    if total_rows == 0:
        raise ValueError("Suricata EVE input contains no DNS events")

    return DNSParseResult(
        events=tuple(events),
        diagnostics=DNSParseDiagnostics(
            total_rows=total_rows,
            accepted_rows=len(events),
            skipped_missing_query_name=skipped_missing_query_name,
            invalid_timestamps=invalid_timestamps,
            invalid_response_ips=invalid_response_ips,
        ),
    )
