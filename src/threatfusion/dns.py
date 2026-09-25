import csv
import io
import ipaddress
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DNSEvent:
    query_name: str
    timestamp: datetime | None = None
    client_ip: str | None = None
    query_type: str | None = None
    response_ip: str | None = None
    response_code: str | None = None


@dataclass(frozen=True)
class DNSParseDiagnostics:
    total_rows: int
    accepted_rows: int
    skipped_missing_query_name: int
    invalid_timestamps: int
    invalid_response_ips: int


@dataclass(frozen=True)
class DNSParseResult:
    events: tuple[DNSEvent, ...]
    diagnostics: DNSParseDiagnostics


def _as_optional_text(value: object) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _parse_timestamp(value: object) -> datetime | None:
    text = _as_optional_text(value)
    if text is None:
        return None

    candidate = text
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"

    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _parse_response_ip(value: object) -> str | None:
    text = _as_optional_text(value)
    if text is None:
        return None

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None

    return str(address)


def _parse_response_code(value: object) -> str | None:
    text = _as_optional_text(value)
    if text is None:
        return None
    return text.upper()


def parse_dns_csv_with_diagnostics(content: str) -> DNSParseResult:
    if content is None or not content.strip():
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    reader = csv.DictReader(io.StringIO(content))
    fieldnames = reader.fieldnames
    if not fieldnames:
        return DNSParseResult(
            events=(),
            diagnostics=DNSParseDiagnostics(0, 0, 0, 0, 0),
        )

    normalized_names = {
        (field or "").strip().lower(): field
        for field in fieldnames
        if field is not None
    }
    if "query_name" not in normalized_names:
        raise ValueError("DNS CSV must include a 'query_name' column")

    events: list[DNSEvent] = []
    total_rows = 0
    skipped_missing_query_name = 0
    invalid_timestamps = 0
    invalid_response_ips = 0

    query_name_key = normalized_names["query_name"]
    timestamp_key = normalized_names.get("timestamp")
    client_ip_key = normalized_names.get("client_ip")
    query_type_key = normalized_names.get("query_type")
    response_ip_key = normalized_names.get("response_ip")
    response_code_key = normalized_names.get("response_code")

    for row in reader:
        if row is None:
            continue

        total_rows += 1
        query_name = _as_optional_text(row.get(query_name_key))
        if query_name is None:
            skipped_missing_query_name += 1
            continue

        timestamp_text = (
            _as_optional_text(row.get(timestamp_key))
            if timestamp_key
            else None
        )
        timestamp = _parse_timestamp(timestamp_text)
        if timestamp_text is not None and timestamp is None:
            invalid_timestamps += 1

        response_ip_text = (
            _as_optional_text(row.get(response_ip_key))
            if response_ip_key
            else None
        )
        response_ip = _parse_response_ip(response_ip_text)
        if response_ip_text is not None and response_ip is None:
            invalid_response_ips += 1

        event = DNSEvent(
            query_name=query_name,
            timestamp=timestamp,
            client_ip=(
                _as_optional_text(row.get(client_ip_key))
                if client_ip_key
                else None
            ),
            query_type=None,
            response_ip=response_ip,
            response_code=(
                _parse_response_code(row.get(response_code_key))
                if response_code_key
                else None
            ),
        )

        if query_type_key:
            query_type = _as_optional_text(row.get(query_type_key))
            if query_type is not None:
                event.query_type = query_type.upper()

        events.append(event)

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


def parse_dns_csv(content: str) -> list[DNSEvent]:
    """Parse project DNS CSV text and return accepted DNS events only."""
    return list(parse_dns_csv_with_diagnostics(content).events)
