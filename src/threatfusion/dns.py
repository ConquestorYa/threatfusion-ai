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


def parse_dns_csv(content: str) -> list[DNSEvent]:
    if content is None or not content.strip():
        return []

    reader = csv.DictReader(io.StringIO(content))
    fieldnames = reader.fieldnames
    if not fieldnames:
        return []

    normalized_names = {
        (field or "").strip().lower(): field for field in fieldnames if field is not None
    }
    if "query_name" not in normalized_names:
        raise ValueError("DNS CSV must include a 'query_name' column")

    events: list[DNSEvent] = []
    query_name_key = normalized_names["query_name"]
    timestamp_key = normalized_names.get("timestamp")
    client_ip_key = normalized_names.get("client_ip")
    query_type_key = normalized_names.get("query_type")
    response_ip_key = normalized_names.get("response_ip")

    for row in reader:
        if row is None:
            continue

        query_name = _as_optional_text(row.get(query_name_key))
        if query_name is None:
            continue

        event = DNSEvent(
            query_name=query_name,
            timestamp=_parse_timestamp(row.get(timestamp_key)) if timestamp_key else None,
            client_ip=_as_optional_text(row.get(client_ip_key)) if client_ip_key else None,
            query_type=None,
            response_ip=None,
        )

        if query_type_key:
            query_type = _as_optional_text(row.get(query_type_key))
            if query_type is not None:
                event.query_type = query_type.upper()

        if response_ip_key:
            event.response_ip = _parse_response_ip(row.get(response_ip_key))

        events.append(event)

    return events
