import ipaddress
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import requests

from ..models import IOCRecord, IOCType

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
REQUEST_TIMEOUT_SECONDS = 30


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None

    try:
        if value.endswith(" UTC"):
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(
                tzinfo=timezone.utc
            )
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_tags(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    return [tag for tag in value if isinstance(tag, str)]


def _classify_ip_port(value: str) -> tuple[str, IOCType] | None:
    candidate = value.strip()

    if candidate.startswith("[") and "]" in candidate:
        closing_bracket = candidate.find("]")
        port = candidate[closing_bracket + 1 :]
        if not port.startswith(":") or not port[1:].isdigit():
            return None
        candidate = candidate[1:closing_bracket]
    elif ":" in candidate:
        candidate, port = candidate.rsplit(":", 1)
        if not port.isdigit():
            return None
    else:
        return None

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None

    ioc_type = IOCType.IPV4 if address.version == 4 else IOCType.IPV6
    return str(address), ioc_type


def _record_from_threatfox_item(item: Mapping[str, Any]) -> IOCRecord:
    value = str(item.get("ioc", ""))
    threatfox_type = str(item.get("ioc_type", "")).lower()

    if threatfox_type == "domain":
        ioc_type = IOCType.DOMAIN
    elif threatfox_type == "url":
        ioc_type = IOCType.URL
    elif threatfox_type == "sha256_hash":
        ioc_type = IOCType.SHA256
    elif threatfox_type == "ip:port":
        ip_result = _classify_ip_port(value)
        if ip_result is None:
            ioc_type = IOCType.UNKNOWN
        else:
            value, ioc_type = ip_result
    else:
        ioc_type = IOCType.UNKNOWN

    return IOCRecord(
        value=value,
        ioc_type=ioc_type,
        source="ThreatFox",
        first_seen=_parse_timestamp(item.get("first_seen")),
        last_seen=_parse_timestamp(item.get("last_seen")),
        threat_type=item.get("threat_type")
        if isinstance(item.get("threat_type"), str)
        else None,
        confidence=None,
        tags=_parse_tags(item.get("tags")),
    )


class ThreatFoxCollector:
    def __init__(
        self,
        auth_key: str,
        session: requests.Session | None = None,
    ) -> None:
        self.auth_key = auth_key
        self.session = session if session is not None else requests.Session()

    def fetch_recent_iocs(self, days: int = 1) -> list[IOCRecord]:
        if not 1 <= days <= 7:
            raise ValueError("days must be between 1 and 7")

        response = self.session.post(
            THREATFOX_API_URL,
            headers={"Auth-Key": self.auth_key},
            json={"query": "get_iocs", "days": days},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()

        if not isinstance(payload, Mapping):
            raise TypeError("ThreatFox response must be a JSON object")

        query_status = payload.get("query_status")
        if query_status != "ok":
            raise ValueError(f"ThreatFox query failed: {query_status}")

        data = payload.get("data", [])
        if not isinstance(data, list):
            raise TypeError("ThreatFox response data must be a list")

        return [
            _record_from_threatfox_item(item)
            for item in data
            if isinstance(item, Mapping)
        ]