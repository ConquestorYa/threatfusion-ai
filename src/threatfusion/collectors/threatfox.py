import csv
import io
import ipaddress
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

import requests

from ..models import IOCRecord, IOCType

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_EXPORT_URL = (
    "https://threatfox-api.abuse.ch/v2/files/exports/{}/full.csv.zip"
)
REQUEST_TIMEOUT_SECONDS = 30

_THREATFOX_POSITIONAL_COLUMNS = (
    "first_seen",
    "id",
    "ioc",
    "ioc_type",
    "threat_type",
    "malware",
    "malware_alias",
    "malware_printable",
    "last_seen",
    "confidence_level",
    "is_compromised",
    "reference",
    "tags",
    "anonymous",
    "reporter",
)


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
    if isinstance(value, list):
        return [tag for tag in value if isinstance(tag, str)]
    if isinstance(value, str):
        return [tag.strip() for tag in value.split(",") if tag.strip()]
    return []


def _parse_confidence(value: Any) -> float | None:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= confidence <= 100:
        return None
    return confidence / 100.0


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
    elif threatfox_type == "md5_hash":
        ioc_type = IOCType.MD5
    elif threatfox_type == "sha1_hash":
        ioc_type = IOCType.SHA1
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
        threat_type=(
            item.get("threat_type")
            if isinstance(item.get("threat_type"), str)
            else None
        ),
        confidence=_parse_confidence(item.get("confidence_level")),
        tags=_parse_tags(item.get("tags")),
    )


def parse_threatfox_csv(content: str) -> list[IOCRecord]:
    """Parse ThreatFox's full CSV export with or without a header row."""
    csv_rows = [
        row
        for row in csv.reader(
            line
            for line in content.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        if row
    ]
    if not csv_rows:
        return []

    first = [cell.strip().lower() for cell in csv_rows[0]]
    has_header = "ioc" in first and "ioc_type" in first

    if has_header:
        header = [cell.strip() for cell in csv_rows[0]]
        rows = (
            dict(zip(header, values, strict=False))
            for values in csv_rows[1:]
        )
    else:
        rows = (
            dict(zip(_THREATFOX_POSITIONAL_COLUMNS, values, strict=False))
            for values in csv_rows
            if len(values) >= 5
        )

    records: list[IOCRecord] = []
    for row in rows:
        if not str(row.get("ioc", "")).strip():
            continue
        records.append(_record_from_threatfox_item(row))
    return records


def _parse_export_zip(content: bytes) -> list[IOCRecord]:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = [
                name
                for name in archive.namelist()
                if name.casefold().endswith(".csv")
            ]
            if not names:
                raise ValueError("ThreatFox export ZIP contains no CSV file")
            csv_content = archive.read(names[0]).decode("utf-8-sig")
    except (zipfile.BadZipFile, UnicodeDecodeError, KeyError) as error:
        raise ValueError("ThreatFox full export is invalid") from error

    records = parse_threatfox_csv(csv_content)
    if not records:
        raise ValueError("ThreatFox full export contained no usable IOCs")
    return records


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

    def fetch_full_iocs(self) -> list[IOCRecord]:
        """Fetch ThreatFox's current non-expired full IOC export."""
        export_url = THREATFOX_EXPORT_URL.format(self.auth_key)
        try:
            response = self.session.get(
                export_url,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise requests.HTTPError(
                "ThreatFox export request failed (request error)"
            ) from None

        try:
            response.raise_for_status()
        except requests.RequestException:
            status_code = getattr(response, "status_code", "unknown")
            raise requests.HTTPError(
                f"ThreatFox export request failed (HTTP status {status_code})"
            ) from None

        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise requests.HTTPError(
                f"ThreatFox export request failed (HTTP status {status_code})"
            )

        return _parse_export_zip(response.content)
