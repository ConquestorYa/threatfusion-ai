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
THREATFOX_FULL_EXPORT_URL = (
    "https://threatfox-api.abuse.ch/v2/files/exports/{}/full.csv.zip"
)
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
        threat_type=item.get("threat_type")
        if isinstance(item.get("threat_type"), str)
        else None,
        confidence=None,
        tags=_parse_tags(item.get("tags")),
    )


def _header_candidate(line: str) -> list[str]:
    candidate = line.lstrip()
    if candidate.startswith("#"):
        candidate = candidate[1:].lstrip()
    return next(csv.reader([candidate]), [])


def _field(row: Mapping[str, Any], *names: str) -> Any:
    lowered = {str(key).strip().casefold(): value for key, value in row.items()}
    for name in names:
        if name.casefold() in lowered:
            return lowered[name.casefold()]
    return None


def _parse_export_tags(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_export_confidence(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        confidence = float(str(value).strip())
    except ValueError:
        return None
    if confidence > 1:
        confidence /= 100.0
    return confidence if 0 <= confidence <= 1 else None


def parse_threatfox_csv(content: str) -> list[IOCRecord]:
    """Parse a ThreatFox full CSV export using header names."""
    lines = content.splitlines()
    header_index: int | None = None
    header_fields: list[str] | None = None

    for index, line in enumerate(lines):
        fields = [field.strip() for field in _header_candidate(line)]
        lowered = {field.casefold() for field in fields}
        has_ioc = "ioc" in lowered or "ioc_value" in lowered
        if has_ioc and "ioc_type" in lowered:
            header_index = index
            header_fields = fields
            break

    if header_index is None or header_fields is None:
        return []

    reader = csv.DictReader(
        [
            ",".join(header_fields),
            *(
                line
                for line in lines[header_index + 1 :]
                if line.strip() and not line.lstrip().startswith("#")
            ),
        ]
    )

    records: list[IOCRecord] = []
    for row in reader:
        ioc = _field(row, "ioc", "ioc_value")
        ioc_type = _field(row, "ioc_type")
        if not isinstance(ioc, str) or not ioc.strip():
            continue
        if not isinstance(ioc_type, str) or not ioc_type.strip():
            continue

        item = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "first_seen": _field(row, "first_seen", "first_seen_utc"),
            "last_seen": _field(row, "last_seen", "last_seen_utc"),
            "threat_type": _field(row, "threat_type"),
            "tags": _parse_export_tags(_field(row, "tags")),
        }
        record = _record_from_threatfox_item(item)
        record.confidence = _parse_export_confidence(
            _field(row, "confidence", "confidence_level")
        )
        records.append(record)

    return records


def _extract_full_csv(payload: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            names = archive.namelist()
            csv_name = next(
                (name for name in names if name.casefold().endswith("full.csv")),
                None,
            )
            if csv_name is None:
                csv_name = next(
                    (name for name in names if name.casefold().endswith(".csv")),
                    None,
                )
            if csv_name is None:
                raise ValueError("ThreatFox export archive does not contain CSV data")
            return archive.read(csv_name).decode("utf-8-sig")
    except zipfile.BadZipFile:
        return payload.decode("utf-8-sig")


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
        """Fetch the current non-expired ThreatFox export."""
        export_url = THREATFOX_FULL_EXPORT_URL.format(self.auth_key)
        try:
            response = self.session.get(
                export_url,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
            )
        except requests.RequestException:
            raise requests.HTTPError(
                "ThreatFox full export request failed (request error)"
            ) from None

        status_code = getattr(response, "status_code", 200)
        try:
            response.raise_for_status()
        except requests.RequestException:
            raise requests.HTTPError(
                f"ThreatFox full export request failed (HTTP status {status_code})"
            ) from None
        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise requests.HTTPError(
                f"ThreatFox full export request failed (HTTP status {status_code})"
            )

        payload = getattr(response, "content", None)
        if not isinstance(payload, (bytes, bytearray)):
            text = getattr(response, "text", "")
            payload = str(text).encode("utf-8")
        return parse_threatfox_csv(_extract_full_csv(bytes(payload)))
