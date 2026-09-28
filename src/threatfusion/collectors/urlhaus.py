import csv
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from ..http_safety import decode_utf8_response
from ..models import IOCRecord, IOCType

URLHAUS_EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{}/recent.csv"
URLHAUS_FULL_EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{}/full.csv"
REQUEST_TIMEOUT_SECONDS = 30
MAX_URLHAUS_FEED_BYTES = 256 * 1024 * 1024


def _sanitized_http_error(status_code: object) -> requests.HTTPError:
    return requests.HTTPError(
        f"URLhaus export request failed (HTTP status {status_code})"
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None

    try:
        if value.endswith(" UTC"):
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S UTC").replace(
                tzinfo=timezone.utc
            )
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_tags(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []

    return [tag.strip() for tag in value.split(",") if tag.strip()]


def _is_url_value(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False

    parsed = urlsplit(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _record_from_urlhaus_row(row: dict[str, str | None]) -> IOCRecord | None:
    value = row.get("url")
    if not _is_url_value(value):
        return None

    return IOCRecord(
        value=value,
        ioc_type=IOCType.URL,
        source="URLhaus",
        first_seen=_parse_timestamp(row.get("dateadded")),
        last_seen=None,
        threat_type=row.get("threat") or None,
        confidence=None,
        tags=_parse_tags(row.get("tags")),
    )


def _header_candidate(line: str) -> list[str]:
    candidate = line.lstrip()
    if candidate.startswith("#"):
        candidate = candidate[1:].lstrip()
    return next(csv.reader([candidate]), [])


def parse_urlhaus_csv(content: str) -> list[IOCRecord]:
    lines = content.splitlines()
    header_index: int | None = None
    header: str | None = None

    for index, line in enumerate(lines):
        fields = {field.strip().lower() for field in _header_candidate(line)}
        if {"dateadded", "url"}.issubset(fields):
            header_index = index
            header = ",".join(_header_candidate(line))
            break

    if header_index is None or header is None:
        return []

    csv_lines = [
        header,
        *(
            line
            for line in lines[header_index + 1 :]
            if not line.lstrip().startswith("#")
        ),
    ]
    reader = csv.DictReader(csv_lines)

    records: list[IOCRecord] = []
    for row in reader:
        record = _record_from_urlhaus_row(row)
        if record is not None:
            records.append(record)

    return records


class URLhausCollector:
    def __init__(
        self,
        auth_key: str,
        session: requests.Session | None = None,
    ) -> None:
        self.auth_key = auth_key
        self.session = session if session is not None else requests.Session()

    def _fetch_export(self, template: str) -> list[IOCRecord]:
        export_url = template.format(self.auth_key)
        try:
            response = self.session.get(
                export_url,
                timeout=REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
            )
        except requests.RequestException:
            raise requests.HTTPError(
                "URLhaus export request failed (request error)"
            ) from None

        try:
            response.raise_for_status()
        except requests.RequestException:
            status_code = getattr(response, "status_code", "unknown")
            raise _sanitized_http_error(status_code) from None

        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and not 200 <= status_code < 300:
            raise _sanitized_http_error(status_code)

        content = decode_utf8_response(
            response,
            max_bytes=MAX_URLHAUS_FEED_BYTES,
            label="URLhaus export",
        )
        records = parse_urlhaus_csv(content)
        if not records:
            raise ValueError("URLhaus export contained no usable URLs")
        return records

    def fetch_recent_urls(self) -> list[IOCRecord]:
        return self._fetch_export(URLHAUS_EXPORT_URL)

    def fetch_full_urls(self) -> list[IOCRecord]:
        """Fetch the full dump, falling back to the documented recent export."""
        try:
            return self._fetch_export(URLHAUS_FULL_EXPORT_URL)
        except requests.HTTPError:
            return self._fetch_export(URLHAUS_EXPORT_URL)
