import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

import requests

from ..models import IOCRecord, IOCType

SGB_API_URL = "https://siberguvenlik.gov.tr/api/address/index"
REQUEST_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class SGBCollectionResult:
    records: tuple[IOCRecord, ...]
    pages_fetched: int
    reached_source_end: bool


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_valid_url(value: str) -> bool:
    parsed = urlsplit(value.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_valid_ip(value: str, ioc_type: IOCType) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False

    return (ioc_type is IOCType.IPV4 and address.version == 4) or (
        ioc_type is IOCType.IPV6 and address.version == 6
    )


def _record_from_sgb_item(item: Mapping[str, Any]) -> IOCRecord | None:
    value = item.get("url")
    address_type = item.get("type")
    if not isinstance(value, str) or not value.strip():
        return None
    if not isinstance(address_type, str) or not address_type.strip():
        return None

    address_type = address_type.strip().lower()
    if address_type == "domain":
        ioc_type = IOCType.DOMAIN
    elif address_type == "url":
        if not _is_valid_url(value):
            return None
        ioc_type = IOCType.URL
    elif address_type in {"ip", "ipv4"}:
        ioc_type = IOCType.IPV4
        if not _is_valid_ip(value, ioc_type):
            return None
    elif address_type in {"ip6", "ipv6"}:
        ioc_type = IOCType.IPV6
        if not _is_valid_ip(value, ioc_type):
            return None
    elif address_type in {"ip6net", "ipv6net"}:
        try:
            ipaddress.IPv6Network(value.strip(), strict=False)
        except ValueError:
            return None
        ioc_type = IOCType.IPV6_NETWORK
    else:
        ioc_type = IOCType.UNKNOWN

    return IOCRecord(
        value=value,
        ioc_type=ioc_type,
        source="SGB",
        first_seen=_parse_date(item.get("date")),
        last_seen=None,
        threat_type=None,
        confidence=None,
        tags=[],
    )


def _response_page(
    payload: Any,
) -> tuple[list[IOCRecord], int, int | None]:
    if not isinstance(payload, Mapping):
        raise TypeError("SGB response must be a JSON object")

    models = payload.get("models")
    if not isinstance(models, list):
        raise TypeError("SGB response models must be a list")

    total_raw = payload.get("totalCount")
    total_count = (
        total_raw
        if isinstance(total_raw, int) and not isinstance(total_raw, bool)
        and total_raw >= 0
        else None
    )

    records: list[IOCRecord] = []
    for item in models:
        if not isinstance(item, Mapping):
            continue
        record = _record_from_sgb_item(item)
        if record is not None:
            records.append(record)
    return records, len(models), total_count


def _records_from_response(payload: Any) -> list[IOCRecord]:
    records, _, _ = _response_page(payload)
    return records


class SGBCollector:
    def __init__(
        self,
        session: requests.Session | None = None,
    ) -> None:
        self.session = session if session is not None else requests.Session()

    def _fetch_page(
        self,
        page: int,
    ) -> tuple[list[IOCRecord], int, int | None]:
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ValueError("page must be a positive integer")

        response = self.session.get(
            SGB_API_URL,
            params={"page": page},
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        response.raise_for_status()
        return _response_page(response.json())

    def fetch_addresses(self, page: int = 1) -> list[IOCRecord]:
        records, _, _ = self._fetch_page(page)
        return records

    def fetch_bounded_addresses(
        self,
        *,
        max_pages: int = 10,
    ) -> SGBCollectionResult:
        """Fetch until the source ends, bounded by a caller-controlled cap."""
        if (
            isinstance(max_pages, bool)
            or not isinstance(max_pages, int)
            or max_pages < 1
        ):
            raise ValueError("max_pages must be a positive integer")

        records: list[IOCRecord] = []
        raw_items_seen = 0
        pages_fetched = 0
        reached_source_end = False

        for page in range(1, max_pages + 1):
            page_records, raw_item_count, total_count = self._fetch_page(page)
            pages_fetched += 1
            records.extend(page_records)
            raw_items_seen += raw_item_count

            if raw_item_count == 0:
                reached_source_end = True
                break
            if total_count is not None and raw_items_seen >= total_count:
                reached_source_end = True
                break

        return SGBCollectionResult(
            records=tuple(records),
            pages_fetched=pages_fetched,
            reached_source_end=reached_source_end,
        )