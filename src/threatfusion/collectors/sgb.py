import ipaddress
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

import requests

from ..http_safety import read_bounded_response_bytes
from ..models import IOCRecord, IOCType

SGB_API_URL = "https://siberguvenlik.gov.tr/api/address/index"
REQUEST_TIMEOUT_SECONDS = 30
MAX_SGB_PAGE_BYTES = 8 * 1024 * 1024
SGB_PAGE_SIZE = 9999
SGB_PARALLEL_PAGES = 4
PageProgressCallback = Callable[[int, int, int | None], None]


@dataclass(frozen=True)
class SGBCollectionResult:
    records: tuple[IOCRecord, ...]
    pages_fetched: int
    reached_source_end: bool


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


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
            params={"page": page, "per-page": SGB_PAGE_SIZE},
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
            stream=True,
        )
        response.raise_for_status()
        payload_bytes = read_bounded_response_bytes(
            response,
            max_bytes=MAX_SGB_PAGE_BYTES,
            label="SGB API response",
        )
        try:
            payload = json.loads(payload_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("SGB response is invalid JSON") from error
        return _response_page(payload)

    def fetch_addresses(self, page: int = 1) -> list[IOCRecord]:
        records, _, _ = self._fetch_page(page)
        return records

    def fetch_bounded_addresses(
        self,
        *,
        max_pages: int = 10,
        progress: PageProgressCallback | None = None,
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

        def accept(page_records, raw_item_count):
            nonlocal raw_items_seen, pages_fetched
            pages_fetched += 1
            records.extend(page_records)
            raw_items_seen += raw_item_count

        first_records, first_raw, total_count = self._fetch_page(1)
        accept(first_records, first_raw)
        if progress is not None:
            progress(1, raw_items_seen, total_count)
        next_page = 2
        if first_raw == 0 or (total_count is not None and raw_items_seen >= total_count):
            reached_source_end = True
        elif total_count is not None:
            # SGB spends ~3 s preparing each page; a small bounded pool overlaps
            # that server time. Pages are merged in order, and any failure fails
            # the whole snapshot exactly as a sequential fetch would.
            expected = min(max_pages, -(-total_count // first_raw))
            pages = range(2, expected + 1)
            results = {}
            with ThreadPoolExecutor(max_workers=SGB_PARALLEL_PAGES) as pool:
                futures = {pool.submit(self._fetch_page, page): page for page in pages}
                seen = raw_items_seen
                try:
                    for future in as_completed(futures):
                        results[futures[future]] = future.result()
                        seen += results[futures[future]][1]
                        if progress is not None:
                            progress(1 + len(results), seen, total_count)
                except BaseException:
                    pool.shutdown(wait=True, cancel_futures=True)
                    raise
            for page in pages:
                page_records, raw_item_count, _ = results[page]
                accept(page_records, raw_item_count)
                if raw_item_count == 0:
                    reached_source_end = True
            next_page = expected + 1
            if raw_items_seen >= total_count:
                reached_source_end = True

        # Sequential continuation: unknown totals or a source that grew meanwhile.
        for page in range(next_page, max_pages + 1):
            if reached_source_end:
                break
            page_records, raw_item_count, total_count = self._fetch_page(page)
            accept(page_records, raw_item_count)

            if progress is not None:
                progress(page, raw_items_seen, total_count)

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