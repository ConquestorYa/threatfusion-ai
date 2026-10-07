import json
from datetime import datetime, timezone

import pytest
import requests

from threatfusion.collectors import sgb
from threatfusion.collectors.sgb import SGB_API_URL, SGB_PAGE_SIZE, SGBCollector
from threatfusion.models import IOCType


class FakeResponse:
    def __init__(self, payload: object, error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.content = json.dumps(payload).encode("utf-8")
        self.headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error

    def json(self) -> object:
        return self.payload

    def iter_content(self, chunk_size: int):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.get_calls: list[tuple[str, dict[str, int], int, bool]] = []

    def get(
        self,
        url: str,
        *,
        params: dict[str, int],
        timeout: int,
        allow_redirects: bool,
        stream: bool = False,
    ) -> FakeResponse:
        self.get_calls.append((url, params, timeout, allow_redirects))
        return self.response


class SequenceSession:
    def __init__(self, payloads: list[object]) -> None:
        self.responses = [FakeResponse(payload) for payload in payloads]
        self.get_calls: list[tuple[str, dict[str, int], int, bool]] = []

    def get(
        self,
        url: str,
        *,
        params: dict[str, int],
        timeout: int,
        allow_redirects: bool,
        stream: bool = False,
    ) -> FakeResponse:
        self.get_calls.append((url, params, timeout, allow_redirects))
        if not self.responses:
            raise AssertionError("unexpected extra SGB page request")
        return self.responses.pop(0)


def make_session(models: list[dict[str, object]]) -> FakeSession:
    return FakeSession(FakeResponse({"totalCount": len(models), "models": models}))


def test_domain_mapping() -> None:
    session = make_session(
        [{"url": "example.com", "type": "domain", "date": "2026-09-23 12:00:00"}]
    )

    record = SGBCollector(session).fetch_addresses()[0]

    assert record.value == "example.com"
    assert record.ioc_type is IOCType.DOMAIN
    assert record.source == "SGB"
    assert record.first_seen is not None
    assert record.first_seen == datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("address_type", "value", "expected_type"),
    [
        ("url", "https://malicious.example/path", IOCType.URL),
        ("ipv4", "192.0.2.10", IOCType.IPV4),
        ("ipv6", "2001:db8::10", IOCType.IPV6),
    ],
)
def test_supported_address_mapping(
    address_type: str, value: str, expected_type: IOCType
) -> None:
    session = make_session([{"url": value, "type": address_type}])

    record = SGBCollector(session).fetch_addresses()[0]

    assert record.value == value
    assert record.ioc_type is expected_type
    assert record.source == "SGB"


def test_short_ip_aliases_map_to_host_types() -> None:
    session = make_session(
        [
            {"url": "192.0.2.10", "type": "ip"},
            {"url": "2001:db8::10", "type": "ip6"},
        ]
    )

    records = SGBCollector(session).fetch_addresses()

    assert [record.ioc_type for record in records] == [IOCType.IPV4, IOCType.IPV6]


def test_ipv6_network_is_preserved_as_network_ioc() -> None:
    value = "2001:db8::/32"
    session = make_session([{"url": value, "type": "ipv6net"}])

    record = SGBCollector(session).fetch_addresses()[0]

    assert record.value == value
    assert record.ioc_type is IOCType.IPV6_NETWORK


def test_short_ipv6_network_alias_is_preserved_as_network_ioc() -> None:
    value = "2001:db8::/32"
    session = make_session([{"url": value, "type": "ip6net"}])

    record = SGBCollector(session).fetch_addresses()[0]

    assert record.value == value
    assert record.ioc_type is IOCType.IPV6_NETWORK




def test_malformed_ipv6_network_is_ignored() -> None:
    session = make_session(
        [{"url": "not-a-network", "type": "ip6net"}]
    )

    assert SGBCollector(session).fetch_addresses() == []

def test_unknown_type_preserves_value() -> None:
    value = "unclassified.example"
    session = make_session([{"url": value, "type": "other"}])

    record = SGBCollector(session).fetch_addresses()[0]

    assert record.value == value
    assert record.ioc_type is IOCType.UNKNOWN


def test_missing_optional_metadata_is_safe() -> None:
    session = make_session([{"url": "example.com", "type": "domain"}])

    record = SGBCollector(session).fetch_addresses()[0]

    assert record.first_seen is None
    assert record.last_seen is None
    assert record.threat_type is None
    assert record.confidence is None
    assert record.tags == []


def test_malformed_records_are_ignored() -> None:
    session = make_session(
        [
            {"type": "domain"},
            {"url": "", "type": "domain"},
            {"url": "not-an-url", "type": "url"},
            {"url": "not-an-ip", "type": "ipv4"},
            {"url": "valid.example", "type": "domain"},
        ]
    )

    records = SGBCollector(session).fetch_addresses()

    assert [record.value for record in records] == ["valid.example"]


def test_pagination_parameters_and_official_endpoint() -> None:
    session = make_session([])

    SGBCollector(session).fetch_addresses(page=3)

    assert session.get_calls == [
        (
            SGB_API_URL,
            {"page": 3, "per-page": SGB_PAGE_SIZE},
            30,
            False,
        )
    ]


@pytest.mark.parametrize("page", [0, -1, True])
def test_invalid_page_is_rejected(page: int) -> None:
    session = make_session([])

    with pytest.raises(ValueError, match="positive integer"):
        SGBCollector(session).fetch_addresses(page)

    assert session.get_calls == []


def test_http_errors_are_propagated() -> None:
    error = requests.HTTPError("service unavailable")
    session = FakeSession(FakeResponse({}, error=error))

    with pytest.raises(requests.HTTPError, match="service unavailable"):
        SGBCollector(session).fetch_addresses()


def test_multiple_records_and_ioc_urls_are_not_requested() -> None:
    malicious_url = "https://malicious.example/payload"
    session = make_session(
        [
            {"url": malicious_url, "type": "url"},
            {"url": "bad.example", "type": "domain"},
        ]
    )

    records = SGBCollector(session).fetch_addresses()

    assert [record.value for record in records] == [malicious_url, "bad.example"]
    assert len(session.get_calls) == 1
    assert session.get_calls[0][0] == SGB_API_URL

def test_bounded_pagination_stops_at_reported_total_count() -> None:
    session = SequenceSession(
        [
            {
                "totalCount": 3,
                "models": [
                    {"url": "one.example", "type": "domain"},
                    {"url": "two.example", "type": "domain"},
                ],
            },
            {
                "totalCount": 3,
                "models": [
                    {"url": "three.example", "type": "domain"},
                ],
            },
        ]
    )

    result = SGBCollector(session).fetch_bounded_addresses(max_pages=10)

    assert [record.value for record in result.records] == [
        "one.example",
        "two.example",
        "three.example",
    ]
    assert result.pages_fetched == 2
    assert result.reached_source_end is True
    assert [call[1]["page"] for call in session.get_calls] == [1, 2]


def test_bounded_pagination_stops_on_empty_page_without_total_count() -> None:
    session = SequenceSession(
        [
            {"models": [{"url": "one.example", "type": "domain"}]},
            {"models": []},
        ]
    )

    result = SGBCollector(session).fetch_bounded_addresses(max_pages=10)

    assert [record.value for record in result.records] == ["one.example"]
    assert result.pages_fetched == 2
    assert result.reached_source_end is True


def test_bounded_pagination_respects_maximum_page_cap() -> None:
    session = SequenceSession(
        [
            {
                "totalCount": 100,
                "models": [{"url": "one.example", "type": "domain"}],
            },
            {
                "totalCount": 100,
                "models": [{"url": "two.example", "type": "domain"}],
            },
        ]
    )

    result = SGBCollector(session).fetch_bounded_addresses(max_pages=2)

    assert [record.value for record in result.records] == [
        "one.example",
        "two.example",
    ]
    assert result.pages_fetched == 2
    assert result.reached_source_end is False


@pytest.mark.parametrize("max_pages", [0, -1, True])
def test_invalid_bounded_page_limit_is_rejected(max_pages: int) -> None:
    session = SequenceSession([])

    with pytest.raises(ValueError, match="max_pages"):
        SGBCollector(session).fetch_bounded_addresses(max_pages=max_pages)

    assert session.get_calls == []



def test_sgb_rejects_oversized_api_response(monkeypatch) -> None:
    monkeypatch.setattr(sgb, "MAX_SGB_PAGE_BYTES", 16)
    response = FakeResponse(
        {"models": [{"url": "example.com", "type": "domain"}]}
    )
    session = FakeSession(response)

    with pytest.raises(ValueError, match="safe download limit"):
        SGBCollector(session).fetch_addresses()


def test_sgb_rejects_invalid_json_response() -> None:
    response = FakeResponse({})
    response.content = b"{not-json"
    session = FakeSession(response)

    with pytest.raises(ValueError, match="invalid JSON"):
        SGBCollector(session).fetch_addresses()


def test_bounded_pagination_reports_progress() -> None:
    session = SequenceSession(
        [
            {
                "totalCount": 3,
                "models": [
                    {"url": "one.example", "type": "domain"},
                    {"url": "two.example", "type": "domain"},
                ],
            },
            {
                "totalCount": 3,
                "models": [{"url": "three.example", "type": "domain"}],
            },
        ]
    )
    progress: list[tuple[int, int, int | None]] = []

    result = SGBCollector(session).fetch_bounded_addresses(
        max_pages=10,
        progress=lambda page, seen, total: progress.append((page, seen, total)),
    )

    assert result.reached_source_end is True
    assert progress == [(1, 2, 3), (2, 3, 3)]


class PageSession:
    """Thread-safe fake keyed by page, recording overlap of in-flight requests."""

    def __init__(self, pages: dict[int, list[str]], total: int, fail_page: int | None = None,
                 delay: float = 0.05) -> None:
        import threading
        self.pages, self.total, self.fail_page, self.delay = pages, total, fail_page, delay
        self.lock = threading.Lock()
        self.active = self.peak = 0
        self.requested: list[int] = []

    def get(self, url, *, params, timeout, allow_redirects, stream=False):
        import time
        page = params["page"]
        with self.lock:
            self.requested.append(page)
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            time.sleep(self.delay)
            if page == self.fail_page:
                raise requests.HTTPError("page failed")
            models = [{"url": value, "type": "domain"} for value in self.pages.get(page, [])]
            return FakeResponse({"totalCount": self.total, "models": models})
        finally:
            with self.lock:
                self.active -= 1


def test_known_total_fetches_remaining_pages_in_bounded_parallel_and_keeps_order() -> None:
    from threatfusion.collectors.sgb import SGB_PARALLEL_PAGES
    pages = {page: [f"p{page}-{index}.example" for index in range(2)] for page in range(1, 9)}
    session = PageSession(pages, total=16)
    progress = []
    result = SGBCollector(session).fetch_bounded_addresses(
        max_pages=100, progress=lambda page, seen, total: progress.append((page, seen, total)))
    assert [record.value for record in result.records] == [v for page in range(1, 9) for v in pages[page]]
    assert result.pages_fetched == 8 and result.reached_source_end
    assert sorted(session.requested) == list(range(1, 9)) and session.requested[0] == 1
    assert 1 < session.peak <= SGB_PARALLEL_PAGES
    assert [seen for _, seen, _ in progress] == [2, 4, 6, 8, 10, 12, 14, 16]


def test_parallel_page_failure_fails_the_whole_snapshot() -> None:
    pages = {page: ["x.example"] for page in range(1, 7)}
    with pytest.raises(requests.HTTPError):
        SGBCollector(PageSession(pages, total=6, fail_page=4)).fetch_bounded_addresses(max_pages=100)


def test_page_cap_below_reported_total_stays_incomplete() -> None:
    pages = {page: ["x.example"] for page in range(1, 7)}
    session = PageSession(pages, total=6, delay=0)
    result = SGBCollector(session).fetch_bounded_addresses(max_pages=3)
    assert result.pages_fetched == 3 and not result.reached_source_end
    assert sorted(session.requested) == [1, 2, 3]
