from datetime import datetime, timezone

import pytest
import requests

from threatfusion.collectors.urlhaus import (
    URLHAUS_EXPORT_URL,
    URLHAUS_FULL_EXPORT_URL,
    URLhausCollector,
    parse_urlhaus_csv,
)
from threatfusion.models import IOCType


class FakeResponse:
    def __init__(
        self,
        text: str,
        error: Exception | None = None,
        status_code: int = 200,
    ) -> None:
        self.text = text
        self.error = error
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error


class FakeSession:
    def __init__(
        self,
        response: FakeResponse,
        get_error: requests.RequestException | None = None,
    ) -> None:
        self.response = response
        self.get_error = get_error
        self.get_calls: list[tuple[str, int, bool]] = []

    def get(
        self,
        url: str,
        *,
        timeout: int,
        allow_redirects: bool,
    ) -> FakeResponse:
        self.get_calls.append((url, timeout, allow_redirects))
        if self.get_error is not None:
            raise self.get_error
        return self.response


CSV_HEADER = "id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter"


def make_session(rows: str) -> FakeSession:
    return FakeSession(FakeResponse(f"{CSV_HEADER}\n{rows}"))


def test_successful_url_conversion_and_field_mapping() -> None:
    malicious_url = "https://malicious.example/payload"
    session = make_session(
        f'1,2026-08-20 05:17:07 UTC,{malicious_url},online,malware_distribution,"tag-one,tag-two",link,reporter'
    )

    records = URLhausCollector("secret", session).fetch_recent_urls()

    assert len(records) == 1
    assert records[0].value == malicious_url
    assert records[0].source == "URLhaus"
    assert records[0].ioc_type is IOCType.URL
    assert records[0].first_seen == datetime(
        2026, 8, 20, 5, 17, 7, tzinfo=timezone.utc
    )
    assert records[0].last_seen is None
    assert records[0].threat_type == "malware_distribution"
    assert records[0].tags == ["tag-one", "tag-two"]
    assert records[0].confidence is None


def test_iso_timestamp_is_supported_and_malformed_timestamp_is_none() -> None:
    session = make_session(
        "1,not-a-timestamp,https://one.example/a,online,malware,,link,reporter\n"
        "2,2026-08-20T05:17:07Z,https://two.example/b,online,phishing,,link,reporter"
    )

    records = URLhausCollector("secret", session).fetch_recent_urls()

    assert records[0].first_seen is None
    assert records[1].first_seen == datetime(
        2026, 8, 20, 5, 17, 7, tzinfo=timezone.utc
    )


def test_empty_tags_are_safe() -> None:
    session = make_session("1,2026-08-20 05:17:07 UTC,https://one.example/a,online,,,link,reporter")

    records = URLhausCollector("secret", session).fetch_recent_urls()

    assert records[0].tags == []


def test_comments_and_malformed_rows_are_ignored() -> None:
    session = FakeSession(
        FakeResponse(
            "# URLhaus export metadata\n"
            "# another comment\n"
            f"{CSV_HEADER}\n"
            "malformed row\n"
            ",2026-08-20 05:17:07 UTC,,online,malware,,link,reporter\n"
            "1,2026-08-20 05:17:07 UTC,https://valid.example/a,online,malware,,link,reporter"
        )
    )

    records = URLhausCollector("secret", session).fetch_recent_urls()

    assert [record.value for record in records] == ["https://valid.example/a"]


def test_comment_prefixed_header_and_last_online_are_supported() -> None:
    content = (
        "# URLhaus export metadata\n"
        "# generated at 2026-09-23\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        "1,2026-08-20 05:17:07 UTC,https://valid.example/a,online,,malware,,link,reporter"
    )

    records = parse_urlhaus_csv(content)

    assert len(records) == 1
    assert records[0].value == "https://valid.example/a"
    assert records[0].threat_type == "malware"


def test_missing_valid_header_returns_no_records() -> None:
    content = (
        "# metadata only\n"
        "1,2026-08-20 05:17:07 UTC,https://valid.example/a,online,malware"
    )

    assert parse_urlhaus_csv(content) == []


def test_http_errors_are_propagated() -> None:
    auth_key = "distinctive-auth-key"
    error = requests.HTTPError(
        f"403 Server Error: forbidden for url: {URLHAUS_EXPORT_URL.format(auth_key)}"
    )
    session = FakeSession(FakeResponse("", error=error, status_code=403))

    with pytest.raises(requests.HTTPError, match="URLhaus export request failed") as exc:
        URLhausCollector(auth_key, session).fetch_recent_urls()

    assert auth_key not in str(exc.value)
    assert URLHAUS_EXPORT_URL.format(auth_key) not in str(exc.value)
    assert len(session.get_calls) == 1


def test_connection_error_does_not_leak_authenticated_url() -> None:
    auth_key = "SUPER-SECRET-URLHAUS-KEY"
    authenticated_url = URLHAUS_EXPORT_URL.format(auth_key)
    error = requests.ConnectionError(f"failed to connect to {authenticated_url}")
    session = FakeSession(FakeResponse(""), get_error=error)

    with pytest.raises(requests.HTTPError, match="URLhaus export request failed") as exc:
        URLhausCollector(auth_key, session).fetch_recent_urls()

    assert auth_key not in str(exc.value)
    assert authenticated_url not in str(exc.value)
    assert len(session.get_calls) == 1


def test_redirect_response_is_rejected_without_another_request() -> None:
    session = FakeSession(FakeResponse("", status_code=302))

    with pytest.raises(requests.HTTPError, match="HTTP status 302"):
        URLhausCollector("secret", session).fetch_recent_urls()

    assert len(session.get_calls) == 1


def test_only_official_export_is_requested_and_ioc_urls_are_not_requested() -> None:
    malicious_url = "https://malicious.example/payload"
    auth_key = "test-auth-key"
    session = make_session(
        f"1,2026-08-20 05:17:07 UTC,{malicious_url},online,malware,,link,reporter"
    )

    record = URLhausCollector(auth_key, session).fetch_recent_urls()[0]

    assert session.get_calls == [
        (URLHAUS_EXPORT_URL.format(auth_key), 30, False)
    ]
    assert record.value == malicious_url
    assert auth_key not in record.value
    assert auth_key not in (record.threat_type or "")
    assert auth_key not in record.tags


def test_full_export_uses_official_full_dump_endpoint() -> None:
    malicious_url = "https://full.example/payload"
    auth_key = "full-export-key"
    session = make_session(
        f"1,2026-08-20 05:17:07 UTC,{malicious_url},online,malware,,link,reporter"
    )

    records = URLhausCollector(auth_key, session).fetch_full_urls()

    assert [item.value for item in records] == [malicious_url]
    assert session.get_calls == [
        (URLHAUS_FULL_EXPORT_URL.format(auth_key), 30, False)
    ]


def test_empty_full_export_is_rejected_without_replacing_cache() -> None:
    session = FakeSession(FakeResponse("# metadata only"))

    with pytest.raises(ValueError, match="no usable URLs"):
        URLhausCollector("secret", session).fetch_full_urls()


def test_multiple_csv_rows_produce_multiple_records() -> None:
    session = make_session(
        "1,2026-08-20 05:17:07 UTC,https://one.example/a,online,malware,,link,reporter\n"
        "2,2026-08-20 05:17:08 UTC,https://two.example/b,online,phishing,,link,reporter"
    )

    records = URLhausCollector("secret", session).fetch_recent_urls()

    assert [record.value for record in records] == [
        "https://one.example/a",
        "https://two.example/b",
    ]