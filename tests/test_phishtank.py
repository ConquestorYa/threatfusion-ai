from datetime import datetime, timezone

import pytest
import requests

from threatfusion.collectors.phishtank import (
    PHISHTANK_FEED_URL,
    PhishTankCollector,
    parse_phishtank_csv,
)


class FakeResponse:
    def __init__(
        self,
        text: str,
        *,
        status_code: int = 200,
        error: Exception | None = None,
    ) -> None:
        self.text = text
        self.status_code = status_code
        self.error = error

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error


class FakeSession:
    def __init__(
        self,
        response: FakeResponse,
        *,
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


HEADER = (
    "phish_id,url,phish_detail_url,submission_time,verified,"
    "verification_time,online,target"
)


def test_parser_keeps_only_verified_online_urls() -> None:
    content = (
        HEADER
        + "\n1,https://bad.example/login,detail,"
        "2026-09-25T10:00:00+00:00,yes,2026-09-25T10:10:00+00:00,yes,Example Bank"
        + "\n2,https://offline.example/,detail,"
        "2026-09-25T10:00:00+00:00,yes,2026-09-25T10:10:00+00:00,no,Example"
    )

    records = parse_phishtank_csv(content)

    assert len(records) == 1
    record = records[0]
    assert record.value == "https://bad.example/login"
    assert record.source == "PhishTank"
    assert record.threat_type == "phishing"
    assert record.confidence == pytest.approx(1.0)
    assert record.first_seen == datetime(
        2026, 9, 25, 10, 10, tzinfo=timezone.utc
    )
    assert "target:Example Bank" in record.tags


def test_collector_uses_keyed_feed_and_does_not_visit_phish_urls() -> None:
    app_key = "test-app-key"
    content = (
        HEADER
        + "\n1,https://bad.example/login,detail,"
        "2026-09-25T10:00:00+00:00,yes,2026-09-25T10:10:00+00:00,yes,Example"
    )
    session = FakeSession(FakeResponse(content))

    records = PhishTankCollector(app_key, session).fetch_verified_online_urls()

    assert [item.value for item in records] == ["https://bad.example/login"]
    assert session.get_calls == [
        (PHISHTANK_FEED_URL.format(app_key), 30, False)
    ]


def test_missing_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="app key"):
        PhishTankCollector("   ")


def test_empty_or_invalid_feed_is_rejected() -> None:
    session = FakeSession(FakeResponse(HEADER))

    with pytest.raises(ValueError, match="no usable verified URLs"):
        PhishTankCollector("secret", session).fetch_verified_online_urls()


def test_connection_error_does_not_leak_keyed_url() -> None:
    app_key = "SUPER-SECRET-PHISHTANK-KEY"
    feed_url = PHISHTANK_FEED_URL.format(app_key)
    session = FakeSession(
        FakeResponse(""),
        get_error=requests.ConnectionError(f"failed to connect to {feed_url}"),
    )

    with pytest.raises(requests.HTTPError, match="PhishTank feed request failed") as exc:
        PhishTankCollector(app_key, session).fetch_verified_online_urls()

    assert app_key not in str(exc.value)
    assert feed_url not in str(exc.value)
