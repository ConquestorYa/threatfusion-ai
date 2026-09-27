from datetime import datetime, timezone

import pytest
import requests

from threatfusion.collectors.phishtank import (
    PHISHTANK_AUTHENTICATED_FEED_TEMPLATE,
    PHISHTANK_FEED_URL,
    PHISHTANK_USER_AGENT,
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
        self.content = text.encode("utf-8")
        self.headers: dict[str, str] = {}

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
        self.get_calls: list[tuple[str, dict[str, str], int, bool, bool]] = []

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: int,
        allow_redirects: bool,
        stream: bool,
    ) -> FakeResponse:
        self.get_calls.append((url, headers, timeout, allow_redirects, stream))
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


def test_collector_uses_public_feed_with_descriptive_user_agent() -> None:
    content = (
        HEADER
        + "\n1,https://bad.example/login,detail,"
        "2026-09-25T10:00:00+00:00,yes,2026-09-25T10:10:00+00:00,yes,Example"
    )
    session = FakeSession(FakeResponse(content))

    records = PhishTankCollector(session).fetch_verified_online_urls()

    assert [item.value for item in records] == ["https://bad.example/login"]
    assert session.get_calls == [
        (
            PHISHTANK_FEED_URL,
            {"User-Agent": PHISHTANK_USER_AGENT},
            30,
            False,
            True,
        )
    ]


def test_public_feed_uses_https_and_disables_redirects() -> None:
    assert PHISHTANK_FEED_URL.startswith("https://")


def test_redirect_response_is_rejected_without_following_it() -> None:
    session = FakeSession(FakeResponse("", status_code=302))

    with pytest.raises(
        requests.HTTPError,
        match="set PHISHTANK_APP_KEY.*HTTP status 302",
    ):
        PhishTankCollector(session).fetch_verified_online_urls()

    assert len(session.get_calls) == 1
    assert session.get_calls[0][-2:] == (False, True)


def test_empty_or_invalid_public_feed_is_rejected() -> None:
    session = FakeSession(FakeResponse(HEADER))

    with pytest.raises(ValueError, match="no usable verified URLs"):
        PhishTankCollector(session).fetch_verified_online_urls()


def test_connection_error_is_sanitized() -> None:
    session = FakeSession(
        FakeResponse(""),
        get_error=requests.ConnectionError(
            f"failed to connect to {PHISHTANK_FEED_URL}"
        ),
    )

    with pytest.raises(
        requests.HTTPError,
        match="PhishTank public feed request failed",
    ) as exc:
        PhishTankCollector(session).fetch_verified_online_urls()

    assert PHISHTANK_FEED_URL not in str(exc.value)


def test_oversized_public_feed_is_rejected() -> None:
    response = FakeResponse(HEADER)
    response.headers = {"Content-Length": str(65 * 1024 * 1024)}
    session = FakeSession(response)

    with pytest.raises(ValueError, match="safe download limit"):
        PhishTankCollector(session).fetch_verified_online_urls()


def test_authenticated_feed_url_uses_app_key_without_logging_it() -> None:
    content = (
        HEADER
        + "\n1,https://bad.example/login,detail,"
        "2026-09-25T10:00:00+00:00,yes,2026-09-25T10:10:00+00:00,yes,Example"
    )
    session = FakeSession(FakeResponse(content))
    app_key = "example-key-123"

    records = PhishTankCollector(
        session,
        app_key=app_key,
    ).fetch_verified_online_urls()

    assert len(records) == 1
    assert session.get_calls[0][0] == PHISHTANK_AUTHENTICATED_FEED_TEMPLATE.format(
        app_key=app_key
    )


def test_authenticated_redirect_error_does_not_expose_app_key() -> None:
    app_key = "very-secret-phishtank-key"
    session = FakeSession(FakeResponse("", status_code=302))

    with pytest.raises(
        requests.HTTPError,
        match="verify PHISHTANK_APP_KEY",
    ) as exc:
        PhishTankCollector(session, app_key=app_key).fetch_verified_online_urls()

    assert app_key not in str(exc.value)
