import bz2
import json
from datetime import datetime, timezone

import pytest
import requests

from threatfusion.collectors.phishtank import (
    PHISHTANK_EXPORT_URL,
    PhishTankCollector,
    parse_phishtank_json,
)
from threatfusion.models import IOCType


class FakeResponse:
    def __init__(
        self,
        content: bytes,
        *,
        status_code: int = 200,
        error: Exception | None = None,
    ) -> None:
        self.content = content
        self.status_code = status_code
        self.error = error

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, dict[str, str], int, bool]] = []

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: int,
        allow_redirects: bool,
    ) -> FakeResponse:
        self.calls.append((url, headers, timeout, allow_redirects))
        return self.response


def _feed(items: list[dict[str, object]]) -> bytes:
    return bz2.compress(json.dumps(items).encode("utf-8"))


def test_parse_verified_online_phishing_urls() -> None:
    payload = _feed(
        [
            {
                "url": "https://phish.example/login",
                "verified": "yes",
                "online": "yes",
                "submission_time": "2026-09-01T10:00:00+00:00",
                "verification_time": "2026-09-01T11:00:00+00:00",
                "target": "Example Bank",
            },
            {
                "url": "https://offline.example/",
                "verified": "yes",
                "online": "no",
            },
        ]
    )

    records = parse_phishtank_json(payload)

    assert len(records) == 1
    assert records[0].value == "https://phish.example/login"
    assert records[0].ioc_type is IOCType.URL
    assert records[0].source == "PhishTank"
    assert records[0].threat_type == "phishing"
    assert records[0].first_seen == datetime(
        2026, 9, 1, 11, 0, tzinfo=timezone.utc
    )
    assert "target:Example Bank" in records[0].tags


def test_invalid_feed_data_is_rejected() -> None:
    with pytest.raises(ValueError, match="bzip2"):
        parse_phishtank_json(b"not-bzip2")


def test_collector_uses_authenticated_feed_without_logging_key() -> None:
    key = "private-phishtank-key"
    session = FakeSession(
        FakeResponse(
            _feed(
                [
                    {
                        "url": "http://phish.example/",
                        "verified": "yes",
                        "online": "yes",
                    }
                ]
            )
        )
    )

    records = PhishTankCollector(key, session).fetch_online_verified_urls()

    assert [record.value for record in records] == ["http://phish.example/"]
    assert session.calls[0][0] == PHISHTANK_EXPORT_URL.format(key)
    assert session.calls[0][2:] == (45, False)
    assert "ThreatFusionAI" in session.calls[0][1]["User-Agent"]


def test_empty_app_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        PhishTankCollector("   ")


def test_http_failure_is_sanitized() -> None:
    key = "secret-key"
    session = FakeSession(
        FakeResponse(
            b"",
            status_code=403,
            error=requests.HTTPError(
                f"forbidden {PHISHTANK_EXPORT_URL.format(key)}"
            ),
        )
    )

    with pytest.raises(requests.HTTPError, match="HTTP status 403") as exc:
        PhishTankCollector(key, session).fetch_online_verified_urls()

    assert key not in str(exc.value)
