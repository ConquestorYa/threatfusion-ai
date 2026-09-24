import socket

import pytest
import requests

from threatfusion.collectors.tranco import (
    REQUEST_TIMEOUT_SECONDS,
    TRANCO_DOWNLOAD_URL,
    TrancoCollector,
)


class FakeResponse:
    def __init__(
        self,
        text: str = "1,example.com\n",
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
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.get_calls: list[tuple[str, int, bool]] = []

    def get(
        self,
        url: str,
        *,
        timeout: int,
        allow_redirects: bool,
    ) -> FakeResponse:
        self.get_calls.append((url, timeout, allow_redirects))
        return self.response


def test_pinned_list_download_url_timeout_and_response_text() -> None:
    session = FakeSession(FakeResponse("1,example.com\n2,example.org\n"))

    csv_content = TrancoCollector("L5PV4", session).fetch_csv()

    assert csv_content == "1,example.com\n2,example.org\n"
    assert session.get_calls == [
        (TRANCO_DOWNLOAD_URL.format("L5PV4"), REQUEST_TIMEOUT_SECONDS, False)
    ]


@pytest.mark.parametrize("list_id", ["", "   ", "abc", "list/id", "https://example.com"])
def test_invalid_list_id_is_rejected(list_id: str) -> None:
    with pytest.raises(ValueError, match="list_id"):
        TrancoCollector(list_id)


def test_http_failure_is_propagated() -> None:
    error = requests.HTTPError("service unavailable")
    session = FakeSession(FakeResponse(error=error))

    with pytest.raises(requests.HTTPError, match="service unavailable"):
        TrancoCollector("L5PV4", session).fetch_csv()


def test_redirect_response_is_rejected_without_returning_csv() -> None:
    body = "1,redirected.example\n"
    session = FakeSession(FakeResponse(body, status_code=302))

    with pytest.raises(requests.HTTPError, match="HTTP status 302") as exc:
        TrancoCollector("L5PV4", session).fetch_csv()

    assert body not in str(exc.value)


def test_domains_in_csv_are_not_requested() -> None:
    session = FakeSession(
        FakeResponse("1,https://malicious.example/path\n2,other.example\n")
    )

    TrancoCollector("L5PV4", session).fetch_csv()

    assert session.get_calls == [
        (TRANCO_DOWNLOAD_URL.format("L5PV4"), REQUEST_TIMEOUT_SECONDS, False)
    ]


def test_collector_does_not_use_dns_or_external_network_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access should use only the injected session")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    session = FakeSession(FakeResponse("1,example.com\n"))

    assert TrancoCollector("L5PV4", session).fetch_csv() == "1,example.com\n"
