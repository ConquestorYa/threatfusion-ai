import pytest

from threatfusion.request_guard import host_header_name, is_allowed_host


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1:8501", "localhost:8501", "LOCALHOST", "localhost.:8501", "[::1]:8501", "127.0.0.1"],
)
def test_loopback_host_headers_are_allowed(host: str) -> None:
    assert is_allowed_host(host, {})


@pytest.mark.parametrize(
    "host",
    [
        "attacker.example:8501",
        "127.0.0.1.nip.io:8501",
        "localhost.attacker.example",
        "192.168.1.10:8501",
        "",
        "127.0.0.1:notaport",
        "user@127.0.0.1",
        "127.0.0.1/path",
        "[::1",
    ],
)
def test_rebinding_or_malformed_host_headers_are_rejected(host: str) -> None:
    assert not is_allowed_host(host, {})


def test_missing_host_header_is_allowed_for_non_browser_clients() -> None:
    assert is_allowed_host(None, {})


def test_explicit_extra_hosts_are_allowed() -> None:
    environment = {"THREATFUSION_ALLOWED_HOSTS": " Analyst-Box.lan , 10.0.0.5 "}

    assert is_allowed_host("analyst-box.lan:8501", environment)
    assert is_allowed_host("10.0.0.5", environment)
    assert not is_allowed_host("other.lan", environment)


def test_host_header_name_normalizes_case_and_brackets() -> None:
    assert host_header_name("LocalHost:1") == "localhost"
    assert host_header_name("[::1]:8501") == "::1"
