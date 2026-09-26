import io
import zipfile
from datetime import datetime, timezone

import pytest
import requests

from threatfusion.collectors.threatfox import (
    THREATFOX_API_URL,
    THREATFOX_FULL_EXPORT_URL,
    ThreatFoxCollector,
    parse_threatfox_csv,
)
from threatfusion.models import IOCType


class FakeResponse:
    def __init__(
        self,
        payload: object,
        error: Exception | None = None,
        *,
        content: bytes = b"",
        status_code: int = 200,
    ) -> None:
        self.payload = payload
        self.error = error
        self.content = content
        self.status_code = status_code
        self.text = content.decode("utf-8", errors="replace")

    def raise_for_status(self) -> None:
        if self.error is not None:
            raise self.error

    def json(self) -> object:
        return self.payload


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.post_calls: list[tuple[object, dict[str, str], dict[str, object], int]] = []
        self.get_calls: list[tuple[object, int, bool]] = []

    def post(
        self,
        url: object,
        *,
        headers: dict[str, str],
        json: dict[str, object],
        timeout: int,
    ) -> FakeResponse:
        self.post_calls.append((url, headers, json, timeout))
        return self.response

    def get(
        self,
        url: object,
        *,
        timeout: int,
        allow_redirects: bool,
    ) -> FakeResponse:
        self.get_calls.append((url, timeout, allow_redirects))
        return self.response


def make_session(items: list[dict[str, object]]) -> FakeSession:
    return FakeSession(FakeResponse({"query_status": "ok", "data": items}))


def test_successful_domain_conversion() -> None:
    session = make_session([{"ioc": "Example.COM.", "ioc_type": "domain"}])

    records = ThreatFoxCollector("secret", session).fetch_recent_iocs()

    assert records[0].value == "Example.COM."
    assert records[0].ioc_type is IOCType.DOMAIN
    assert records[0].source == "ThreatFox"


def test_successful_url_conversion() -> None:
    session = make_session(
        [{"ioc": "https://malicious.example/path", "ioc_type": "url"}]
    )

    records = ThreatFoxCollector("secret", session).fetch_recent_iocs()

    assert records[0].value == "https://malicious.example/path"
    assert records[0].ioc_type is IOCType.URL


def test_ipv4_with_port_conversion() -> None:
    session = make_session([{"ioc": "192.0.2.10:443", "ioc_type": "ip:port"}])

    records = ThreatFoxCollector("secret", session).fetch_recent_iocs()

    assert records[0].value == "192.0.2.10"
    assert records[0].ioc_type is IOCType.IPV4


def test_ipv6_with_port_conversion() -> None:
    session = make_session([{"ioc": "[2001:db8::10]:443", "ioc_type": "ip:port"}])

    records = ThreatFoxCollector("secret", session).fetch_recent_iocs()

    assert records[0].value == "2001:db8::10"
    assert records[0].ioc_type is IOCType.IPV6


def test_bracketed_ipv6_with_non_numeric_port_is_unknown() -> None:
    session = make_session([{"ioc": "[2001:db8::10]:abc", "ioc_type": "ip:port"}])

    record = ThreatFoxCollector("secret", session).fetch_recent_iocs()[0]

    assert record.value == "[2001:db8::10]:abc"
    assert record.ioc_type is IOCType.UNKNOWN


def test_timestamps_and_tags_are_parsed() -> None:
    session = make_session(
        [
            {
                "ioc": "example.com",
                "ioc_type": "domain",
                "first_seen": "2026-09-23T10:15:00Z",
                "last_seen": "2026-09-23T11:15:00+00:00",
                "threat_type": "botnet_cc",
                "tags": ["c2", "malware"],
            }
        ]
    )

    record = ThreatFoxCollector("secret", session).fetch_recent_iocs()[0]

    assert record.first_seen == datetime(2026, 9, 23, 10, 15, tzinfo=timezone.utc)
    assert record.last_seen == datetime(2026, 9, 23, 11, 15, tzinfo=timezone.utc)
    assert record.threat_type == "botnet_cc"
    assert record.tags == ["c2", "malware"]
    assert record.confidence is None


def test_documented_threatfox_timestamp_is_parsed_as_utc() -> None:
    session = make_session(
        [
            {
                "ioc": "example.com",
                "ioc_type": "domain",
                "first_seen": "2020-12-08 13:36:27 UTC",
            }
        ]
    )

    record = ThreatFoxCollector("secret", session).fetch_recent_iocs()[0]

    assert record.first_seen == datetime(2020, 12, 8, 13, 36, 27, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("threatfox_type", "expected_type"),
    [
        ("md5_hash", IOCType.MD5),
        ("sha1_hash", IOCType.SHA1),
        ("sha256_hash", IOCType.SHA256),
    ],
)
def test_hash_types_preserve_value_and_map_to_ioc_type(
    threatfox_type: str, expected_type: IOCType
) -> None:
    hash_value = "ABCDEF0123456789"
    session = make_session([{"ioc": hash_value, "ioc_type": threatfox_type}])

    record = ThreatFoxCollector("secret", session).fetch_recent_iocs()[0]

    assert record.value == hash_value
    assert record.ioc_type is expected_type


def test_unsupported_type_becomes_unknown() -> None:
    session = make_session([{"ioc": "abc123", "ioc_type": "sha512_hash"}])

    record = ThreatFoxCollector("secret", session).fetch_recent_iocs()[0]

    assert record.value == "abc123"
    assert record.ioc_type is IOCType.UNKNOWN


@pytest.mark.parametrize("days", [0, 8])
def test_days_outside_allowed_range_are_rejected(days: int) -> None:
    session = make_session([])

    with pytest.raises(ValueError, match="between 1 and 7"):
        ThreatFoxCollector("secret", session).fetch_recent_iocs(days)

    assert session.post_calls == []


def test_non_success_query_status_raises_clear_exception() -> None:
    session = FakeSession(FakeResponse({"query_status": "no_result"}))

    with pytest.raises(ValueError, match="ThreatFox query failed: no_result"):
        ThreatFoxCollector("secret", session).fetch_recent_iocs()


def test_http_errors_are_propagated() -> None:
    error = requests.HTTPError("service unavailable")
    session = FakeSession(FakeResponse({}, error=error))

    with pytest.raises(requests.HTTPError, match="service unavailable"):
        ThreatFoxCollector("secret", session).fetch_recent_iocs()


def test_malicious_url_is_sent_as_data_only() -> None:
    malicious_url = "https://malicious.example/payload"
    session = make_session([{"ioc": malicious_url, "ioc_type": "url"}])

    record = ThreatFoxCollector("secret", session).fetch_recent_iocs()[0]

    assert record.value == malicious_url
    assert len(session.post_calls) == 1
    assert session.post_calls[0][0] == THREATFOX_API_URL
    assert session.post_calls[0][2] == {"query": "get_iocs", "days": 1}


def _zip_full_csv(text: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("full.csv", text)
    return buffer.getvalue()


def test_full_export_parser_maps_domain_url_and_confidence() -> None:
    content = (
        "# first_seen,ioc_id,ioc,ioc_type,threat_type,confidence_level,tags\n"
        '2026-09-01 10:00:00 UTC,1,bad.example,domain,botnet_cc,90,"c2,test"\n'
        "2026-09-02 11:00:00 UTC,2,https://bad.example/p,url,payload_delivery,75,malware"
    )

    records = parse_threatfox_csv(content)

    assert [record.ioc_type for record in records] == [IOCType.DOMAIN, IOCType.URL]
    assert records[0].value == "bad.example"
    assert records[0].confidence == pytest.approx(0.9)
    assert records[0].tags == ["c2", "test"]
    assert records[1].confidence == pytest.approx(0.75)


def test_full_export_fetch_uses_official_archive_and_hides_key() -> None:
    auth_key = "secret-full-export-key"
    csv_text = (
        "# first_seen,ioc,ioc_type,threat_type,confidence_level,tags\n"
        "2026-09-01 10:00:00 UTC,bad.example,domain,botnet_cc,100,c2"
    )
    session = FakeSession(
        FakeResponse({}, content=_zip_full_csv(csv_text))
    )

    records = ThreatFoxCollector(auth_key, session).fetch_full_iocs()

    assert [record.value for record in records] == ["bad.example"]
    assert session.get_calls == [
        (THREATFOX_FULL_EXPORT_URL.format(auth_key), 30, False)
    ]
