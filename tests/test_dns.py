import socket
from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent, parse_dns_csv


def test_successful_complete_row() -> None:
    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "2026-09-24T10:30:00Z,192.168.1.10,Example.COM.,A,203.0.113.5\n"
    )

    events = parse_dns_csv(content)

    assert events == [
        DNSEvent(
            query_name="Example.COM.",
            timestamp=datetime(2026, 9, 24, 10, 30, tzinfo=timezone.utc),
            client_ip="192.168.1.10",
            query_type="A",
            response_ip="203.0.113.5",
        )
    ]


def test_query_name_case_and_trailing_dot_are_preserved() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T11:00:00Z,10.0.0.7,Example.Sub.Domain.,AAAA,2001:db8::1\n"

    event = parse_dns_csv(content)[0]

    assert event.query_name == "Example.Sub.Domain."


def test_surrounding_whitespace_is_trimmed() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n 2026-09-24T11:00:00Z , 10.0.0.7 ,  suspicious.example  ,  a , 203.0.113.9 \n"

    event = parse_dns_csv(content)[0]

    assert event.query_name == "suspicious.example"
    assert event.client_ip == "10.0.0.7"
    assert event.query_type == "A"
    assert event.response_ip == "203.0.113.9"


def test_iso_z_timestamp_is_parsed() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T10:31:00Z,192.168.1.15,suspicious.example,A,\n"

    event = parse_dns_csv(content)[0]

    assert event.timestamp == datetime(2026, 9, 24, 10, 31, tzinfo=timezone.utc)


def test_malformed_timestamp_is_none() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\nnot-a-timestamp,192.168.1.15,example.com,A,\n"

    event = parse_dns_csv(content)[0]

    assert event.timestamp is None


def test_missing_optional_fields_are_safe() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n,,example.com,,\n"

    event = parse_dns_csv(content)[0]

    assert event.timestamp is None
    assert event.client_ip is None
    assert event.query_type is None
    assert event.response_ip is None


def test_query_type_is_uppercased() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T12:00:00Z,10.0.0.1,example.com,cname,\n"

    event = parse_dns_csv(content)[0]

    assert event.query_type == "CNAME"


def test_valid_ipv4_and_ipv6_response_are_canonicalized() -> None:
    ipv4_content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T12:00:00Z,10.0.0.1,example.com,A,192.168.1.10\n"
    ipv6_content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T12:00:00Z,10.0.0.1,example.com,AAAA,2001:0DB8:0000:0000:0000:0000:0000:0001\n"

    ipv4_event = parse_dns_csv(ipv4_content)[0]
    ipv6_event = parse_dns_csv(ipv6_content)[0]

    assert ipv4_event.response_ip == "192.168.1.10"
    assert ipv6_event.response_ip == "2001:db8::1"


def test_nonstandard_ipv4_leading_zero_octets_are_rejected() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T12:00:00Z,10.0.0.1,example.com,A,192.168.001.010\n"

    event = parse_dns_csv(content)[0]

    assert event.response_ip is None


def test_malformed_response_ip_is_none_without_dropping_event() -> None:
    content = "timestamp,client_ip,query_name,query_type,response_ip\n2026-09-24T12:00:00Z,10.0.0.1,example.com,A,not-an-ip\n"

    event = parse_dns_csv(content)[0]

    assert event.query_name == "example.com"
    assert event.response_ip is None


def test_missing_query_name_row_is_skipped() -> None:
    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "2026-09-24T10:30:00Z,192.168.1.10,,A,203.0.113.5\n"
        "2026-09-24T10:31:00Z,192.168.1.15,valid.example,A,203.0.113.6\n"
    )

    events = parse_dns_csv(content)

    assert [event.query_name for event in events] == ["valid.example"]


def test_empty_query_name_row_is_skipped() -> None:
    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "2026-09-24T10:31:00Z,192.168.1.15,   ,A,203.0.113.6\n"
    )

    assert parse_dns_csv(content) == []


def test_missing_query_name_header_raises_value_error() -> None:
    content = "timestamp,client_ip,query_type,response_ip\n2026-09-24T10:31:00Z,192.168.1.15,A,203.0.113.6\n"

    with pytest.raises(ValueError, match="query_name"):
        parse_dns_csv(content)


def test_extra_columns_are_tolerated() -> None:
    content = (
        "timestamp,client_ip,query_name,unexpected_column,query_type,response_ip\n"
        "2026-09-24T10:31:00Z,192.168.1.15,example.com,ignored,A,203.0.113.6\n"
    )

    event = parse_dns_csv(content)[0]

    assert event.query_name == "example.com"
    assert event.query_type == "A"


def test_multiple_rows_produce_multiple_events() -> None:
    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "2026-09-24T10:30:00Z,192.168.1.10,first.example,A,203.0.113.5\n"
        "2026-09-24T10:31:00Z,192.168.1.15,second.example,AAAA,2001:db8::10\n"
    )

    events = parse_dns_csv(content)

    assert [event.query_name for event in events] == ["first.example", "second.example"]


def test_empty_csv_or_header_only_returns_empty_list() -> None:
    assert parse_dns_csv("") == []
    assert parse_dns_csv("timestamp,client_ip,query_name,query_type,response_ip\n") == []


def test_no_networking_is_performed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access should not occur during CSV parsing")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "2026-09-24T10:30:00Z,192.168.1.10,Example.COM.,A,203.0.113.5\n"
    )

    assert parse_dns_csv(content)[0].query_name == "Example.COM."
