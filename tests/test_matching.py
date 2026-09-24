import socket

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.matching import DNSIOCMatch, match_dns_events
from threatfusion.models import IOCRecord, IOCType


def test_case_insensitive_domain_match() -> None:
    event = DNSEvent(query_name="Example.COM.")
    indicator = IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox")

    matches = match_dns_events([event], [indicator])

    assert matches == [DNSIOCMatch(event=event, indicator=indicator, match_type="query_domain")]


def test_trailing_dot_domain_match() -> None:
    event = DNSEvent(query_name="evil.example.")
    indicator = IOCRecord("Evil.Example", IOCType.DOMAIN, "SGB")

    matches = match_dns_events([event], [indicator])

    assert matches[0].match_type == "query_domain"
    assert matches[0].event is event
    assert matches[0].indicator is indicator


def test_unrelated_domain_has_no_match() -> None:
    event = DNSEvent(query_name="safe.example.")
    indicator = IOCRecord("bad.example", IOCType.DOMAIN, "ThreatFox")

    assert match_dns_events([event], [indicator]) == []


def test_url_ioc_hostname_matches_dns_query() -> None:
    event = DNSEvent(query_name="Evil.Example.")
    indicator = IOCRecord("https://evil.example/payload/file.exe", IOCType.URL, "URLhaus")

    matches = match_dns_events([event], [indicator])

    assert matches == [
        DNSIOCMatch(event=event, indicator=indicator, match_type="url_hostname")
    ]


def test_malformed_url_ioc_is_ignored() -> None:
    event = DNSEvent(query_name="example.com.")
    indicator = IOCRecord("not a valid url", IOCType.URL, "ThreatFox")

    assert match_dns_events([event], [indicator]) == []


def test_malformed_url_ioc_does_not_break_matching_batch() -> None:
    event = DNSEvent(query_name="example.com.")
    malformed = IOCRecord("http://[::1", IOCType.URL, "ThreatFox")
    valid = IOCRecord("https://example.com/path", IOCType.URL, "URLhaus")

    matches = match_dns_events([event], [malformed, valid])

    assert matches == [
        DNSIOCMatch(event=event, indicator=valid, match_type="url_hostname")
    ]


def test_url_parsing_does_not_perform_networking(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access should not occur during URL parsing")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    event = DNSEvent(query_name="evil.example.")
    indicator = IOCRecord("https://evil.example/payload", IOCType.URL, "ThreatFox")

    matches = match_dns_events([event], [indicator])

    assert matches[0].match_type == "url_hostname"


def test_ipv4_response_ip_match() -> None:
    event = DNSEvent(query_name="example.com.", response_ip="203.0.113.7")
    indicator = IOCRecord("203.0.113.7", IOCType.IPV4, "ThreatFox")

    matches = match_dns_events([event], [indicator])

    assert matches == [
        DNSIOCMatch(event=event, indicator=indicator, match_type="response_ip")
    ]


def test_ipv6_response_ip_match() -> None:
    event = DNSEvent(query_name="example.com.", response_ip="2001:db8::1")
    indicator = IOCRecord("2001:0DB8:0000:0000:0000:0000:0000:0001", IOCType.IPV6, "SGB")

    matches = match_dns_events([event], [indicator])

    assert matches[0].match_type == "response_ip"
    assert matches[0].indicator is indicator


def test_ipv4_and_ipv6_types_do_not_cross_match() -> None:
    event = DNSEvent(query_name="example.com.", response_ip="203.0.113.7")
    ipv6_indicator = IOCRecord("203.0.113.7", IOCType.IPV6, "ThreatFox")

    assert match_dns_events([event], [ipv6_indicator]) == []


def test_hash_indicators_are_ignored() -> None:
    event = DNSEvent(query_name="example.com.", response_ip="203.0.113.7")
    indicator = IOCRecord("abcdef0123456789", IOCType.SHA256, "ThreatFox")

    assert match_dns_events([event], [indicator]) == []


def test_unknown_indicators_are_ignored() -> None:
    event = DNSEvent(query_name="example.com.")
    indicator = IOCRecord("example.com", IOCType.UNKNOWN, "ThreatFox")

    assert match_dns_events([event], [indicator]) == []


def test_missing_response_ip_is_safe() -> None:
    event = DNSEvent(query_name="example.com.")
    indicator = IOCRecord("203.0.113.7", IOCType.IPV4, "ThreatFox")

    assert match_dns_events([event], [indicator]) == []


def test_multiple_cti_sources_for_same_domain_produce_multiple_matches() -> None:
    event = DNSEvent(query_name="Example.COM.")
    first = IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox")
    second = IOCRecord("example.com", IOCType.DOMAIN, "SGB")

    matches = match_dns_events([event], [first, second])

    assert [match.indicator for match in matches] == [first, second]
    assert [match.match_type for match in matches] == ["query_domain", "query_domain"]


def test_domain_and_url_hostname_matches_can_both_be_preserved() -> None:
    event = DNSEvent(query_name="Evil.Example.")
    domain_indicator = IOCRecord("evil.example", IOCType.DOMAIN, "ThreatFox")
    url_indicator = IOCRecord("https://evil.example/payload", IOCType.URL, "URLhaus")

    matches = match_dns_events([event], [domain_indicator, url_indicator])

    assert [match.match_type for match in matches] == ["query_domain", "url_hostname"]
    assert [match.indicator for match in matches] == [domain_indicator, url_indicator]


def test_original_event_identity_is_preserved() -> None:
    event = DNSEvent(query_name="example.com.")
    indicator = IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox")

    matches = match_dns_events([event], [indicator])

    assert matches[0].event is event


def test_original_indicator_identity_is_preserved() -> None:
    event = DNSEvent(query_name="example.com.")
    indicator = IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox")

    matches = match_dns_events([event], [indicator])

    assert matches[0].indicator is indicator


def test_empty_events_or_indicators_return_empty_list() -> None:
    assert match_dns_events([], []) == []
    assert match_dns_events([DNSEvent("example.com.")], []) == []
    assert match_dns_events([], [IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox")]) == []


def test_no_networking_is_performed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("network access should not occur during matching")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    event = DNSEvent(query_name="Example.COM.", response_ip="203.0.113.7")
    indicators = [
        IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox"),
        IOCRecord("203.0.113.7", IOCType.IPV4, "SGB"),
    ]

    matches = match_dns_events([event], indicators)

    assert [match.match_type for match in matches] == ["query_domain", "response_ip"]
