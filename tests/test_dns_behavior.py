import socket
from datetime import datetime, timedelta, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import aggregate_dns_behavior


def test_aggregate_dns_behavior_normalizes_and_groups_domains() -> None:
    events = [
        DNSEvent(
            query_name="Example.COM.",
            client_ip="10.0.0.1",
            query_type="A",
            response_ip="203.0.113.10",
        ),
        DNSEvent(
            query_name="example.com",
            client_ip="10.0.0.2",
            query_type="AAAA",
            response_ip="2001:db8::1",
        ),
    ]

    result = aggregate_dns_behavior(events)

    assert len(result) == 1
    behavior = result[0]
    assert behavior.domain == "example.com"
    assert behavior.event_count == 2
    assert behavior.unique_client_count == 2
    assert behavior.unique_response_ip_count == 2
    assert behavior.query_types == ("A", "AAAA")


def test_timestamp_summary_reports_observed_span() -> None:
    start = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
    events = [
        DNSEvent(query_name="example.com", timestamp=start),
        DNSEvent(
            query_name="example.com",
            timestamp=start + timedelta(seconds=75),
        ),
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.first_seen == start
    assert behavior.last_seen == start + timedelta(seconds=75)
    assert behavior.observed_span_seconds == pytest.approx(75.0)


def test_mixed_naive_and_aware_timestamps_are_not_compared() -> None:
    events = [
        DNSEvent(
            query_name="example.com",
            timestamp=datetime(
                2026, 9, 24, 10, 0, tzinfo=timezone.utc
            ).replace(tzinfo=None),
        ),
        DNSEvent(
            query_name="example.com",
            timestamp=datetime(2026, 9, 24, 10, 1, tzinfo=timezone.utc),
        ),
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.first_seen is None
    assert behavior.last_seen is None
    assert behavior.observed_span_seconds is None


def test_missing_optional_fields_do_not_create_fake_unique_values() -> None:
    events = [
        DNSEvent(query_name="example.com"),
        DNSEvent(query_name="example.com"),
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.unique_client_count == 0
    assert behavior.unique_response_ip_count == 0
    assert behavior.query_types == ()


def test_output_order_is_deterministic_by_normalized_domain() -> None:
    events = [
        DNSEvent(query_name="z.example"),
        DNSEvent(query_name="A.example."),
    ]

    result = aggregate_dns_behavior(events)

    assert [item.domain for item in result] == ["a.example", "z.example"]


def test_dns_behavior_aggregation_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("DNS behavior aggregation must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    result = aggregate_dns_behavior(
        [DNSEvent(query_name="Example.COM.", response_ip="203.0.113.5")]
    )

    assert result[0].domain == "example.com"


def test_response_code_and_nxdomain_metrics_are_explainable() -> None:
    events = [
        DNSEvent(query_name="example.com", response_code="NOERROR"),
        DNSEvent(query_name="example.com", response_code="NXDOMAIN"),
        DNSEvent(query_name="example.com", response_code="NXDOMAIN"),
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.response_code_counts == (("NOERROR", 1), ("NXDOMAIN", 2))
    assert behavior.nxdomain_count == 2
    assert behavior.nxdomain_ratio == pytest.approx(2 / 3)


def test_domain_shape_metrics_include_depth_numeric_ratio_and_entropy() -> None:
    behavior = aggregate_dns_behavior(
        [DNSEvent(query_name="a12.b34.c56.example.com")]
    )[0]

    assert behavior.label_count == 5
    assert behavior.subdomain_depth == 3
    assert behavior.numeric_character_ratio == pytest.approx(6 / 19)
    assert behavior.hostname_entropy is not None


def test_response_ip_churn_rate_uses_observed_responses() -> None:
    events = [
        DNSEvent(query_name="example.com", response_ip="203.0.113.1"),
        DNSEvent(query_name="example.com", response_ip="203.0.113.2"),
        DNSEvent(query_name="example.com", response_ip="203.0.113.2"),
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.unique_response_ip_count == 2
    assert behavior.response_ip_churn_rate == pytest.approx(2 / 3)


def test_periodicity_metrics_are_derived_when_timestamps_are_comparable() -> None:
    start = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
    events = [
        DNSEvent(query_name="example.com", timestamp=start + timedelta(seconds=30 * i))
        for i in range(4)
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.periodic_interval_seconds == pytest.approx(30.0)
    assert behavior.periodicity_score == pytest.approx(1.0)
    assert behavior.periodic_query_pattern is True


def test_periodicity_metrics_gracefully_skip_mixed_timestamp_awareness() -> None:
    events = [
        DNSEvent(
            query_name="example.com",
            timestamp=datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc).replace(
                tzinfo=None
            ),
        ),
        DNSEvent(
            query_name="example.com",
            timestamp=datetime(2026, 9, 24, 10, 1, tzinfo=timezone.utc),
        ),
        DNSEvent(
            query_name="example.com",
            timestamp=datetime(2026, 9, 24, 10, 2, tzinfo=timezone.utc),
        ),
    ]

    behavior = aggregate_dns_behavior(events)[0]

    assert behavior.periodic_interval_seconds is None
    assert behavior.periodicity_score is None
    assert behavior.periodic_query_pattern is None
