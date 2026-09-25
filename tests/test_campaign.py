from __future__ import annotations

import socket
from datetime import datetime, timezone

import pytest

from threatfusion.campaign import find_related_activity
from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import DomainBehavior
from threatfusion.hybrid_assessment import HybridAssessment, HybridVerdict
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def assessment(domain: str, verdict: HybridVerdict) -> HybridAssessment:
    return HybridAssessment(
        domain=domain,
        verdict=verdict,
        known_ioc_sources=(),
        known_match_types=(),
        ml_probability=None,
        ml_tier=None,
        behavior=DomainBehavior(
            domain=domain,
            event_count=1,
            unique_client_count=1,
            unique_response_ip_count=1,
            query_types=("A",),
            first_seen=None,
            last_seen=None,
            observed_span_seconds=None,
        ),
        behavior_signals=(),
        reasons=(),
    )


def result_with(
    events: list[DNSEvent],
    assessments: list[HybridAssessment],
) -> RuntimeAnalysisResult:
    return RuntimeAnalysisResult(
        events=tuple(events),
        matches=(),
        ml_probabilities={},
        assessments=tuple(assessments),
    )


def test_shared_client_creates_relationship_and_cluster() -> None:
    start = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
    result = result_with(
        [
            DNSEvent(
                query_name="a.example",
                client_ip="192.0.2.10",
                timestamp=start,
            ),
            DNSEvent(
                query_name="b.example",
                client_ip="192.0.2.10",
                timestamp=start,
            ),
        ],
        [
            assessment("a.example", HybridVerdict.REVIEW),
            assessment("b.example", HybridVerdict.KNOWN_THREAT),
        ],
    )

    report = find_related_activity(result)

    assert len(report.relationships) == 1
    relationship = report.relationships[0]
    assert relationship.shared_client_count == 1
    assert relationship.shared_response_ip_count == 0
    assert relationship.reasons == ("shared_client", "time_proximity")
    assert len(report.clusters) == 1
    assert report.clusters[0].domains == ("a.example", "b.example")


def test_shared_response_ip_creates_relationship() -> None:
    result = result_with(
        [
            DNSEvent(
                query_name="a.example",
                response_ip="198.51.100.10",
            ),
            DNSEvent(
                query_name="b.example",
                response_ip="198.51.100.10",
            ),
        ],
        [
            assessment("a.example", HybridVerdict.HIGH_RISK),
            assessment("b.example", HybridVerdict.REVIEW),
        ],
    )

    relationship = find_related_activity(result).relationships[0]

    assert relationship.shared_client_count == 0
    assert relationship.shared_response_ip_count == 1
    assert relationship.reasons == ("shared_response_ip",)


def test_time_proximity_alone_does_not_create_relationship() -> None:
    start = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
    result = result_with(
        [
            DNSEvent(query_name="a.example", timestamp=start),
            DNSEvent(query_name="b.example", timestamp=start),
        ],
        [
            assessment("a.example", HybridVerdict.REVIEW),
            assessment("b.example", HybridVerdict.REVIEW),
        ],
    )

    report = find_related_activity(result)

    assert report.relationships == ()
    assert report.clusters == ()


def test_low_verdict_domains_are_excluded() -> None:
    result = result_with(
        [
            DNSEvent(
                query_name="review.example",
                client_ip="192.0.2.10",
            ),
            DNSEvent(
                query_name="low.example",
                client_ip="192.0.2.10",
            ),
        ],
        [
            assessment("review.example", HybridVerdict.REVIEW),
            assessment("low.example", HybridVerdict.LOW),
        ],
    )

    report = find_related_activity(result)

    assert report.relationships == ()
    assert report.clusters == ()


def test_connected_relationships_form_one_deterministic_group() -> None:
    result = result_with(
        [
            DNSEvent(query_name="c.example", client_ip="192.0.2.2"),
            DNSEvent(query_name="b.example", client_ip="192.0.2.2"),
            DNSEvent(query_name="b.example", client_ip="192.0.2.1"),
            DNSEvent(query_name="a.example", client_ip="192.0.2.1"),
        ],
        [
            assessment("c.example", HybridVerdict.REVIEW),
            assessment("a.example", HybridVerdict.REVIEW),
            assessment("b.example", HybridVerdict.REVIEW),
        ],
    )

    report = find_related_activity(result)

    assert len(report.clusters) == 1
    assert report.clusters[0].cluster_id == "group-1"
    assert report.clusters[0].domains == (
        "a.example",
        "b.example",
        "c.example",
    )
    assert len(report.clusters[0].relationships) == 2


def test_mixed_timestamp_awareness_is_ignored_as_time_context() -> None:
    aware = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
    naive = aware.replace(tzinfo=None)
    result = result_with(
        [
            DNSEvent(
                query_name="a.example",
                client_ip="192.0.2.1",
                timestamp=aware,
            ),
            DNSEvent(
                query_name="b.example",
                client_ip="192.0.2.1",
                timestamp=naive,
            ),
        ],
        [
            assessment("a.example", HybridVerdict.REVIEW),
            assessment("b.example", HybridVerdict.REVIEW),
        ],
    )

    relationship = find_related_activity(result).relationships[0]

    assert relationship.min_time_delta_seconds is None
    assert relationship.reasons == ("shared_client",)




def test_many_unrelated_candidates_do_not_create_relationships() -> None:
    events = [
        DNSEvent(
            query_name=f"domain-{index}.example",
            client_ip=f"192.0.2.{index + 1}",
        )
        for index in range(100)
    ]
    assessments = [
        assessment(f"domain-{index}.example", HybridVerdict.REVIEW)
        for index in range(100)
    ]

    report = find_related_activity(result_with(events, assessments))

    assert report.relationships == ()
    assert report.clusters == ()

def test_negative_time_window_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        find_related_activity(
            result_with([], []),
            time_proximity_seconds=-1,
        )


def test_campaign_analysis_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("campaign analysis must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    report = find_related_activity(
        result_with(
            [
                DNSEvent(
                    query_name="a.example",
                    client_ip="192.0.2.1",
                ),
                DNSEvent(
                    query_name="b.example",
                    client_ip="192.0.2.1",
                ),
            ],
            [
                assessment("a.example", HybridVerdict.REVIEW),
                assessment("b.example", HybridVerdict.REVIEW),
            ],
        )
    )

    assert report.clusters
