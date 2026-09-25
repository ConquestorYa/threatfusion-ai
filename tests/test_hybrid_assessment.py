import socket
from datetime import datetime, timedelta, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import (
    BehaviorHeuristicConfig,
    HybridVerdict,
    MLThresholds,
    assess_dns_domains,
)
from threatfusion.matching import DNSIOCMatch
from threatfusion.models import IOCRecord, IOCType


def thresholds() -> MLThresholds:
    return MLThresholds(
        high_confidence=0.80,
        medium_confidence=0.60,
        low_confidence=0.50,
    )


def test_known_ioc_match_takes_precedence() -> None:
    event = DNSEvent(query_name="Known.Bad.")
    indicator = IOCRecord("known.bad", IOCType.DOMAIN, "ThreatFox")
    match = DNSIOCMatch(event=event, indicator=indicator, match_type="query_domain")

    assessment = assess_dns_domains(
        [event],
        [match],
        ml_probabilities={"known.bad": 0.10},
        ml_thresholds=thresholds(),
    )[0]

    assert assessment.verdict is HybridVerdict.KNOWN_THREAT
    assert assessment.known_ioc_sources == ("ThreatFox",)
    assert assessment.known_match_types == ("query_domain",)
    assert "known_ioc_match" in assessment.reasons




def test_url_hostname_ioc_is_contextual_review_not_known_threat() -> None:
    event = DNSEvent(query_name="shared-host.example")
    indicator = IOCRecord(
        "https://shared-host.example/malware.exe",
        IOCType.URL,
        "URLhaus",
    )
    match = DNSIOCMatch(
        event=event,
        indicator=indicator,
        match_type="url_hostname",
    )

    assessment = assess_dns_domains([event], [match])[0]

    assert assessment.verdict is HybridVerdict.REVIEW
    assert assessment.known_ioc_sources == ("URLhaus",)
    assert assessment.known_match_types == ("url_hostname",)
    assert assessment.reasons == ("url_hostname_ioc_context",)


def test_response_ip_ioc_is_contextual_review_not_known_threat() -> None:
    event = DNSEvent(
        query_name="shared-service.example",
        response_ip="203.0.113.10",
    )
    indicator = IOCRecord("203.0.113.10", IOCType.IPV4, "ThreatFox")
    match = DNSIOCMatch(
        event=event,
        indicator=indicator,
        match_type="response_ip",
    )

    assessment = assess_dns_domains([event], [match])[0]

    assert assessment.verdict is HybridVerdict.REVIEW
    assert assessment.reasons == ("response_ip_ioc_context",)


def test_contextual_ioc_plus_high_ml_can_be_high_risk() -> None:
    event = DNSEvent(query_name="suspicious.example")
    indicator = IOCRecord(
        "https://suspicious.example/payload",
        IOCType.URL,
        "URLhaus",
    )
    match = DNSIOCMatch(event=event, indicator=indicator, match_type="url_hostname")

    assessment = assess_dns_domains(
        [event],
        [match],
        ml_probabilities={"suspicious.example": 0.90},
        ml_thresholds=thresholds(),
    )[0]

    assert assessment.verdict is HybridVerdict.HIGH_RISK
    assert assessment.reasons == (
        "url_hostname_ioc_context",
        "ml_high_confidence",
    )

def test_high_confidence_ml_signal_is_high_risk() -> None:
    event = DNSEvent(query_name="unknown.example")

    assessment = assess_dns_domains(
        [event],
        [],
        ml_probabilities={"UNKNOWN.EXAMPLE.": 0.85},
        ml_thresholds=thresholds(),
    )[0]

    assert assessment.verdict is HybridVerdict.HIGH_RISK
    assert assessment.ml_tier == "high"
    assert assessment.ml_probability == pytest.approx(0.85)


def test_medium_ml_plus_two_behavior_signals_is_high_risk() -> None:
    events = [
        DNSEvent(
            query_name="unknown.example",
            client_ip=f"10.0.0.{index % 4 + 1}",
            response_ip=f"203.0.113.{index % 4 + 1}",
        )
        for index in range(4)
    ]

    assessment = assess_dns_domains(
        events,
        [],
        ml_probabilities={"unknown.example": 0.65},
        ml_thresholds=thresholds(),
        behavior_config=BehaviorHeuristicConfig(
            high_query_count=100,
            multi_client_count=3,
            response_ip_churn_count=3,
            query_type_diversity_count=10,
            burst_query_count=100,
        ),
    )[0]

    assert assessment.verdict is HybridVerdict.HIGH_RISK
    assert assessment.ml_tier == "medium"
    assert set(assessment.behavior_signals) == {
        "multi_client_observation",
        "response_ip_churn",
    }


def test_low_ml_signal_requires_review() -> None:
    event = DNSEvent(query_name="unknown.example")

    assessment = assess_dns_domains(
        [event],
        [],
        ml_probabilities={"unknown.example": 0.55},
        ml_thresholds=thresholds(),
    )[0]

    assert assessment.verdict is HybridVerdict.REVIEW
    assert assessment.ml_tier == "low"


def test_behavior_alone_can_trigger_review_but_not_known_threat() -> None:
    events = [
        DNSEvent(
            query_name="busy.example",
            client_ip=f"10.0.0.{index % 3 + 1}",
            query_type=("A", "AAAA", "TXT")[index % 3],
        )
        for index in range(6)
    ]

    assessment = assess_dns_domains(
        events,
        [],
        behavior_config=BehaviorHeuristicConfig(
            high_query_count=100,
            multi_client_count=3,
            response_ip_churn_count=100,
            query_type_diversity_count=3,
            burst_query_count=100,
        ),
    )[0]

    assert assessment.verdict is HybridVerdict.REVIEW
    assert set(assessment.behavior_signals) == {
        "multi_client_observation",
        "query_type_diversity",
    }


def test_rapid_query_burst_is_explainable_signal() -> None:
    start = datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc)
    events = [
        DNSEvent(
            query_name="burst.example",
            timestamp=start + timedelta(seconds=index),
        )
        for index in range(20)
    ]

    assessment = assess_dns_domains(
        events,
        [],
        behavior_config=BehaviorHeuristicConfig(
            high_query_count=100,
            multi_client_count=100,
            response_ip_churn_count=100,
            query_type_diversity_count=100,
            burst_query_count=20,
            burst_span_seconds=60,
        ),
    )[0]

    assert assessment.behavior_signals == ("rapid_query_burst",)
    assert assessment.verdict is HybridVerdict.LOW


def test_no_evidence_is_low_risk() -> None:
    assessment = assess_dns_domains(
        [DNSEvent(query_name="quiet.example")],
        [],
    )[0]

    assert assessment.verdict is HybridVerdict.LOW
    assert assessment.reasons == ()


def test_probabilities_and_thresholds_must_be_supplied_together() -> None:
    with pytest.raises(ValueError, match="supplied together"):
        assess_dns_domains(
            [DNSEvent(query_name="example.com")],
            [],
            ml_probabilities={"example.com": 0.9},
        )


def test_invalid_probability_is_rejected() -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        assess_dns_domains(
            [DNSEvent(query_name="example.com")],
            [],
            ml_probabilities={"example.com": 1.5},
            ml_thresholds=thresholds(),
        )


def test_invalid_threshold_order_is_rejected() -> None:
    with pytest.raises(ValueError, match="high"):
        MLThresholds(
            high_confidence=0.50,
            medium_confidence=0.70,
            low_confidence=0.40,
        )


def test_hybrid_assessment_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("hybrid assessment must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    assessment = assess_dns_domains(
        [DNSEvent(query_name="Example.COM.")],
        [],
        ml_probabilities={"example.com": 0.85},
        ml_thresholds=thresholds(),
    )[0]

    assert assessment.verdict is HybridVerdict.HIGH_RISK
