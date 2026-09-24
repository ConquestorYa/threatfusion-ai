from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

import threatfusion.runtime_analysis as runtime_analysis
from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import HybridVerdict, MLThresholds
from threatfusion.models import IOCRecord, IOCType
from threatfusion.runtime_analysis import analyze_dns_csv, analyze_dns_events


def fake_artifact():
    return SimpleNamespace(
        thresholds=MLThresholds(
            high_confidence=0.80,
            medium_confidence=0.60,
            low_confidence=0.50,
        )
    )


def test_runtime_pipeline_preserves_events_and_known_ioc_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = DNSEvent(query_name="Known.Bad.")
    indicator = IOCRecord("known.bad", IOCType.DOMAIN, "ThreatFox")

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"known.bad": 0.10},
    )

    result = analyze_dns_events([event], [indicator], fake_artifact())

    assert result.events == (event,)
    assert len(result.matches) == 1
    assert result.matches[0].event is event
    assert result.matches[0].indicator is indicator
    assert result.assessments[0].verdict is HybridVerdict.KNOWN_THREAT
    assert result.assessments[0].known_ioc_sources == ("ThreatFox",)


def test_runtime_pipeline_uses_artifact_thresholds_for_ml_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = DNSEvent(query_name="unknown.example")

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"unknown.example": 0.85},
    )

    result = analyze_dns_events([event], [], fake_artifact())

    assessment = result.assessments[0]
    assert assessment.verdict is HybridVerdict.HIGH_RISK
    assert assessment.ml_tier == "high"
    assert assessment.ml_probability == pytest.approx(0.85)


def test_runtime_pipeline_passes_unique_normalized_probabilities_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        DNSEvent(query_name="Example.COM."),
        DNSEvent(query_name="example.com"),
    ]
    captured: list[list[str]] = []

    def predict(artifact, domains):
        values = list(domains)
        captured.append(values)
        return {"example.com": 0.55}

    monkeypatch.setattr(runtime_analysis, "predict_domain_probabilities", predict)

    result = analyze_dns_events(events, [], fake_artifact())

    assert captured == [["Example.COM.", "example.com"]]
    assert result.ml_probabilities == {"example.com": 0.55}
    assert len(result.assessments) == 1
    assert result.assessments[0].domain == "example.com"


def test_invalid_domain_can_remain_dns_evidence_without_ml_probability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = DNSEvent(query_name="not a valid domain")

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {},
    )

    result = analyze_dns_events([event], [], fake_artifact())

    assert result.events == (event,)
    assert result.ml_probabilities == {}
    assert len(result.assessments) == 1
    assert result.assessments[0].ml_probability is None


def test_runtime_supports_generator_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        DNSEvent(query_name="one.example"),
        DNSEvent(query_name="two.example"),
    ]
    indicators = [
        IOCRecord("one.example", IOCType.DOMAIN, "SGB"),
    ]

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {
            "one.example": 0.20,
            "two.example": 0.20,
        },
    )

    result = analyze_dns_events(
        (event for event in events),
        (indicator for indicator in indicators),
        fake_artifact(),
    )

    assert len(result.events) == 2
    assert len(result.matches) == 1
    assert len(result.assessments) == 2


def test_dns_csv_convenience_helper_parses_and_analyzes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "2026-09-24T10:00:00Z,10.0.0.1,example.com,A,203.0.113.5\n"
    )

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"example.com": 0.55},
    )

    result = analyze_dns_csv(content, [], fake_artifact())

    assert len(result.events) == 1
    assert result.events[0].client_ip == "10.0.0.1"
    assert result.assessments[0].verdict is HybridVerdict.REVIEW


def test_response_ip_ioc_match_keeps_known_threat_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = DNSEvent(
        query_name="apparently-benign.example",
        response_ip="203.0.113.7",
    )
    indicator = IOCRecord("203.0.113.7", IOCType.IPV4, "ThreatFox")

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"apparently-benign.example": 0.10},
    )

    result = analyze_dns_events([event], [indicator], fake_artifact())

    assessment = result.assessments[0]
    assert assessment.verdict is HybridVerdict.KNOWN_THREAT
    assert assessment.known_match_types == ("response_ip",)


def test_runtime_analysis_does_not_perform_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("runtime analysis must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"example.com": 0.10},
    )

    result = analyze_dns_events(
        [DNSEvent(query_name="example.com")],
        [IOCRecord("example.com", IOCType.DOMAIN, "ThreatFox")],
        fake_artifact(),
    )

    assert result.assessments[0].verdict is HybridVerdict.KNOWN_THREAT
