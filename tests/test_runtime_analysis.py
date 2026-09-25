from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from threatfusion import runtime_analysis
from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import HybridVerdict, MLThresholds
from threatfusion.models import IOCRecord, IOCType
from threatfusion.runtime_analysis import (
    MAX_DNS_EVENTS,
    analyze_dns_csv,
    analyze_dns_csv_with_diagnostics,
    analyze_dns_events,
    analyze_pihole_query_db_with_diagnostics,
    analyze_zeek_dns_log_with_diagnostics,
    is_ml_scoring_candidate,
)


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




def test_dns_csv_runtime_helper_returns_input_quality_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = (
        "timestamp,client_ip,query_name,query_type,response_ip\n"
        "bad-time,10.0.0.1,example.com,A,not-an-ip\n"
        "2026-09-24T10:00:00Z,10.0.0.2,,A,203.0.113.5\n"
    )
    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"example.com": 0.55},
    )

    result, diagnostics = analyze_dns_csv_with_diagnostics(
        content,
        [],
        fake_artifact(),
    )

    assert len(result.events) == 1
    assert diagnostics.total_rows == 2
    assert diagnostics.accepted_rows == 1
    assert diagnostics.skipped_missing_query_name == 1
    assert diagnostics.invalid_timestamps == 1
    assert diagnostics.invalid_response_ips == 1





def test_pihole_runtime_helper_parses_and_analyzes(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    path = tmp_path / "pihole-FTL.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE queries (
                id INTEGER PRIMARY KEY,
                timestamp INTEGER,
                type INTEGER,
                domain TEXT,
                client TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO queries VALUES (?, ?, ?, ?, ?)",
            (1, 1700000000, 1, "example.com", "10.0.0.5"),
        )

    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"example.com": 0.55},
    )

    result, diagnostics = analyze_pihole_query_db_with_diagnostics(
        path.read_bytes(),
        [],
        fake_artifact(),
    )

    assert len(result.events) == 1
    assert result.events[0].client_ip == "10.0.0.5"
    assert result.events[0].query_type == "A"
    assert result.events[0].response_ip is None
    assert result.assessments[0].verdict is HybridVerdict.REVIEW
    assert diagnostics.accepted_rows == 1

def test_zeek_runtime_helper_parses_and_analyzes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = (
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tquery\tqtype_name\tanswers\n"
        "1700000000.0\t10.0.0.5\texample.com\tA\t203.0.113.7\n"
    )
    monkeypatch.setattr(
        runtime_analysis,
        "predict_domain_probabilities",
        lambda artifact, domains: {"example.com": 0.55},
    )

    result, diagnostics = analyze_zeek_dns_log_with_diagnostics(
        content,
        [],
        fake_artifact(),
    )

    assert len(result.events) == 1
    assert result.events[0].client_ip == "10.0.0.5"
    assert result.events[0].response_ip == "203.0.113.7"
    assert result.assessments[0].verdict is HybridVerdict.REVIEW
    assert diagnostics.accepted_rows == 1

def test_response_ip_ioc_match_is_contextual_review(
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
    assert assessment.verdict is HybridVerdict.REVIEW
    assert assessment.known_match_types == ("response_ip",)
    assert assessment.reasons == ("response_ip_ioc_context",)


def test_ml_scoring_skips_reverse_local_and_single_label_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = [
        DNSEvent(query_name="example.com"),
        DNSEvent(query_name="1.0.0.127.in-addr.arpa"),
        DNSEvent(query_name="printer.local"),
        DNSEvent(query_name="internalhost"),
    ]
    captured: list[list[str]] = []

    def predict(artifact, domains):
        values = list(domains)
        captured.append(values)
        return {"example.com": 0.55}

    monkeypatch.setattr(runtime_analysis, "predict_domain_probabilities", predict)

    result = analyze_dns_events(events, [], fake_artifact())

    assert captured == [["example.com"]]
    assert result.ml_probabilities == {"example.com": 0.55}
    by_domain = {item.domain: item for item in result.assessments}
    assert by_domain["1.0.0.127.in-addr.arpa"].ml_probability is None
    assert by_domain["printer.local"].ml_probability is None
    assert by_domain["internalhost"].ml_probability is None


def test_ml_scoring_candidate_rules_are_explicit() -> None:
    assert is_ml_scoring_candidate("example.com")
    assert not is_ml_scoring_candidate("localhost")
    assert not is_ml_scoring_candidate("host.local")
    assert not is_ml_scoring_candidate("1.0.0.127.in-addr.arpa")
    assert not is_ml_scoring_candidate("singlelabel")


def test_runtime_rejects_excessive_event_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_analysis, "MAX_DNS_EVENTS", 2)

    with pytest.raises(ValueError, match="event analysis limit"):
        analyze_dns_events(
            [
                DNSEvent(query_name="one.example"),
                DNSEvent(query_name="two.example"),
                DNSEvent(query_name="three.example"),
            ],
            [],
            fake_artifact(),
        )

    assert MAX_DNS_EVENTS >= 2


def test_runtime_rejects_excessive_unique_query_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runtime_analysis, "MAX_UNIQUE_QUERY_NAMES", 2)

    with pytest.raises(ValueError, match="unique-query analysis limit"):
        analyze_dns_events(
            [
                DNSEvent(query_name="one.example"),
                DNSEvent(query_name="two.example"),
                DNSEvent(query_name="three.example"),
            ],
            [],
            fake_artifact(),
        )


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
