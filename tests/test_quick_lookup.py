from __future__ import annotations

import socket
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from threatfusion import quick_lookup
from threatfusion.cti_cache import replace_source_records
from threatfusion.hybrid_assessment import HybridVerdict, MLThresholds
from threatfusion.models import IOCRecord, IOCType
from threatfusion.quick_lookup import analyze_quick_lookup, analyze_quick_lookup_from_cache


def fake_artifact():
    return SimpleNamespace(
        thresholds=MLThresholds(
            high_confidence=0.80,
            medium_confidence=0.60,
            low_confidence=0.50,
        )
    )


def test_domain_lookup_uses_exact_domain_cti(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"evil.example": 0.10},
    )
    indicator = IOCRecord("evil.example", IOCType.DOMAIN, "ThreatFox")

    result = analyze_quick_lookup("Evil.Example.", [indicator], fake_artifact())

    assert result.input_type == "Domain"
    assert result.normalized_domain == "evil.example"
    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert [item.match_type for item in result.evidence] == ["query_domain"]


def test_url_lookup_detects_exact_url_without_duplicate_hostname_match(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"evil.example": 0.10},
    )
    indicator = IOCRecord(
        "https://evil.example/payload",
        IOCType.URL,
        "URLhaus",
        first_seen=datetime(2026, 9, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 25, tzinfo=timezone.utc),
        threat_type="malware_download",
    )

    result = analyze_quick_lookup(
        "HTTPS://EVIL.EXAMPLE:443/payload#ignored",
        [indicator],
        fake_artifact(),
    )

    assert result.input_type == "URL"
    assert result.normalized_url == "https://evil.example/payload"
    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert [item.match_type for item in result.evidence] == ["exact_url"]
    assert result.evidence[0].first_seen == datetime(
        2026, 9, 1, tzinfo=timezone.utc
    )
    assert result.evidence[0].last_seen == datetime(
        2026, 9, 25, tzinfo=timezone.utc
    )


def test_url_hostname_context_is_review_not_known_threat(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"evil.example": 0.10},
    )
    indicator = IOCRecord(
        "https://evil.example/known-payload",
        IOCType.URL,
        "URLhaus",
    )

    result = analyze_quick_lookup(
        "https://evil.example/different-path",
        [indicator],
        fake_artifact(),
    )

    assert result.verdict is HybridVerdict.REVIEW
    assert [item.match_type for item in result.evidence] == ["url_hostname"]


def test_exact_ipv4_ioc_is_known_threat_without_domain_ml(monkeypatch):
    def fail_ml(*args, **kwargs):
        raise AssertionError("IP literals must not be scored by the domain model")

    monkeypatch.setattr(quick_lookup, "predict_domain_scores", fail_ml)
    indicator = IOCRecord(
        "143.20.185.213",
        IOCType.IPV4,
        "ThreatFox",
        threat_type="botnet_cc",
    )

    result = analyze_quick_lookup("143.20.185.213", [indicator], fake_artifact())

    assert result.input_type == "IPv4"
    assert result.normalized_ip == "143.20.185.213"
    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert result.ml_score is None
    assert [item.match_type for item in result.evidence] == ["exact_ip"]
    assert "exact_ip_ioc_match" in result.reasons


def test_ip_hosted_exact_url_is_known_threat(monkeypatch):
    def fail_ml(*args, **kwargs):
        raise AssertionError("IP-hosted URLs must not be scored by the domain model")

    monkeypatch.setattr(quick_lookup, "predict_domain_scores", fail_ml)
    indicator = IOCRecord(
        "http://143.20.185.213/armv7",
        IOCType.URL,
        "URLhaus",
        threat_type="malware_download",
    )

    result = analyze_quick_lookup(
        "http://143.20.185.213/armv7",
        [indicator],
        fake_artifact(),
    )

    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert result.uses_public_ip_literal is True
    assert [item.match_type for item in result.evidence] == ["exact_url"]
    assert "public_ip_literal_url" in result.reasons


def test_public_ip_literal_url_is_context_only_without_cti(monkeypatch):
    def fail_ml(*args, **kwargs):
        raise AssertionError("IP-hosted URLs must not be scored by the domain model")

    monkeypatch.setattr(quick_lookup, "predict_domain_scores", fail_ml)

    result = analyze_quick_lookup(
        "http://8.8.8.8/example",
        [],
        fake_artifact(),
    )

    assert result.uses_public_ip_literal is True
    assert "public_ip_literal_url" in result.reasons
    assert result.verdict is HybridVerdict.LOW


def test_private_ip_literal_url_is_not_public_ip_signal(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {},
    )

    result = analyze_quick_lookup(
        "http://192.168.1.10/admin",
        [],
        fake_artifact(),
    )

    assert result.normalized_ip == "192.168.1.10"
    assert result.uses_public_ip_literal is False
    assert "public_ip_literal_url" not in result.reasons


def test_plain_http_url_is_flagged_without_changing_verdict(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"example.com": 0.10},
    )

    result = analyze_quick_lookup(
        "http://example.com/login",
        [],
        fake_artifact(),
    )

    assert result.uses_plain_http is True
    assert "plaintext_http_transport" in result.reasons
    assert result.verdict is HybridVerdict.LOW


def test_https_url_is_not_flagged_as_plain_http(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"example.com": 0.10},
    )

    result = analyze_quick_lookup(
        "https://example.com/login",
        [],
        fake_artifact(),
    )

    assert result.uses_plain_http is False
    assert "plaintext_http_transport" not in result.reasons


def test_high_ml_score_can_raise_high_risk_without_cti(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"unknown.example": 0.91},
    )

    result = analyze_quick_lookup("unknown.example", [], fake_artifact())

    assert result.verdict is HybridVerdict.HIGH_RISK
    assert result.ml_tier == "high"
    assert result.ml_score == pytest.approx(0.91)


def test_domain_shape_is_context_only_when_ml_and_cti_are_low(monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"123456789012.example": 0.10},
    )

    result = analyze_quick_lookup("123456789012.example", [], fake_artifact())

    assert result.lexical_context.numeric_character_ratio is not None
    assert result.lexical_context.numeric_character_ratio >= 0.3
    assert "numeric_heavy_hostname" in result.reasons
    assert result.verdict is HybridVerdict.LOW


@pytest.mark.parametrize(
    "value",
    [
        "",
        "localhost",
        "not a valid domain",
        "ftp://example.com/file",
        "https://user:pass@example.com/",
        "http://[::1",
    ],
)
def test_invalid_or_unsupported_lookup_input_is_rejected(value, monkeypatch):
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {},
    )

    with pytest.raises(ValueError):
        analyze_quick_lookup(value, [], fake_artifact())


def test_quick_lookup_from_cache_matches_exact_ip_and_ip_url(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("143.20.185.213", IOCType.IPV4, "ThreatFox")],
    )
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "http://143.20.185.213/armv7",
                IOCType.URL,
                "URLhaus",
            )
        ],
    )

    def fail_ml(*args, **kwargs):
        raise AssertionError("IP-hosted URLs must not use domain ML")

    monkeypatch.setattr(quick_lookup, "predict_domain_scores", fail_ml)

    result = analyze_quick_lookup_from_cache(
        "http://143.20.185.213/armv7",
        db_path,
        fake_artifact(),
    )

    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert {item.match_type for item in result.evidence} == {
        "exact_ip",
        "exact_url",
    }


def test_quick_lookup_from_cache_uses_indexed_candidates(tmp_path, monkeypatch):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "ThreatFox",
        [
            IOCRecord("target.example", IOCType.DOMAIN, "ThreatFox"),
            IOCRecord("unrelated.example", IOCType.DOMAIN, "ThreatFox"),
        ],
    )
    replace_source_records(
        db_path,
        "URLhaus",
        [
            IOCRecord(
                "https://target.example/payload",
                IOCType.URL,
                "URLhaus",
            ),
            IOCRecord(
                "https://other.example/payload",
                IOCType.URL,
                "URLhaus",
            ),
        ],
    )
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"target.example": 0.10},
    )

    result = analyze_quick_lookup_from_cache(
        "https://target.example/payload",
        db_path,
        fake_artifact(),
    )

    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert {item.indicator_value for item in result.evidence} == {
        "target.example",
        "https://target.example/payload",
    }


def test_quick_lookup_never_performs_networking(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("quick lookup must remain passive")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    monkeypatch.setattr(
        quick_lookup,
        "predict_domain_scores",
        lambda artifact, domains: {"example.com": 0.10},
    )

    result = analyze_quick_lookup(
        "https://example.com/path",
        [IOCRecord("example.com", IOCType.DOMAIN, "SGB")],
        fake_artifact(),
    )

    assert result.verdict is HybridVerdict.KNOWN_THREAT
