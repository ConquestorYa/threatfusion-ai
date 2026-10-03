from __future__ import annotations

import json
import socket

import pytest

from threatfusion import cli, runtime_analysis, quick_lookup
from threatfusion.app_config import load_app_config
from threatfusion.cti_cache import replace_source_records
from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import HybridVerdict
from threatfusion.models import IOCRecord, IOCType


def test_cti_only_config_is_explicit_and_does_not_require_model_pin():
    assert load_app_config({}).cti_only is False
    config = load_app_config(
        {"THREATFUSION_CTI_ONLY": "1", "THREATFUSION_PUBLIC_MODE": "1"}
    )
    assert config.cti_only
    assert config.model_sha256 is None
    assert not config.history_enabled
    assert not load_app_config({"THREATFUSION_CTI_ONLY": "1"}).history_enabled
    with pytest.raises(ValueError, match="boolean"):
        load_app_config({"THREATFUSION_CTI_ONLY": "maybe"})


def test_cti_only_runtime_preserves_cti_without_loading_or_scoring_model(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError(
            "CTI-only analysis must not score a model or use networking"
        )

    monkeypatch.setattr(runtime_analysis, "predict_domain_scores", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = runtime_analysis.analyze_dns_events(
        [DNSEvent(query_name="Known.Example."), DNSEvent(query_name="unseen.example")],
        [IOCRecord("known.example", IOCType.DOMAIN, "ThreatFox")],
        None,
    )
    assert result.ml_scores == {}
    assessments = {item.domain: item for item in result.assessments}
    assert assessments["known.example"].verdict is HybridVerdict.KNOWN_THREAT
    assert assessments["unseen.example"].verdict is HybridVerdict.LOW
    assert all(
        item.ml_score is None and item.ml_tier is None for item in result.assessments
    )


@pytest.mark.parametrize("target", ["known.example", "https://known.example/payload"])
def test_cti_only_lookup_keeps_deterministic_evidence(monkeypatch, target):
    def forbidden(*args, **kwargs):
        raise AssertionError("CTI-only lookup must not score a model")

    monkeypatch.setattr(quick_lookup, "predict_domain_scores", forbidden)
    result = quick_lookup.analyze_quick_lookup(
        target,
        [IOCRecord("known.example", IOCType.DOMAIN, "ThreatFox")],
        None,
    )
    assert result.verdict is HybridVerdict.KNOWN_THREAT
    assert result.ml_score is None and result.ml_tier is None
    assert result.evidence[0].source == "ThreatFox"


def test_cli_cti_only_works_with_missing_model_and_private_inputs(
    tmp_path, monkeypatch, capsys
):
    def forbidden(*args, **kwargs):
        raise AssertionError("CTI-only CLI must not load a pickle artifact")

    monkeypatch.setattr(cli, "load_trusted_ml_artifact", forbidden)
    db = tmp_path / "cache.sqlite"
    replace_source_records(
        db, "ThreatFox", [IOCRecord("known.example", IOCType.DOMAIN, "ThreatFox")]
    )
    telemetry = tmp_path / "dns.csv"
    telemetry.write_text(
        "query_name,client_ip,response_ip\nknown.example,192.0.2.1,203.0.113.1\n"
    )
    report = tmp_path / "report.json"
    assert (
        cli.main(
            [
                str(telemetry),
                "--cti-only",
                "--model-dir",
                str(tmp_path / "missing"),
                "--db",
                str(db),
                "--json-output",
                str(report),
            ]
        )
        == 0
    )
    payload = json.loads(report.read_text())
    assert payload["model_name"] == "cti_only_ml_disabled"
    assert payload["findings"][0]["verdict"] == "Known Threat"
    assert payload["findings"][0]["ml_score"] is None
    assert "192.0.2.1" not in report.read_text()
    assert "203.0.113.1" not in report.read_text()
    stdout = capsys.readouterr().out
    assert "ML disabled" in stdout
    assert "known.example" not in stdout
