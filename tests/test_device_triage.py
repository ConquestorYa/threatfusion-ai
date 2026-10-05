from __future__ import annotations

import json
import os
import socket
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion import cli, runtime_analysis
from threatfusion.dashboard import device_finding_rows
from threatfusion.device_triage import build_device_findings
from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import HybridVerdict, MLThresholds
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_analysis_report, build_device_report
from threatfusion.runtime_analysis import analyze_dns_events


def periodic(*, client="192.0.2.1", count=20, interval=100, domain="service.test"):
    start = datetime(2026, 10, 4, tzinfo=timezone.utc)
    return [DNSEvent(
        domain, timestamp=start + timedelta(seconds=index * interval),
        client_ip=client, response_ip="198.51.100.1", response_code="NOERROR",
    ) for index in range(count)]


def test_sustained_periodicity_is_review_without_malware_escalation():
    result = analyze_dns_events(periodic(), [], None)
    finding = result.device_findings[0]
    assert finding.priority == "review"
    assert finding.assessment.verdict is HybridVerdict.LOW
    assert finding.reasons == ("periodic_query_pattern", "sustained_periodic_dns")
    assert finding.limitations == ()
    assert result.assessments[0].verdict is HybridVerdict.LOW


def test_short_capture_and_duplicates_do_not_prove_sustained_periodicity():
    short = analyze_dns_events(periodic(interval=2), [], None).device_findings[0]
    assert short.priority == "observe"
    assert "insufficient_observed_span" in short.limitations
    # Simulates repeated answer rows/A+AAAA at the same query timestamps.
    events = periodic(count=10, interval=300)
    duplicate = analyze_dns_events(events + [replace(e) for e in events], [], None)
    assert duplicate.device_findings[0].distinct_timestamps == 10
    assert duplicate.device_findings[0].priority == "observe"


def test_client_grouping_prevents_pooled_periodicity_from_creating_device_alert():
    events = periodic(count=10, interval=200, client="192.0.2.1")
    events += [replace(e, timestamp=e.timestamp + timedelta(seconds=100))
               for e in periodic(count=10, interval=200, client="192.0.2.2")]
    result = analyze_dns_events(events, [], None)
    assert result.assessments[0].behavior.periodic_query_pattern
    assert len(result.device_findings) == 2
    assert all(f.priority == "observe" for f in result.device_findings)


@pytest.mark.parametrize("change,limitation", [
    ({"timestamp": None}, "missing_timestamps"),
    ({"client_ip": None}, "missing_or_invalid_client_ip"),
    ({"client_ip": "not-an-ip"}, "missing_or_invalid_client_ip"),
])
def test_incomplete_metadata_limits_periodic_review(change, limitation):
    events = periodic()
    events = [replace(e, **change) for e in events] if "client_ip" in change else (
        [replace(events[0], **change)] + events[1:]
    )
    finding = analyze_dns_events(events, [], None).device_findings[0]
    assert finding.priority == "observe"
    assert limitation in finding.limitations


def test_naive_and_mixed_timezones_are_not_sufficient_coverage():
    for all_naive in (True, False):
        events = periodic()
        events = [replace(e, timestamp=e.timestamp.replace(tzinfo=None))
                  if all_naive or index == 0 else e
                  for index, e in enumerate(events)]
        finding = analyze_dns_events(events, [], None).device_findings[0]
        assert finding.priority == "observe"
        assert "ambiguous_timestamp_timezone" in finding.limitations


def test_cti_response_infrastructure_is_scoped_to_observed_client():
    events = [
        DNSEvent("shared.test", client_ip="192.0.2.1", response_ip="198.51.100.1"),
        DNSEvent("shared.test", client_ip="192.0.2.2", response_ip="198.51.100.2"),
    ]
    result = analyze_dns_events(
        events, [IOCRecord("198.51.100.1", IOCType.IPV4, "Synthetic-Lab")], None,
    )
    findings = {f.client_ip: f for f in result.device_findings}
    assert findings["192.0.2.1"].priority == "review"
    assert findings["192.0.2.1"].assessment.known_match_types == ("response_ip",)
    assert findings["192.0.2.2"].priority == "observe"
    assert findings["192.0.2.2"].assessment.known_ioc_sources == ()


def test_exact_cti_is_first_even_with_missing_timestamp_or_client():
    result = analyze_dns_events(
        [DNSEvent("ioc.test")], [IOCRecord("ioc.test", IOCType.DOMAIN, "Synthetic-Lab")], None,
    )
    finding = result.device_findings[0]
    assert finding.priority == "investigate"
    assert finding.assessment.verdict is HybridVerdict.KNOWN_THREAT
    assert "missing_or_invalid_client_ip" in finding.limitations


def test_connection_ip_targets_are_not_labeled_sustained_dns():
    result = analyze_dns_events(periodic(domain="198.51.100.2"), [], None)
    finding = result.device_findings[0]
    assert finding.priority == "observe"
    assert "sustained_periodic_dns" not in finding.reasons
    assert "ip_target_not_dns_query" in finding.limitations


def test_ipv6_identity_is_canonical_and_order_is_deterministic():
    events = periodic(client="2001:db8::1") + periodic(client="2001:0db8:0:0::1")
    result = analyze_dns_events(events, [], None)
    assert len(result.device_findings) == 1
    assert result.device_findings[0].client_ip == "2001:db8::1"
    assert result.device_findings == analyze_dns_events(reversed(events), [], None).device_findings


def test_device_processing_does_not_repeat_ml_inference_or_network(monkeypatch):
    from types import SimpleNamespace
    calls = []
    def predict(artifact, domains):
        calls.append(list(domains))
        return {"service.test": 0.9}
    def forbidden(*args, **kwargs):
        raise AssertionError("No network during local triage")
    monkeypatch.setattr(runtime_analysis, "predict_domain_scores", predict)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    artifact = SimpleNamespace(thresholds=MLThresholds(0.8, 0.6, 0.5))
    result = analyze_dns_events(periodic() + periodic(client="192.0.2.2"), [], artifact)
    assert len(calls) == 1
    assert all(f.assessment.ml_score == 0.9 for f in result.device_findings)


def test_default_device_report_uses_aliases_and_aggregate_export_stays_private():
    result = analyze_dns_events(periodic(), [], None)
    report = build_device_report(result)
    assert "192.0.2.1" not in report and "198.51.100.1" not in report
    payload = json.loads(report)
    assert payload["findings"][0]["Device"] == "Device 001"
    assert payload["privacy"]["client_ip_values_included"] is False
    assert "192.0.2.1" in build_device_report(result, include_client_ips=True)
    assert "198.51.100.1" not in build_device_report(result, include_client_ips=True)
    aggregate = build_analysis_report(result, model_name="cti_only_ml_disabled")
    assert "Device 001" not in aggregate.json_text
    assert "192.0.2.1" not in aggregate.json_text


def test_device_cli_requires_explicit_raw_export_and_refuses_overwrite(tmp_path, monkeypatch):
    input_path = tmp_path / "dns.csv"
    input_path.write_text("query_name,client_ip\nioc.test,192.0.2.1\n")
    monkeypatch.setattr(cli, "load_ioc_records", lambda path: [])
    output = tmp_path / "device.json"
    args = [str(input_path), "--cti-only", "--device-json-output", str(output)]
    assert cli.main(args) == 0
    assert "192.0.2.1" not in output.read_text()
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        cli.main(args)
    with pytest.raises(SystemExit):
        cli.main([str(input_path), "--include-client-ips"])
    raw = tmp_path / "raw.json"
    assert cli.main(args[:-1] + [str(raw), "--include-client-ips"]) == 0
    assert "192.0.2.1" in raw.read_text()


@pytest.mark.parametrize("public_mode", [True, False])
def test_device_ui_exercises_privacy_toggle_and_observe_filter(public_mode):
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from threatfusion.dns import DNSEvent\n"
        "from threatfusion.models import IOCRecord, IOCType\n"
        "from threatfusion.runtime_analysis import analyze_dns_events\n"
        "from threatfusion.ui_device_triage import render_device_triage\n"
        "result = analyze_dns_events([DNSEvent('ioc.test', client_ip='192.0.2.1'), "
        "DNSEvent('normal.test', client_ip='192.0.2.2')], "
        "[IOCRecord('ioc.test', IOCType.DOMAIN, 'Synthetic-Lab')], None)\n"
        f"render_device_triage(result, public_mode={public_mode!r})\n"
    ).run(timeout=15)
    assert not app.exception
    assert len(app.dataframe[0].value) == 1
    assert app.dataframe[0].value.iloc[0]["Device"] == "Device 001"
    ips = [c for c in app.checkbox if c.key == "device_triage_include_ips"]
    assert bool(ips) is not public_mode
    if ips:
        ips[0].check().run(timeout=15)
        assert app.dataframe[0].value.iloc[0]["Device"] == "192.0.2.1"
    app.checkbox(key="device_triage_include_observe").check().run(timeout=15)
    assert not app.exception
    assert len(app.dataframe[0].value) == 2
    if ips:
        app.checkbox(key="device_triage_include_ips").uncheck()
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["Cihaz"] == "Cihaz 001"
    assert "30 dakikadan kısa" in app.dataframe[0].value.iloc[0]["Veri sınırlamaları"]


def test_foreign_matches_are_not_assigned_to_unrelated_events():
    from threatfusion.matching import DNSIOCMatch
    foreign = DNSEvent("service.test", client_ip="192.0.2.1")
    match = DNSIOCMatch(foreign, IOCRecord("service.test", IOCType.DOMAIN, "Synthetic-Lab"), "query_domain")
    finding = build_device_findings(periodic(), [match])[0]
    assert finding.assessment.known_ioc_sources == ()
    assert device_finding_rows((finding,))[0]["Verdict"] == "Low"


def test_complete_dashboard_renders_device_tab_with_real_pipeline(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFUSION_CTI_ONLY", "1")
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "0")
    monkeypatch.setenv("THREATFUSION_DB_PATH", str(tmp_path / "cti.sqlite"))
    monkeypatch.setenv("THREATFUSION_EVALUATION_REPORT", str(tmp_path / "missing.json"))
    app = AppTest.from_string(
        "import streamlit as st\n"
        "from datetime import datetime, timedelta, timezone\n"
        "from threatfusion.dns import DNSEvent\n"
        "from threatfusion.runtime_analysis import analyze_dns_events\n"
        "events = [DNSEvent('service.test', client_ip='192.0.2.1', "
        "timestamp=datetime(2026, 10, 4, tzinfo=timezone.utc) + timedelta(seconds=i*300)) "
        "for i in range(24)]\n"
        "st.session_state['analysis_result'] = analyze_dns_events(events, [], None)\n"
        "import streamlit_app\nstreamlit_app.main()\n"
    ).run(timeout=15)
    assert not app.exception
    assert "Device triage" in [tab.label for tab in app.tabs]
    frames = [frame.value for frame in app.dataframe if "Queue priority" in frame.value.columns]
    assert len(frames) == 1
    assert frames[0].iloc[0]["Queue priority"] == "Review"
    assert frames[0].iloc[0]["Verdict"] == "Low"
    assert "192.0.2.1" not in frames[0].to_json()
