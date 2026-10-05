from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion import cli, ui_connections
from threatfusion.expected_connections import MAX_RULE_BYTES, connection_contexts, parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_analysis_report, build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics

NOW = datetime(2026, 10, 4, 18, tzinfo=timezone.utc)


def rule(now=NOW, **changes):
    return dict(id="private-software-reference", originator_ip="192.0.2.1",
                responder_ip="198.51.100.1", responder_port=443, protocol="tcp",
                valid_from=(now - timedelta(days=1)).isoformat(),
                valid_until=(now + timedelta(days=1)).isoformat(),
                max_connections=100, max_duration_seconds=7200,
                max_originator_bytes=10000, max_responder_bytes=10000) | changes


def config(*rules):
    return json.dumps({"schema_version": 1, "rules": list(rules)}).encode()


def telemetry(now=NOW, *, source="192.0.2.1", target="198.51.100.1", **changes):
    row = dict(ts=int((now - timedelta(hours=3)).timestamp()), uid="C1",
               **{"id.orig_h": source, "id.orig_p": 50000, "id.resp_h": target,
                  "id.resp_p": 443}, proto="tcp", duration=4000, orig_bytes=100,
               resp_bytes=200, conn_state="SF", missed_bytes=0) | changes
    return "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(row) + "\n" + "\t".join(map(str, row.values())) + "\n"


def result(**changes):
    return analyze_zeek_conn_log_with_diagnostics(telemetry(**changes), [], None)[0]


def test_expected_context_preserves_all_detection_evidence_and_export_privacy():
    original = result()
    frozen = build_analysis_report(original, model_name="cti-only", generated_at=NOW)
    rules = parse_expected_connections(config(rule()))
    context, = connection_contexts(original, rules, evaluated_at=NOW)
    assert context.expected and context.status == "declared_expected"
    assert original.connection_findings[0].priority == "review"
    assert original.connection_findings[0].reasons == ("long_bidirectional_tcp_session",)
    assert build_analysis_report(original, model_name="cti-only", generated_at=NOW) == frozen
    report = build_connection_report(original, expected_rules=rules, evaluated_at=NOW)
    for private in ("192.0.2.1", "198.51.100.1", rule()["id"], "valid_until", "C1"):
        assert private not in report
    payload = json.loads(report)
    assert payload["schema_version"] == 2
    assert payload["findings"][0]["Queue priority"] == "Review"
    assert payload["findings"][0]["Declared expected"]


@pytest.mark.parametrize("changes", [
    {"originator_ip": "192.0.2.2"}, {"responder_ip": "198.51.100.2"},
    {"responder_port": 8443}, {"max_connections": 1, "max_duration_seconds": 3999},
    {"max_originator_bytes": 99}, {"max_responder_bytes": 199},
    {"valid_until": NOW.isoformat()},
    {"valid_from": (NOW - timedelta(hours=2)).isoformat()},
])
def test_mismatched_expired_or_exceeded_declarations_never_remove_review(changes):
    context, = connection_contexts(result(), parse_expected_connections(config(rule(**changes))), evaluated_at=NOW)
    assert not context.expected and context.status == "review"


@pytest.mark.parametrize("changes", [{"ts": "-"}, {"orig_bytes": "-"},
                                         {"id.orig_p": "-"}, {"missed_bytes": 1},
                                         {"ts": int(NOW.timestamp())}])
def test_incomplete_or_future_evidence_cannot_be_declared_expected(changes):
    context, = connection_contexts(result(**changes), parse_expected_connections(config(rule())), evaluated_at=NOW)
    assert not context.expected


@pytest.mark.parametrize("changes", [
    {"originator_ip": "192.0.2.0/24"}, {"responder_ip": "*"}, {"protocol": "udp"},
    {"id": "contains spaces"}, {"responder_port": True}, {"max_connections": 0},
    {"max_originator_bytes": -1}, {"max_duration_seconds": float("nan")},
    {"max_duration_seconds": 10**400}, {"extra": "ignored?"},
    {"valid_from": "2026-10-03T00:00:00"}, {"valid_until": "2026-12-01T00:00:00Z"},
    {"valid_from": "0001-01-01T00:00:00+14:00"},
])
def test_rule_validation_rejects_broad_ambiguous_or_unbounded_inputs(changes):
    with pytest.raises(ValueError):
        parse_expected_connections(config(rule(**changes)))


def test_extreme_valid_dates_do_not_overflow_rule_validation():
    assert len(parse_expected_connections(config(rule(valid_from="9999-12-30T00:00:00Z",
                                                       valid_until="9999-12-31T00:00:00Z")))) == 1


def test_json_bounds_duplicate_keys_and_duplicate_ids_are_rejected():
    for content in (b" " * (MAX_RULE_BYTES + 1), b'{"schema_version":1,"schema_version":1,"rules":[]}',
                    config(rule(), rule()), config(*(rule(id=f"rule-{i}") for i in range(129))),
                    b'{"schema_version":true,"rules":[]}', b'[' * 1500, b'\xff'):
        with pytest.raises(ValueError):
            parse_expected_connections(content)


@pytest.mark.parametrize("target,indicator", [
    ("198.51.100.1", IOCRecord("198.51.100.1", IOCType.IPV4, "synthetic")),
    ("2001:db8::1", IOCRecord("2001:db8::/32", IOCType.IPV6_NETWORK, "synthetic")),
])
def test_exact_and_network_cti_override_declarations_even_for_observe(target, indicator):
    original, _ = analyze_zeek_conn_log_with_diagnostics(telemetry(target=target, duration=1), [indicator], None)
    context, = connection_contexts(original, parse_expected_connections(config(rule(responder_ip=target))), evaluated_at=NOW)
    assert context.cti_matched and not context.expected and context.status == "cti_conflict"
    assert context.matched_rule_ids
    assert original.connection_findings[0].priority == "observe"
    other_client = replace(original.connection_findings[0], originator_ip="192.0.2.2")
    context, = connection_contexts(replace(original, connection_findings=(other_client,)), evaluated_at=NOW)
    assert not context.cti_matched


def test_time_and_count_bounds_fail_closed():
    rules = parse_expected_connections(config(rule(max_connections=1)))
    original = result()
    finding = replace(original.connection_findings[0], connection_count=2, confirmed_session_count=2)
    assert not connection_contexts(replace(original, connection_findings=(finding,)), rules, evaluated_at=NOW)[0].expected
    with pytest.raises(ValueError):
        connection_contexts(original, rules, evaluated_at=NOW.replace(tzinfo=None))


def test_unattributed_client_keeps_destination_cti_visible():
    original, _ = analyze_zeek_conn_log_with_diagnostics(
        telemetry(source="-", duration=1), [IOCRecord("198.51.100.1", IOCType.IPV4, "synthetic")], None,
    )
    context, = connection_contexts(original, evaluated_at=NOW)
    assert context.cti_matched and context.status == "cti_conflict" and not context.expected


def test_cli_context_is_explicit_private_and_invalid_files_write_nothing(tmp_path, monkeypatch, capsys):
    now = datetime.now(timezone.utc)
    source = tmp_path / "conn.log"
    source.write_text(telemetry(now))
    declarations = tmp_path / "expected-connections.json"
    declarations.write_bytes(config(rule(now)))
    output = tmp_path / "review.json"
    monkeypatch.setattr(cli, "load_ioc_records", lambda path: [])
    args = [str(source), "--format", "zeek-conn", "--cti-only", "--expected-connections", str(declarations),
            "--connection-json-output", str(output)]
    assert cli.main(args) == 0
    assert json.loads(output.read_text())["findings"][0]["Declared expected"]
    assert "Declared expected groups: 1" in capsys.readouterr().out
    output.unlink()
    declarations.write_bytes(b'{"private": "must not appear in errors"}')
    with pytest.raises(SystemExit):
        cli.main(args)
    assert not output.exists()
    assert "must not appear" not in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main([str(source), "--expected-connections", str(declarations)])


@pytest.mark.parametrize("public_mode", [False, True])
def test_ui_expected_filter_cti_visibility_and_public_boundary(monkeypatch, public_mode):
    now = datetime.now(timezone.utc)
    payload = config(rule(now))
    uploader_calls = []
    def upload(*args, **kwargs):
        uploader_calls.append(kwargs["key"])
        return SimpleNamespace(size=len(payload), getvalue=lambda: payload)
    monkeypatch.setattr(ui_connections.st, "file_uploader", upload)
    text = telemetry(now)
    app = AppTest.from_string(
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"result, _ = analyze_zeek_conn_log_with_diagnostics({text!r}, [], None)\n"
        f"render_connections(result, public_mode={public_mode!r})\n"
    ).run(timeout=15)
    assert not app.exception
    assert bool(uploader_calls) is not public_mode
    if public_mode:
        assert len([frame for frame in app.dataframe if "Originator" in frame.value.columns]) == 1
        assert app.dataframe[-1].value["Connection starts"].sum() == app.dataframe[0].value["Connections"].sum()
        assert "192.0.2.1" not in str([frame.value for frame in app.dataframe])
        return
    assert len(app.dataframe) == 0
    app.checkbox(key="connection_show_expected").check().run(timeout=15)
    assert app.dataframe[0].value.iloc[0]["Analyst context"] == "Declared expected"
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert app.dataframe[0].value.iloc[0]["Analist bağlamı"] == "Beklentiye uyuyor"
    cti_app = AppTest.from_string(
        "from threatfusion.models import IOCRecord, IOCType\n"
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"result, _ = analyze_zeek_conn_log_with_diagnostics({text!r}, [IOCRecord('198.51.100.1', IOCType.IPV4, 'synthetic')], None)\n"
        "render_connections(result, public_mode=False)\n"
    ).run(timeout=15)
    assert not cti_app.exception
    assert cti_app.dataframe[0].value.iloc[0]["Analyst context"] == "CTI conflict"


def test_context_workload_records_masquerade_limitation_and_immutable_inputs(tmp_path):
    from scripts.lab.evaluate_expected_controls import evaluate
    output = tmp_path / "context-controls"
    summary = evaluate(output)
    assert summary["passed_controls"] == 11
    observations = {r["name"]: r for r in summary["observations"]}
    assert observations["heartbeat_on_declared_endpoint"]["status"] == "declared_expected"
    assert observations["heartbeat_unknown"]["status"] == "review"
    assert observations["cti_conflict"]["status"] == "cti_conflict"
    assert all(r["original_priority"] == "review" for r in summary["observations"] if r["status"] == "declared_expected")
    original = (output / "summary.json").read_bytes()
    with pytest.raises(FileExistsError):
        evaluate(output)
    assert (output / "summary.json").read_bytes() == original


@pytest.mark.parametrize("oversized", [False, True])
def test_invalid_ui_upload_keeps_original_reviews_visible(monkeypatch, oversized):
    payload = b'{"private-note": "never echo this topology"}'
    monkeypatch.setattr(ui_connections.st, "file_uploader", lambda *a, **kw: SimpleNamespace(
        size=MAX_RULE_BYTES + 1 if oversized else len(payload), getvalue=lambda: payload,
    ))
    app = AppTest.from_string(
        "from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics\n"
        "from threatfusion.ui_connections import render_connections\n"
        f"result, _ = analyze_zeek_conn_log_with_diagnostics({telemetry()!r}, [], None)\n"
        "render_connections(result, public_mode=False)\n"
    ).run(timeout=15)
    assert not app.exception and app.error
    assert "never echo" not in app.error[0].value
    assert app.dataframe[0].value.iloc[0]["Queue priority"] == "Review"
    assert not app.dataframe[0].value.iloc[0]["Declared expected"]
