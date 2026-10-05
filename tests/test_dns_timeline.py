from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion.dns import DNSEvent
from threatfusion.dns_timeline import build_dns_timelines, validate_dns_timelines
from threatfusion.reporting import build_device_report, build_analysis_report
from threatfusion.runtime_analysis import analyze_dns_events

NOW = datetime(2026, 10, 5, 6, tzinfo=timezone.utc)


def events():
    return [
        DNSEvent(
            "updates.test",
            NOW + timedelta(seconds=i * 120),
            "192.0.2.11",
            response_code=("NOERROR", "NXDOMAIN", "SERVFAIL", None)[i % 4],
        )
        for i in range(20)
    ]


def test_dns_timeline_reconciles_queries_codes_timezones_and_privacy():
    rows = events()
    rows[1].timestamp = rows[1].timestamp.astimezone(timezone(timedelta(hours=3)))
    result = analyze_dns_events(rows, (), None)
    report = json.loads(build_device_report(result))
    block = report["timelines"]
    validate_dns_timelines(block, report["findings"])
    (timeline,) = block["groups"]
    assert timeline["group"] == report["findings"][0]["Group"] == 1
    assert len(timeline["buckets"]) <= 48
    assert sum(b["queries"] for b in timeline["buckets"]) == 20
    for name in ("NOERROR", "NXDOMAIN", "SERVFAIL", "unanswered"):
        assert sum(b["responses"].get(name, 0) for b in timeline["buckets"]) == 5
    assert "192.0.2.11" not in json.dumps(report)
    assert (
        "timelines"
        not in build_analysis_report(
            result, model_name="cti_only_ml_disabled"
        ).json_text
    )


def test_missing_ambiguous_and_duplicate_query_times_remain_explicit():
    result = analyze_dns_events(events(), (), None)
    rows = [
        DNSEvent("updates.test", NOW, "192.0.2.11"),
        DNSEvent("updates.test", NOW, "192.0.2.11"),
        DNSEvent("updates.test", None, "192.0.2.11"),
        DNSEvent("updates.test", NOW.replace(tzinfo=None), "192.0.2.11"),
    ]
    (timeline,) = build_dns_timelines(rows, result.device_findings)["groups"]
    assert timeline["untimed_queries"] == 2
    assert sum(b["queries"] for b in timeline["buckets"]) == 2
    # Duplicate rows count as existing telemetry observations; no new dedup policy.


def test_unknown_clients_ip_fallbacks_and_group_caps_are_disclosed():
    rows = [DNSEvent(f"site{i}.test", NOW, "192.0.2.11") for i in range(205)]
    rows += [DNSEvent("unknown.test", NOW), DNSEvent("198.51.100.1", NOW, "192.0.2.11")]
    result = analyze_dns_events(rows, (), None)
    report = json.loads(build_device_report(result))
    validate_dns_timelines(report["timelines"], report["findings"])
    assert len(report["timelines"]["groups"]) == 200
    assert report["timelines"]["groups_omitted"] == 7
    assert all(
        report["findings"][g["group"] - 1]["Device"] != "Unattributed"
        for g in report["timelines"]["groups"]
    )


def test_long_sparse_span_has_bounded_utc_bins_and_empty_gaps():
    rows = [
        DNSEvent("service.test", NOW + timedelta(days=i * 50), "192.0.2.11")
        for i in range(3)
    ]
    report = json.loads(build_device_report(analyze_dns_events(rows, (), None)))
    (timeline,) = report["timelines"]["groups"]
    assert len(timeline["buckets"]) <= 48
    assert any(b["queries"] == 0 for b in timeline["buckets"])
    assert sum(b["queries"] for b in timeline["buckets"]) == 3
    validate_dns_timelines(report["timelines"], report["findings"])


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda p: p["timelines"].update(policy="other"),
        lambda p: p["timelines"].update(groups_omitted=1),
        lambda p: p["timelines"]["groups"][0].update(group=True),
        lambda p: p["findings"][0].update(Group=True),
        lambda p: p["timelines"]["groups"][0].update(bucket_seconds=61),
        lambda p: p["timelines"]["groups"][0].update(untimed_queries=1),
        lambda p: p["timelines"]["groups"][0]["buckets"][0].update(queries=True),
        lambda p: p["timelines"]["groups"][0]["buckets"][0].update(
            start_utc="2026-01-01T12:00:00"
        ),
        lambda p: p["timelines"]["groups"][0]["buckets"][0]["responses"].update(
            mystery=1
        ),
    ],
)
def test_corrupt_dns_timelines_fail_validation(corrupt):
    report = json.loads(build_device_report(analyze_dns_events(events(), (), None)))
    corrupt(report)
    with pytest.raises(ValueError):
        validate_dns_timelines(report["timelines"], report["findings"])


def test_device_target_ui_is_bilingual_and_resets_only_on_mapping_revision():
    report = json.loads(
        build_device_report(
            analyze_dns_events(
                events() + [DNSEvent("normal.test", NOW, "192.0.2.12")], (), None
            )
        )
    )
    program = (
        "import streamlit as st\nfrom threatfusion.ui_dns_timeline import render_dns_timeline\n"
        "revision=st.text_input('Mapping',value='first')\n"
        f"render_dns_timeline({report['findings']!r},{report['timelines']!r},key='test',revision=revision)\n"
    )
    app = AppTest.from_string(program).run(timeout=15)
    assert (
        not app.exception and app.selectbox(key="test_dns_device").value == "Device 001"
    )
    app.selectbox(key="test_dns_device").select("Device 002").run(timeout=15)
    assert app.selectbox(key="test_dns_device").value == "Device 002"
    app.run(timeout=15)
    assert app.selectbox(key="test_dns_device").value == "Device 002"
    app.text_input[0].set_value("second").run(timeout=15)
    assert app.selectbox(key="test_dns_device").value == "Device 001"
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception and "DNS sorguları" in app.dataframe[0].value


def test_empty_or_old_device_reports_do_not_offer_fake_timelines():
    from threatfusion.ui_dns_timeline import render_dns_timeline

    # Run the shared UI through Streamlit's runner, including legacy snapshots.
    assert callable(render_dns_timeline)
    report = json.loads(build_device_report(analyze_dns_events([], (), None)))
    assert report["timelines"]["groups"] == []
    old_rows = copy.deepcopy(
        json.loads(build_device_report(analyze_dns_events(events(), (), None)))[
            "findings"
        ]
    )
    old_rows[0].pop("Group")
    app = AppTest.from_string(
        "from threatfusion.ui_dns_timeline import render_dns_timeline\n"
        f"render_dns_timeline({old_rows!r},None,key='test',revision='old')\n"
    ).run(timeout=15)
    assert not app.exception and not app.selectbox


def test_switching_device_with_multiple_domains_clears_old_target_safely():
    rows = [
        DNSEvent(name, NOW, client)
        for client in ("192.0.2.11", "192.0.2.12")
        for name in ("a.test", "b.test", "c.test", "d.test")
    ]
    report = json.loads(build_device_report(analyze_dns_events(rows, (), None)))
    app = AppTest.from_string(
        "from threatfusion.ui_dns_timeline import render_dns_timeline\n"
        f"render_dns_timeline({report['findings']!r},{report['timelines']!r},key='test',revision='same')\n"
    ).run(timeout=15)
    assert not app.exception
    app.selectbox(key="test_dns_device").select("Device 002").run(timeout=15)
    app.run(timeout=15)
    assert not app.exception
    selected = app.selectbox(key="test_dns_target").value
    assert report["findings"][selected - 1]["Device"] == "Device 002"
    app.selectbox(key="test_dns_device").select("Device 001").run(timeout=15)
    app.run(timeout=15)
    assert not app.exception
    selected = app.selectbox(key="test_dns_target").value
    assert report["findings"][selected - 1]["Device"] == "Device 001"
