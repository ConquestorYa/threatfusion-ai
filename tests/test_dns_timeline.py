from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
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


