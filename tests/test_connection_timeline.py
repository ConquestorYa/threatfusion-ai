from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from threatfusion.connection_timeline import MAX_BUCKETS, MAX_GROUPS, build_timelines, validate_timeline_report
from threatfusion.connections import ConnectionRecord, analyze_connections
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_dns_events

NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)


def record(uid="private-uid", **changes):
    return replace(ConnectionRecord(uid, NOW, "192.0.2.1", "198.51.100.1", 40000,
                                    443, "tcp", 4000, 10, 20, "SF", 0), **changes)


def report(*records):
    result = analyze_dns_events([], [], None, connections=records)
    return json.loads(build_connection_report(result, generated_at=NOW, evaluated_at=NOW))


def test_real_pipeline_reconciles_duplicates_conflicts_missing_times_and_bytes():
    first = record()
    rows = (first, first, record("conflict"), record("conflict", responder_ip="198.51.100.2"),
            record("unknown", timestamp=None, originator_bytes=None),
            record("naive", timestamp=NOW.replace(tzinfo=None)),
            record("later", timestamp=NOW + timedelta(minutes=20), originator_bytes=None, state="private-state"))
    payload = report(*rows)
    validate_timeline_report(payload["timelines"], payload["findings"])
    group = next(g for g in payload["timelines"]["groups"] if g["untimed_connections"] == 2)
    assert len(group["buckets"]) == 5
    assert [b["connections"] for b in group["buckets"]] == [1, 0, 0, 0, 1]
    assert group["buckets"][-1]["originator_bytes"] == 0
    assert group["buckets"][-1]["originator_bytes_unknown"] == 1
    assert group["buckets"][-1]["states"] == {"unknown": 1}
    assert sum(b["connections"] for b in group["buckets"]) + group["untimed_connections"] == 4
    text = json.dumps(payload)
    for private in ("192.0.2.1", "198.51.100.1", "private-uid", "private-state"):
        assert private not in text
    assert sum(g["untimed_connections"] + sum(b["connections"] for b in g["buckets"])
               for g in payload["timelines"]["groups"]) == 4


def test_global_caps_keep_all_findings_and_prioritize_reviews_without_changing_detection():
    records = tuple(record(f"uid{i}", responder_port=i, duration_seconds=1) for i in range(MAX_GROUPS + 3))
    records += (record("review", responder_port=65535),)
    result = analyze_dns_events([], [], None, connections=records)
    assert result.connection_findings == analyze_connections(records)
    assert len(result.connection_timelines) == MAX_GROUPS
    payload = json.loads(build_connection_report(result))
    assert len(payload["findings"]) == MAX_GROUPS + 4
    assert payload["findings"][0]["Queue priority"] == "Review"
    assert payload["timelines"]["groups_omitted"] == 4
    validate_timeline_report(payload["timelines"], payload["findings"])


def test_adaptive_width_offset_timezone_and_unknown_time_only_groups():
    records = (record("first", timestamp=NOW.astimezone(timezone(timedelta(hours=3)))),
               record("last", timestamp=NOW + timedelta(days=7)))
    groups = build_timelines(records, analyze_connections(records))
    assert len(groups[0].buckets) <= MAX_BUCKETS
    assert groups[0].bucket_seconds > 300
    assert groups[0].buckets[0]["start_utc"] == NOW.isoformat()
    assert sum(b["connections"] for b in groups[0].buckets) == 2
    payload = report(record(timestamp=None))
    assert payload["timelines"]["groups"][0]["buckets"] == []
    assert payload["timelines"]["groups"][0]["untimed_connections"] == 1
    validate_timeline_report(payload["timelines"], payload["findings"])
    assert report()["timelines"]["groups"] == []


@pytest.mark.parametrize("change", [
    lambda t: t.update(groups_omitted=1),
    lambda t: t["groups"].append(t["groups"][0]),
    lambda t: t["groups"][0].update(group=True),
    lambda t: t["groups"][0].update(group=2),
    lambda t: t["groups"][0].update(bucket_seconds=0),
    lambda t: t["groups"][0].update(untimed_connections=1),
    lambda t: t["groups"][0]["buckets"][0].update(start_utc="2026-10-04T12:00:00"),
    lambda t: t["groups"][0]["buckets"][0].update(connections=-1),
    lambda t: t["groups"][0]["buckets"][0].update(states={"SF": True}),
    lambda t: t["groups"][0]["buckets"][0].update(states={"private": 1}),
    lambda t: t["groups"][0]["buckets"][0].update(originator_bytes=-1),
    lambda t: t["groups"][0]["buckets"][0].update(responder_bytes_unknown=2),
    lambda t: t["groups"][0]["buckets"][0].update(originator_bytes_unknown=1),
    lambda t: t.update(groups_omitted=False),
])
def test_snapshot_validation_rejects_corrupt_or_misleading_details(change):
    payload = report(record())
    modified = copy.deepcopy(payload["timelines"])
    change(modified)
    with pytest.raises(ValueError):
        validate_timeline_report(modified, payload["findings"])


@pytest.mark.skipif(__import__("os").name != "posix", reason="Linux live analyzer contract")
def test_live_analyzer_preserves_existing_outputs_and_refuses_git_or_public_directories(tmp_path, monkeypatch):
    from scripts.lab import analyze_termination

    checkout = tmp_path / "checkout"
    checkout.mkdir(mode=0o700)
    monkeypatch.setattr(analyze_termination, "ROOT", checkout)
    with pytest.raises(ValueError, match="outside the repository"):
        analyze_termination.analyze(checkout)
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    public.chmod(0o755)  # Make the public fixture explicit even under umask 077.
    with pytest.raises(ValueError, match="owner-only"):
        analyze_termination.analyze(public)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    proof = private / "proof.json"
    proof.write_text("preserve")
    with pytest.raises(ValueError, match="Existing analysis outputs"):
        analyze_termination.analyze(private)
    assert proof.read_text() == "preserve"
