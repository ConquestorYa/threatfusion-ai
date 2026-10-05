from __future__ import annotations

import errno
import json
import os
import sqlite3
from datetime import timedelta

import pytest

from scripts.lab.evaluate_dns_collector import NOW, cases, log
from threatfusion import telemetry_collector as module
from threatfusion.models import IOCRecord, IOCType
from threatfusion.ui_collector import read_snapshot

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux collector contract")


@pytest.fixture
def paths(tmp_path):
    source = tmp_path / "input"
    source.mkdir()
    return source, tmp_path / "private"


def test_idle_cache_reuses_analysis_but_refreshes_cti_mutations_and_retention(
    paths, monkeypatch
):
    source, state = paths
    (source / "dns.log").write_text(log(cases(1)[0]["rows"][:1]))
    calls = []
    original = module.build_dns_snapshot

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "build_dns_snapshot", counted)
    indicator = IOCRecord("different.test", IOCType.DOMAIN, "Synthetic")
    with module.ZeekCollector(source, state) as collector:
        first = collector.tick(now=NOW, indicators=[indicator])
        second = collector.tick(now=NOW + timedelta(seconds=1), indicators=[indicator])
        assert len(calls) == 1 and not second["scan"]["analysis_recomputed"]
        assert first["selection_revision"] == second["selection_revision"]
        indicator.value = "updates.test"
        changed = collector.tick(now=NOW + timedelta(seconds=2), indicators=[indicator])
        assert len(calls) == 2 and changed["scan"]["analysis_recomputed"]
        assert (
            read_snapshot(state)["dns"]["report"]["findings"][0]["Queue priority"]
            == "Investigate"
        )
        expired = collector.tick(now=NOW + timedelta(days=2), indicators=[indicator])
        assert len(calls) == 3 and expired["counts"]["analyzed_dns_events"] == 0


def test_mapping_revision_survives_refresh_restart_but_changes_for_new_dns_client(
    paths,
):
    source, state = paths
    row = cases(1)[0]["rows"][0]
    (source / "dns.log").write_text(log([row]))
    with module.ZeekCollector(source, state) as collector:
        first = collector.tick(now=NOW)
        row2 = list(row)
        row2[0] += 1
        (source / "dns.more.log").write_text(log([row2]))
        more = collector.tick(now=NOW)
        assert first["selection_revision"] == more["selection_revision"]
    with module.ZeekCollector(source, state) as collector:
        restart = collector.tick(now=NOW)
        assert restart["selection_revision"] == first["selection_revision"]
        row3 = list(row)
        row3[1], row3[2] = "Cnew", "192.0.2.12"
        (source / "dns.new.log").write_text(log([row3]))
        changed = collector.tick(now=NOW)
        assert changed["selection_revision"] != first["selection_revision"]
    assert "selection_identity" not in (state / "connections.json").read_text()


def test_scan_backlog_fairness_rejection_categories_and_repaired_archive(
    paths, monkeypatch
):
    source, state = paths
    monkeypatch.setattr(module, "MAX_IMPORTS_PER_TICK", 2)
    (source / "dns.a.log").write_text(log(cases(1)[0]["rows"][:1], closed=False))
    (source / "dns.b.log.gz").write_bytes(b"bad archive")
    (source / "dns.c.log").write_text(log(cases(1)[0]["rows"][:1]))
    with module.ZeekCollector(source, state) as collector:
        first = collector.tick(now=NOW)
        assert first["scan"]["remaining_candidates"] == 1
        assert first["scan"]["rejections"]["archive"] == 1
        second = collector.tick(now=NOW)
        assert second["counts"]["analyzed_dns_events"] == 1
        (source / "dns.b.log.gz").unlink()
        (source / "dns.a.log").write_text(log(cases(1)[0]["rows"][:2]))
        third = collector.tick(now=NOW)
        assert third["counts"]["analyzed_dns_events"] == 2
        assert third["scan"]["rejections"]["archive"] == 0
    read_snapshot(state)


def test_full_disk_preserves_last_snapshot_and_committed_dns_evidence(
    paths, monkeypatch
):
    source, state = paths
    (source / "dns.log").write_text(log(cases(1)[0]["rows"][:1]))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    old = (state / "connections.json").read_bytes()
    (source / "dns.more.log").write_text(log(cases(1)[0]["rows"][:2]))
    atomic = module._atomic

    def disk_full(*args):
        raise OSError(errno.ENOSPC, "PRIVATE test path must never be printed")

    monkeypatch.setattr(module, "_atomic", disk_full)
    with module.ZeekCollector(source, state) as collector:
        with pytest.raises(OSError) as error:
            collector.tick(now=NOW)
        assert error.value.errno == errno.ENOSPC
    assert (state / "connections.json").read_bytes() == old
    monkeypatch.setattr(module, "_atomic", atomic)
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
        assert (
            status["counts"]["new_records"] == 0
            and status["counts"]["analyzed_dns_events"] == 2
        )
        assert collector.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_file_permission_failure_is_visible_and_retried_after_repair(paths):
    if os.geteuid() == 0:
        pytest.skip("Root bypasses this permission control")
    source, state = paths
    path = source / "dns.log"
    path.write_text(log(cases(1)[0]["rows"][:1]))
    path.chmod(0o000)
    try:
        with module.ZeekCollector(source, state) as collector:
            rejected = collector.tick(now=NOW)
            assert rejected["scan"]["rejections"]["access"] == 1
            assert rejected["counts"]["analyzed_dns_events"] == 0
            path.chmod(0o600)
            repaired = collector.tick(now=NOW)
            assert repaired["counts"]["new_dns_records"] == 1
            assert repaired["counts"]["rejected_files"] == 0
    finally:
        path.chmod(0o600)


def test_idle_cache_does_not_freeze_expected_rule_expiry(paths):
    from threatfusion.expected_connections import parse_expected_connections

    source, state = paths
    fields = "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state missed_bytes".split()
    values = [
        int(NOW.timestamp()) - 5000,
        "Cexpect",
        "192.0.2.11",
        40000,
        "198.51.100.1",
        443,
        "tcp",
        4000,
        100,
        200,
        "SF",
        0,
    ]
    (source / "conn.log").write_text(
        "#separator \\x09\n#path\tconn\n#fields\t"
        + "\t".join(fields)
        + "\n"
        + "\t".join(map(str, values))
        + "\n#close\t2026-10-05-03-00-00\n"
    )
    rules = parse_expected_connections(
        json.dumps(
            {
                "schema_version": 1,
                "rules": [
                    {
                        "id": "private-rule",
                        "originator_ip": "192.0.2.11",
                        "responder_ip": "198.51.100.1",
                        "responder_port": 443,
                        "protocol": "tcp",
                        "valid_from": (NOW - timedelta(days=1)).isoformat(),
                        "valid_until": (NOW + timedelta(seconds=1)).isoformat(),
                        "max_connections": 10,
                        "max_duration_seconds": 8000,
                        "max_originator_bytes": 10000,
                        "max_responder_bytes": 10000,
                    }
                ],
            }
        ).encode()
    )
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW, rules=rules)
        assert read_snapshot(state)["findings"][0]["Declared expected"]
        expired = collector.tick(now=NOW + timedelta(seconds=2), rules=rules)
        assert not expired["scan"]["analysis_recomputed"]
        assert not read_snapshot(state)["findings"][0]["Declared expected"]


@pytest.mark.parametrize("sqlite", [False, True])
def test_cli_disk_full_error_is_actionable_without_exception_text(
    paths, monkeypatch, capsys, sqlite
):
    source, state = paths
    error = (
        sqlite3.OperationalError("private secret path")
        if sqlite
        else OSError(errno.ENOSPC, "private secret path")
    )
    if sqlite:
        error.sqlite_errorcode = sqlite3.SQLITE_FULL
    monkeypatch.setattr(
        module.ZeekCollector, "tick", lambda *a, **k: (_ for _ in ()).throw(error)
    )
    with pytest.raises(SystemExit) as stopped:
        module.main(["--input-dir", str(source), "--state-dir", str(state), "--once"])
    assert stopped.value.code == 1
    text = capsys.readouterr().err
    assert (
        "disk space" in text
        and "private secret path" not in text
        and str(source) not in text
    )


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda status: status["scan"].update(remaining_candidates=True),
        lambda status: status["scan"].update(analysis_elapsed_seconds=float("nan")),
        lambda status: status["scan"]["rejections"].update(access=1),
        lambda status: status.update(selection_revision="private raw address"),
    ],
)
def test_malformed_operational_snapshot_is_rejected(paths, corrupt):
    source, state = paths
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    report = read_snapshot(state)
    corrupt(report["collector"])
    (state / "connections.json").write_text(json.dumps(report))
    with pytest.raises(ValueError):
        read_snapshot(state)
