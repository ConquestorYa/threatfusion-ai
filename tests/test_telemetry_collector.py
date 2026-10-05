from __future__ import annotations

import gzip
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion import telemetry_collector as module
from threatfusion.expected_connections import parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.ui_collector import read_snapshot

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux collector file/lock contract")
NOW = datetime(2026, 10, 4, 18, tzinfo=timezone.utc)
FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "missed_bytes")


def text(indices=(0,), *, close=True, long=False):
    rows = [[int(NOW.timestamp()) - 9000 + i * 300, f"C{i}", "192.0.2.1", 40000+i,
             "198.51.100.1", 443, "tcp", 4000 if long else 1, 100, 200, "SF", 0] for i in indices]
    return "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n" + "".join(
        "\t".join(map(str, row)) + "\n" for row in rows
    ) + ("#close\t2026-10-04-18-00-00\n" if close else "")


@pytest.fixture
def paths(tmp_path):
    source, state = tmp_path / "source", tmp_path / "private"
    source.mkdir()
    return source, state


def test_rotation_gzip_copy_and_restart_preserve_one_window(paths):
    source, state = paths
    current = source / "conn.log"
    current.write_text(text(range(12), close=False))
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["retained_records"] == 0
        current.write_text(text(range(12)))
        assert collector.tick(now=NOW)["counts"]["retained_records"] == 12
        current.rename(source / "conn.older.log")
        current.write_text(text(range(12, 24)))
        assert collector.tick(now=NOW)["counts"]["review_groups"] == 1
        (source / "conn.copy.log.gz").write_bytes(gzip.compress((source / "conn.older.log").read_bytes()))
        assert collector.tick(now=NOW)["counts"]["duplicate_files"] == 1
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
        assert status["counts"]["retained_records"] == 24
        assert status["counts"]["new_records"] == 0
    row, = read_snapshot(state)["findings"]
    assert row["Connections"] == 24 and row["Queue priority"] == "Review"
    assert row["Originator"] == "Host 001"
    timeline = read_snapshot(state)["timelines"]["groups"][0]
    assert timeline["group"] == row["Group"]
    assert sum(bucket["connections"] for bucket in timeline["buckets"]) == 24


def test_crash_after_checkpoint_commit_regenerates_report_without_duplicate(paths, monkeypatch):
    source, state = paths
    (source / "conn.log").write_text(text(range(24)))
    atomic = module._atomic
    monkeypatch.setattr(module, "_atomic", lambda *a: (_ for _ in ()).throw(OSError("simulated write failure")))
    with module.ZeekCollector(source, state) as collector:
        with pytest.raises(OSError):
            collector.tick(now=NOW)
    monkeypatch.setattr(module, "_atomic", atomic)
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
        assert status["counts"]["new_records"] == 0 and status["counts"]["retained_records"] == 24
    assert read_snapshot(state)["findings"][0]["Connections"] == 24


def test_conflicting_uid_in_another_archive_excludes_evidence(paths):
    source, state = paths
    (source / "conn.a.log").write_text(text((0,), long=True))
    (source / "conn.b.log").write_text(text((0,), long=True).replace("198.51.100.1", "198.51.100.2"))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    rows = read_snapshot(state)["findings"]
    assert len(rows) == 2 and all(r["Conflicting UIDs"] == 1 and r["Connections"] == 0 for r in rows)


def test_private_state_lock_binding_and_permissions(paths):
    source, state = paths
    with module.ZeekCollector(source, state):
        with pytest.raises(BlockingIOError):
            module.ZeekCollector(source, state)
    other = source.parent / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="bound"):
        module.ZeekCollector(other, state)
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    assert state.stat().st_mode & 0o777 == 0o700
    for path in state.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    state.chmod(0o755)
    with pytest.raises(ValueError):
        module.ZeekCollector(source, state)


def test_retention_capacity_is_visible_and_disables_expectations(paths):
    source, state = paths
    (source / "conn.log").write_text(text(range(3), long=True))
    rules = parse_expected_connections(json.dumps({"schema_version": 1, "rules": [{
        "id": "checked-service", "originator_ip": "192.0.2.1", "responder_ip": "198.51.100.1",
        "responder_port": 443, "protocol": "tcp", "valid_from": (NOW-timedelta(days=1)).isoformat(),
        "valid_until": (NOW+timedelta(days=1)).isoformat(), "max_connections": 10,
        "max_duration_seconds": 8000, "max_originator_bytes": 10000, "max_responder_bytes": 10000,
    }]}).encode())
    with module.ZeekCollector(source, state, max_records=2) as collector:
        status = collector.tick(now=NOW, rules=rules)
        assert status["counts"]["retained_records"] == 2 and status["capacity_coverage_loss"]
        assert not read_snapshot(state)["findings"][0]["Declared expected"]
        status = collector.tick(now=NOW+timedelta(days=2))
        assert status["counts"]["retained_records"] == 0 and not status["capacity_coverage_loss"]
        assert status["counts"]["new_records"] == 0


def test_unchanged_archives_do_not_resurrect_after_ledger_retention(paths):
    source, state = paths
    (source / "conn.log").write_text(text())
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        status = collector.tick(now=NOW+timedelta(days=10))
        assert status["counts"]["new_records"] == 0 and status["counts"]["retained_records"] == 0
        if os.geteuid() != 0:
            previous = (state / "connections.json").read_bytes()
            source.chmod(0o000)
            try:
                with pytest.raises(PermissionError):
                    collector.tick(now=NOW+timedelta(days=11))
                assert (state / "connections.json").read_bytes() == previous
            finally:
                source.chmod(0o700)


def test_symlinks_fifo_invalid_rows_and_expansion_bombs_are_rejected(paths, monkeypatch):
    source, state = paths
    external = source.parent / "outside.log"
    external.write_text(text())
    (source / "conn.link.log").symlink_to(external)
    os.mkfifo(source / "conn.fifo.log")
    (source / "conn.bad.log").write_text(text().replace("\tSF\t0", "\tSF\tunknown"))
    (source / "conn.bomb.log.gz").write_bytes(gzip.compress(b"x"*4097))
    monkeypatch.setattr(module, "MAX_FILE_BYTES", 4096)
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
    assert status["counts"]["rejected_files"] == 4
    assert not status["counts"]["retained_records"]
    (state / "connections.json").chmod(0o644)
    with pytest.raises(ValueError):
        read_snapshot(state)


def test_cti_snapshot_can_be_refreshed_without_new_traffic(paths):
    source, state = paths
    (source / "conn.log").write_text(text())
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        assert not read_snapshot(state)["findings"][0]["CTI match"]
        collector.tick(now=NOW, indicators=[IOCRecord("198.51.100.1", IOCType.IPV4, "synthetic")])
        assert read_snapshot(state)["findings"][0]["CTI match"]


def test_rejected_and_open_files_cannot_starve_later_archive(paths, monkeypatch):
    source, state = paths
    monkeypatch.setattr(module, "MAX_IMPORTS_PER_TICK", 2)
    (source / "conn.a.log").write_text(text(close=False))
    (source / "conn.b.log.gz").write_bytes(b"not gzip")
    (source / "conn.c.log").write_text(text())
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 0
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 1


def test_fifo_lock_is_rejected_without_blocking(paths):
    source, state = paths
    state.mkdir(mode=0o700)
    os.mkfifo(state / "collector.lock", mode=0o600)
    with pytest.raises(ValueError, match="regular file"):
        module.ZeekCollector(source, state)


def test_collector_ui_bilingual_snapshot_and_public_boundary(paths):
    source, state = paths
    (source / "conn.log").write_text(text(long=True))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=datetime.now(timezone.utc))
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\n"
        f"render_collector(Path({str(state)!r}), public_mode=False)\n"
    ).run(timeout=15)
    assert not app.exception and app.dataframe[0].value.iloc[0]["Originator"] == "Host 001"
    assert app.selectbox(key="collector_timeline_group").value == 1
    assert app.dataframe[-1].value.iloc[0]["Zeek states"] == "SF: 1"
    before = read_snapshot(state)
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=20)
    assert not app.exception
    assert app.dataframe[-1].value.iloc[0]["Zeek durumları"] == "SF: 1"
    assert read_snapshot(state) == before
    assert not app.exception and app.dataframe[0].value.iloc[0]["Başlatan"] == "Sistem 001"
    public = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\n"
        f"render_collector(Path({str(state)!r}), public_mode=True)\n"
    ).run(timeout=15)
    assert not public.exception and not public.dataframe and not public.metric


def test_real_process_sigterm_releases_lock_and_restart_is_idempotent(paths):
    source, state = paths
    (source / "conn.log").write_text(text())
    command = [sys.executable, "-m", "threatfusion.telemetry_collector", "--input-dir", str(source),
               "--state-dir", str(state), "--poll-seconds", "1"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        for _ in range(100):
            if (state / "connections.json").exists() or process.poll() is not None:
                break
            time.sleep(0.05)
        assert (state / "connections.json").exists()
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0, stderr
        assert json.loads(stdout.splitlines()[0])["retained_records"] == 1
        restarted = subprocess.run(command+["--once"], capture_output=True, text=True, timeout=10)
        assert restarted.returncode == 0
        assert json.loads(restarted.stdout)["new_records"] == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_complete_managed_application_exposes_collector_but_hosted_profile_does_not(tmp_path, monkeypatch):
    from threatfusion.cti_cache import initialize_cti_cache
    from threatfusion.ui_local_settings import _mode_config

    root = tmp_path / "installation"
    root.mkdir(mode=0o700)
    (root / ".threatfusion-install").write_text("1\n")
    root.joinpath("runtime/cti").mkdir(parents=True)
    initialize_cti_cache(root / "runtime/cti/threatfusion.sqlite")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "conn.log").write_text(text(long=True))
    with module.ZeekCollector(logs, root / "collector") as collector:
        collector.tick(now=datetime.now(timezone.utc))
    monkeypatch.setenv("THREATFUSION_LOCAL_INSTALL_DIR", str(root))
    monkeypatch.setenv("THREATFUSION_LOCAL_LOOPBACK", "1")
    _mode_config.clear()
    application = Path(__file__).resolve().parents[1] / "streamlit_app.py"
    app = AppTest.from_file(str(application))
    app.session_state["workspace_nav"] = "Collected connections"
    app.run(timeout=20)
    assert not app.exception and app.dataframe[0].value.iloc[0]["Originator"] == "Host 001"
    monkeypatch.delenv("THREATFUSION_LOCAL_INSTALL_DIR")
    monkeypatch.delenv("THREATFUSION_LOCAL_LOOPBACK")
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "1")
    monkeypatch.setenv("THREATFUSION_CTI_ONLY", "1")
    monkeypatch.setenv("THREATFUSION_DB_PATH", str(root / "runtime/cti/threatfusion.sqlite"))
    monkeypatch.setenv("THREATFUSION_COLLECTOR_STATE_DIR", str(root / "collector"))
    public = AppTest.from_file(str(application))
    public.session_state["workspace_nav"] = "Collected connections"
    public.run(timeout=20)
    assert not public.exception and all(b.key != "nav_collector" for b in public.button)
    assert not public.dataframe
