"""Collector CLI behavior while the user's CTI cache is locked by a refresh."""
from __future__ import annotations

import json
import os
import sqlite3

import pytest

from scripts.lab.operational_faults import ACCEPTANCE, CASES, conn_rows, seed_cache
from scripts.lab.measure_multiday import log
from threatfusion import telemetry_collector as module
from threatfusion.collector_health import validate_collector_health
from threatfusion.cti_cache import replace_source_records
from threatfusion.models import IOCRecord, IOCType
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux collector file/lock contract")


def busy():
    error = sqlite3.OperationalError("database is locked")
    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
    return error


def setup(tmp_path):
    source, state, cache = tmp_path / "source", tmp_path / "private", tmp_path / "cti.sqlite"
    source.mkdir()
    (source / "conn.a.log").write_text(log("conn", conn_rows("t", 20)))
    replace_source_records(cache, "Synthetic", [IOCRecord("198.51.100.77", IOCType.IPV4, "Synthetic")])
    return source, state, cache


def drive(monkeypatch, steps):
    """Run main's poll loop with each sleep performing the next test step."""
    calls = iter(steps)

    def sleep(_seconds):
        step = next(calls, None)
        if step is None:
            raise KeyboardInterrupt
        step()
    monkeypatch.setattr(module.time, "sleep", sleep)


def status(state):
    return json.loads((state / "status.json").read_text())


def rollback_journal(cache, monkeypatch):
    """Fallback when WAL cannot be enabled (e.g. a filesystem without shared memory)."""
    from threatfusion import cti_cache
    monkeypatch.setattr(cti_cache, "_enable_wal", lambda connection: None)
    with sqlite3.connect(cache) as connection:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"


def test_real_cti_lock_longer_than_busy_timeout_keeps_collecting_with_disclosure(tmp_path, monkeypatch, capsys):
    source, state, cache = setup(tmp_path)
    rollback_journal(cache, monkeypatch)
    observed = []
    holder = sqlite3.connect(cache, timeout=0, isolation_level=None)

    def lock():
        observed.append(status(state))
        holder.execute("BEGIN EXCLUSIVE")
        os.utime(cache)  # Force a reload attempt while the lock is held.

    def unlock():
        observed.append(status(state))
        holder.execute("ROLLBACK")
        replace_source_records(cache, "Other", [IOCRecord("changed.test", IOCType.DOMAIN, "Other")])

    drive(monkeypatch, [lock, unlock, lambda: observed.append(status(state))])
    try:
        assert module.main(["--input-dir", str(source), "--state-dir", str(state), "--db", str(cache)]) == 0
    finally:
        holder.close()
    first, during, after = observed
    assert not first["cti_reload_deferred"] and first["cti_indicators"] == 1
    assert during["cti_reload_deferred"] and during["cti_indicators"] == 1
    assert not after["cti_reload_deferred"] and after["cti_indicators"] == 2
    assert after["counts"]["retained_records"] == 20
    validate_collector_health(during)


def test_busy_first_cti_read_never_scans_as_empty_cache(tmp_path, monkeypatch, capsys):
    source, state, cache = setup(tmp_path)
    attempts = []

    def read(self):
        attempts.append(1)
        if len(attempts) == 1:
            raise busy()
        self.records = [IOCRecord("198.51.100.77", IOCType.IPV4, "Synthetic")]
        return self.records
    monkeypatch.setattr(module.CTICacheReader, "read", read)
    drive(monkeypatch, [lambda: None])
    assert module.main(["--input-dir", str(source), "--state-dir", str(state), "--db", str(cache)]) == 0
    assert "CTI cache is busy" in capsys.readouterr().err
    # The waiting poll produced no scan; the first scan has the full cache.
    assert status(state)["cti_indicators"] == 1 and not status(state)["cti_reload_deferred"]


def test_busy_cti_once_and_other_sqlite_errors_stop_actionably(tmp_path, monkeypatch, capsys):
    source, state, cache = setup(tmp_path)
    monkeypatch.setattr(module.CTICacheReader, "read", lambda self: (_ for _ in ()).throw(busy()))
    with pytest.raises(SystemExit) as stopped:
        module.main(["--input-dir", str(source), "--state-dir", str(state), "--db", str(cache), "--once"])
    assert stopped.value.code == 1 and "CTI cache is busy" in capsys.readouterr().err
    assert not (state / "status.json").exists()

    monkeypatch.setattr(module.CTICacheReader, "read",
                        lambda self: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error")))
    with pytest.raises(SystemExit) as stopped:
        module.main(["--input-dir", str(source), "--state-dir", str(state), "--db", str(cache)])
    assert stopped.value.code == 1 and "Collector stopped" in capsys.readouterr().err


def test_cti_reload_state_is_validated_and_defaults_false(tmp_path):
    source, state, _ = setup(tmp_path)
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick()["cti_reload_deferred"] is False
    with pytest.raises(ValueError, match="CTI reload"):
        validate_collector_health({"cti_reload_deferred": "yes"})


def test_fault_method_declares_every_case_and_fixture_parses(tmp_path):
    assert set(ACCEPTANCE) == set(CASES)
    parsed = parse_zeek_conn_log_with_diagnostics(log("conn", conn_rows("m", 30)))
    assert len(parsed.connections) == 30 and not parsed.diagnostics.invalid_connection_fields
    seed_cache(tmp_path / "cache.sqlite", count=3)
    assert (tmp_path / "cache.sqlite").stat().st_mode & 0o777 == 0o600


def test_dashboard_warns_when_cti_reload_was_deferred(tmp_path):
    from datetime import datetime, timezone
    from streamlit.testing.v1 import AppTest
    source, state, _ = setup(tmp_path)
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=datetime.now(timezone.utc), cti_reload_deferred=True,
                       indicators=[IOCRecord("198.51.100.77", IOCType.IPV4, "Synthetic")])
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\n"
        f"render_collector(Path({str(state)!r}), public_mode=False)\n"
    ).run(timeout=15)
    assert not app.exception
    assert any("CTI cache was busy" in warning.value for warning in app.warning)
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=20)
    assert any("CTI önbelleği meşguldü" in warning.value for warning in app.warning)


def test_unchanged_indicators_are_not_deep_copied_and_changed_content_recomputes(tmp_path):
    source, state, _ = setup(tmp_path)
    first = [IOCRecord("198.51.100.77", IOCType.IPV4, "Synthetic", tags=["a"])]
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick(indicators=first)["scan"]["analysis_recomputed"]
        # Field view shares immutable values; a real cache is not deep-copied.
        assert collector.cached_indicators[0][0][0] is first[0].value
        assert not collector.tick(indicators=first)["scan"]["analysis_recomputed"]
        reloaded = [IOCRecord("198.51.100.77", IOCType.IPV4, "Synthetic", tags=["a"])]
        assert not collector.tick(indicators=reloaded)["scan"]["analysis_recomputed"]
        changed = [IOCRecord("198.51.100.77", IOCType.IPV4, "Synthetic", tags=["b"])]
        assert collector.tick(indicators=changed)["scan"]["analysis_recomputed"]
        changed[0].tags.append("c")  # In-place mutation still invalidates.
        assert collector.tick(indicators=changed)["scan"]["analysis_recomputed"]


def test_wal_cache_lets_collector_read_while_a_refresh_writes(tmp_path, monkeypatch):
    source, state, cache = setup(tmp_path)
    with sqlite3.connect(cache) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    observed = []
    holder = sqlite3.connect(cache, timeout=0, isolation_level=None)

    def write():
        holder.execute("BEGIN IMMEDIATE")
        holder.execute("INSERT INTO cti_metadata VALUES('refresh-in-progress', '1')")
        os.utime(cache)

    def check():
        observed.append(status(state))
        holder.execute("ROLLBACK")

    drive(monkeypatch, [write, check])
    try:
        assert module.main(["--input-dir", str(source), "--state-dir", str(state), "--db", str(cache)]) == 0
    finally:
        holder.close()
    # The reload during the open write transaction succeeded immediately.
    assert observed[0]["cti_reload_deferred"] is False and observed[0]["cti_indicators"] == 1
