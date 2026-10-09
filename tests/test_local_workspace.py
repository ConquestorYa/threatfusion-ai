from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone

import pytest

from threatfusion import local_workspace as workspace
from threatfusion.cti_cache import (
    initialize_cti_cache,
    load_ioc_records,
    replace_source_records,
)
from threatfusion.cti_refresh import CTIRefreshOutcome
from threatfusion.models import IOCRecord, IOCType

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux managed installation"
)


@pytest.fixture
def root(tmp_path):
    directory = tmp_path / "installation"
    directory.mkdir(mode=0o700)
    (directory / ".threatfusion-install").write_text("1\n")
    directory.joinpath("runtime/cti").mkdir(parents=True)
    initialize_cti_cache(directory / "runtime/cti/threatfusion.sqlite")
    return directory


def test_default_private_settings_and_credentials_roundtrip(root):
    assert workspace.load_settings(root) == {
        "mode": "cti-only",
        "interval_hours": 6,
        "automatic": False,
    }
    assert workspace.load_credentials(root) == {}
    assert not (root / "credentials.json").exists()
    workspace.save_settings(root, mode="cti-only", interval_hours=12, automatic=True)
    assert workspace.load_settings(root)["interval_hours"] == 12
    workspace.save_credentials(
        root,
        {"THREATFOX_AUTH_KEY": "owned-test-key", "UNRELATED_SECRET": "never stored"},
    )
    assert workspace.load_credentials(root) == {"THREATFOX_AUTH_KEY": "owned-test-key"}
    assert (root / "credentials.json").stat().st_mode & 0o777 == 0o600
    assert (root / "workspace.json").stat().st_mode & 0o777 == 0o600
    workspace.forget_credentials(root)
    assert workspace.load_credentials(root) == {}


@pytest.mark.parametrize(
    "key,value",
    [
        ("mode", "experimental"),
        ("interval_hours", 1),
        ("interval_hours", True),
        ("automatic", "yes"),
    ],
)
def test_invalid_settings_are_refused(root, key, value):
    settings = {"mode": "cti-only", "interval_hours": 6, "automatic": False, key: value}
    with pytest.raises(ValueError):
        workspace.save_settings(root, **settings)
    workspace.write_private_json(root / "workspace.json", settings)
    with pytest.raises(ValueError):
        workspace.load_settings(root)


@pytest.mark.parametrize("payload", ["x" * 513, "bad\nkey", 12])
def test_bad_credentials_are_rejected_without_file_creation(root, payload):
    with pytest.raises(ValueError):
        workspace.save_credentials(root, {"URLHAUS_AUTH_KEY": payload})
    assert not (root / "credentials.json").exists()


def test_public_permissions_and_links_are_refused(root, tmp_path):
    workspace.save_credentials(root, {"THREATFOX_AUTH_KEY": "test-only"})
    (root / "credentials.json").chmod(0o644)
    with pytest.raises(ValueError):
        workspace.load_credentials(root)
    (root / "credentials.json").unlink()
    target = tmp_path / "unrelated.json"
    target.write_text("{}")
    (root / "credentials.json").symlink_to(target)
    with pytest.raises(OSError):
        workspace.load_credentials(root)
    workspace.save_credentials(root, {})
    assert target.read_text() == "{}"
    assert not (root / "credentials.json").is_symlink()
    root.chmod(0o755)
    with pytest.raises(ValueError):
        workspace.load_settings(root)


def test_refresh_preserves_existing_data_and_redacts_errors(root, monkeypatch):
    db = root / "runtime/cti/threatfusion.sqlite"
    replace_source_records(
        db, "Test", [IOCRecord("fixture.example", IOCType.DOMAIN, "Test")]
    )
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "inherited-developer-key")
    captured = {}

    def refresh(path, **kwargs):
        captured.update(kwargs)
        return (
            CTIRefreshOutcome(
                "SGB",
                "failed",
                error_type="HTTPError",
                detail="https://secret-key.example",
            ),
        )

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    status = workspace.refresh_workspace(
        root, credentials={"URLHAUS_AUTH_KEY": "own-key"}
    )
    assert captured["threatfox_key"] is None and captured["urlhaus_key"] == "own-key"
    assert status["skipped"] == ["ThreatFox"]
    assert not status["running"]
    assert "secret-key" not in json.dumps(status)
    assert "own-key" not in (root / "refresh-status.json").read_text()
    assert load_ioc_records(db)[0].value == "fixture.example"
    assert not (root / "credentials.json").exists()


def test_saved_keys_are_used_only_explicitly(root, monkeypatch):
    workspace.save_credentials(root, {"THREATFOX_AUTH_KEY": "saved-key"})
    seen = []

    def refresh(path, **kwargs):
        seen.append(kwargs["threatfox_key"])
        return ()

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    workspace.refresh_workspace(root)
    workspace.refresh_workspace(root, credentials={})
    assert seen == ["saved-key", None]


def test_concurrent_refresh_does_not_touch_status(root, monkeypatch):
    import fcntl

    with (root / ".refresh.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        assert workspace.refresh_workspace(root) == {"busy": True}
        assert not (root / "refresh-status.json").exists()


def test_unexpected_failure_is_safe_and_throttled(root, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("private-key-bearing-url")

    monkeypatch.setattr(workspace, "refresh_configured_sources", broken)
    status = workspace.refresh_workspace(root)
    assert status["failed"] and not status["running"]
    assert "private-key" not in json.dumps(status)
    settings = {"mode": "cti-only", "automatic": True, "interval_hours": 6}
    now = datetime.fromisoformat(status["attempted_at"])
    assert not workspace.refresh_due(settings, status, now + timedelta(hours=5))
    assert workspace.refresh_due(settings, status, now + timedelta(hours=6))


@pytest.mark.parametrize(
    "mode,automatic,expected",
    [("demo", True, False), ("cti-only", False, False), ("cti-only", True, True)],
)
def test_refresh_requires_opt_in_and_real_mode(mode, automatic, expected):
    assert (
        workspace.refresh_due(
            {"mode": mode, "automatic": automatic, "interval_hours": 6},
            {},
            datetime.now(timezone.utc),
        )
        is expected
    )


def test_automatic_loop_catches_up_and_stops(root, monkeypatch):
    workspace.save_settings(root, mode="cti-only", interval_hours=6, automatic=True)
    stop = threading.Event()
    calls = []

    def refresh(path):
        calls.append(path)
        stop.set()

    monkeypatch.setattr(workspace, "refresh_workspace", refresh)
    workspace.automatic_refresh_loop(root, stop, poll_seconds=0.01)
    assert calls == [root]


def test_unsafe_refresh_lock_preserves_its_target(root, tmp_path):
    target = tmp_path / "keep"
    target.write_text("private")
    (root / ".refresh.lock").symlink_to(target)
    with pytest.raises(OSError):
        workspace.refresh_workspace(root)
    assert target.read_text() == "private"


def test_progress_records_safe_percentages_and_stale_running_is_ignored(root, monkeypatch):
    snapshots = []

    def refresh(path, **kwargs):
        progress = kwargs["progress"]
        progress("URLhaus", "fetching", "https://key-bearing.example")
        snapshots.append(workspace.read_private_json(root / "refresh-status.json")["progress"])
        progress("URLhaus", "refreshed", "5 active records")
        progress("SGB", "fetching", "page 2 · 500 / 1,000 raw records")
        snapshots.append(workspace.read_private_json(root / "refresh-status.json")["progress"])
        return ()

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    status = workspace.refresh_workspace(root, credentials={"URLHAUS_AUTH_KEY": "own-key"})
    assert [s["percent"] for s in snapshots] == [0, 71]
    assert snapshots[1]["completed"] == 1 and snapshots[1]["total"] == 2
    assert "key-bearing" not in (root / "refresh-status.json").read_text()
    assert not workspace.refresh_running(status) and "progress" not in status
    assert workspace.refresh_running({"running": True, "pid": os.getpid()})
    assert not workspace.refresh_running({"running": True, "pid": 2 ** 22 + 12345})
    assert not workspace.refresh_running({"running": True})


def test_background_refresh_runs_once_outside_the_caller(root, monkeypatch):
    import time
    calls = []
    monkeypatch.setattr(workspace, "refresh_configured_sources", lambda path, **k: calls.append(1) or ())
    assert workspace.start_background_refresh(root, credentials={})
    deadline = time.monotonic() + 10
    while not workspace.read_private_json(root / "refresh-status.json").get("finished_at"):
        assert time.monotonic() < deadline
        time.sleep(0.02)
    assert calls == [1]
    workspace.write_private_json(root / "refresh-status.json", {"running": True, "pid": os.getpid()})
    assert not workspace.start_background_refresh(root, credentials={})


def test_sgb_record_counts_are_kept_as_safe_integers(root, monkeypatch):
    seen = []

    def refresh(path, **kwargs):
        kwargs["progress"]("SGB", "fetching", "page 3 · 29,997 / 495,842 raw records")
        seen.append(workspace.read_private_json(root / "refresh-status.json")["progress"]["items"])
        return ()

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    workspace.refresh_workspace(root, credentials={})
    assert seen == [{"seen": 29997, "total": 495842}]
