"""User-owned installation settings, optional credentials and serialized CTI refresh."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


KEY_NAMES = ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY")
INTERVALS = (6, 12, 24)


def refresh_configured_sources(*args, **kwargs):
    # Settings are also read by the standard-library bootstrap interpreter.
    # Collector dependencies are available only in the runtime environment.
    from .cti_refresh import refresh_configured_sources as refresh

    return refresh(*args, **kwargs)


def validate_root(root: Path) -> Path:
    root = Path(root)
    info = root.lstat()
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("installation must be an owner-only directory")
    if (root / ".threatfusion-install").read_text().strip() != "1":
        raise ValueError("installation ownership marker is missing")
    return root


def read_private_json(path: Path, default: dict | None = None) -> dict:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return dict(default or {})
    with os.fdopen(descriptor) as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > 20_000
        ):
            raise ValueError("local configuration must be a small owner-only file")
        result = json.load(handle)
    if not isinstance(result, dict):
        raise ValueError("invalid local configuration")
    return result


def write_private_json(path: Path, values: dict) -> None:
    # mkstemp creates mode 0600 before writing; replacement is atomic.
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".settings-")
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(values, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_settings(root: Path) -> dict:
    validate_root(root)
    values = read_private_json(root / "workspace.json")
    mode = values.get("mode", "cti-only")
    hours = values.get("interval_hours", 6)
    automatic = values.get("automatic", False)
    if (
        mode not in {"demo", "cti-only"}
        or type(hours) is not int
        or hours not in INTERVALS
    ):
        raise ValueError("invalid workspace settings")
    if type(automatic) is not bool:
        raise ValueError("invalid refresh setting")
    return {"mode": mode, "interval_hours": hours, "automatic": automatic}


def save_settings(
    root: Path, *, mode: str, interval_hours: int, automatic: bool
) -> None:
    validate_root(root)
    if (
        mode not in {"demo", "cti-only"}
        or type(interval_hours) is not int
        or interval_hours not in INTERVALS
    ):
        raise ValueError("invalid workspace settings")
    if type(automatic) is not bool:
        raise ValueError("invalid refresh setting")
    write_private_json(
        root / "workspace.json",
        {
            "mode": mode,
            "interval_hours": interval_hours,
            "automatic": automatic,
        },
    )


def clean_credentials(values: dict) -> dict[str, str]:
    result = {}
    for key in KEY_NAMES:
        value = values.get(key, "")
        if (
            not isinstance(value, str)
            or len(value) > 512
            or any(ord(c) < 32 for c in value)
        ):
            raise ValueError("invalid API key")
        if value.strip():
            result[key] = value.strip()
    return result


def load_credentials(root: Path) -> dict[str, str]:
    validate_root(root)
    return clean_credentials(read_private_json(root / "credentials.json"))


def save_credentials(root: Path, values: dict) -> None:
    validate_root(root)
    write_private_json(root / "credentials.json", clean_credentials(values))


def forget_credentials(root: Path) -> None:
    validate_root(root)
    (root / "credentials.json").unlink(missing_ok=True)


def refresh_due(settings: dict, status: dict, now: datetime) -> bool:
    if settings["mode"] != "cti-only" or not settings["automatic"]:
        return False
    try:
        last = datetime.fromisoformat(status["attempted_at"])
        if last.tzinfo is None:
            return True
        return now - last >= timedelta(hours=settings["interval_hours"])
    except (KeyError, ValueError, TypeError):
        return True


def refresh_workspace(
    root: Path,
    *,
    credentials: dict | None = None,
    progress=None,
    now: datetime | None = None,
) -> dict:
    """Fixed feeds only, no inherited developer keys, and one refresh at a time."""
    import fcntl

    validate_root(root)
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        raise ValueError("refresh time must be timezone-aware")
    keys = (
        load_credentials(root)
        if credentials is None
        else clean_credentials(credentials)
    )
    descriptor = os.open(
        root / ".refresh.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"busy": True}
        # Record attempts even on failure to avoid retry loops while offline.
        status = {
            "attempted_at": reference.isoformat(),
            "running": True,
            "outcomes": [],
        }
        write_private_json(root / "refresh-status.json", status)
        try:
            outcomes = refresh_configured_sources(
                root / "runtime/cti/threatfusion.sqlite",
                threatfox_key=keys.get("THREATFOX_AUTH_KEY"),
                urlhaus_key=keys.get("URLHAUS_AUTH_KEY"),
                phishtank_key=keys.get("PHISHTANK_APP_KEY"),
                stale_after=timedelta(hours=load_settings(root)["interval_hours"]),
                progress=progress,
                now=reference,
            )
            # Persist only safe aggregates. Never retain exception URLs or bodies.
            status["outcomes"] = [
                {
                    k: v
                    for k, v in asdict(item).items()
                    if k in {"source", "status", "record_count"}
                }
                for item in outcomes
            ]
            status["skipped"] = [
                source
                for source, key in (
                    ("ThreatFox", "THREATFOX_AUTH_KEY"),
                    ("URLhaus", "URLHAUS_AUTH_KEY"),
                )
                if key not in keys
            ]
        except Exception:
            status["failed"] = True
        finally:
            status["running"] = False
            status["finished_at"] = datetime.now(timezone.utc).isoformat()
            write_private_json(root / "refresh-status.json", status)
        return status


def automatic_refresh_loop(
    root: Path, stop: threading.Event, *, poll_seconds: float = 30
) -> None:
    """Runs only during the local application lifetime, including startup catch-up."""
    while not stop.is_set():
        try:
            settings = load_settings(root)
            status = read_private_json(root / "refresh-status.json")
            if refresh_due(settings, status, datetime.now(timezone.utc)):
                refresh_workspace(root)
        except (OSError, ValueError, TypeError):
            # No raw exceptions: credentials can be present in upstream errors.
            pass
        stop.wait(poll_seconds)
