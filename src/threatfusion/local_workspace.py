"""User-owned installation settings, optional credentials and serialized CTI refresh."""

from __future__ import annotations

import json
import os
import re
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
    force: bool = False,
) -> dict:
    """Fixed feeds only, no inherited developer keys, and one refresh at a time.

    ``force`` downloads sources that are still fresh; PhishTank keeps its own
    24-hour public-feed limit.
    """
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
        total = 2 + sum(
            bool(keys.get(name)) for name in ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY")
        )
        status = {
            "attempted_at": reference.isoformat(),
            "running": True,
            "pid": os.getpid(),
            "outcomes": [],
            "progress": {"source": None, "stage": "starting", "completed": 0,
                         "total": total, "percent": 0},
        }
        write_private_json(root / "refresh-status.json", status)
        try:
            outcomes = refresh_configured_sources(
                root / "runtime/cti/threatfusion.sqlite",
                threatfox_key=keys.get("THREATFOX_AUTH_KEY"),
                urlhaus_key=keys.get("URLHAUS_AUTH_KEY"),
                phishtank_key=keys.get("PHISHTANK_APP_KEY"),
                stale_after=timedelta(hours=load_settings(root)["interval_hours"]),
                progress=_progress_recorder(root, status, total, progress),
                now=reference,
                force=bool(force),
            )
            # Persist only safe aggregates. Never retain exception URLs or bodies.
            status["outcomes"] = [
                {
                    k: v
                    for k, v in asdict(item).items()
                    if k in {"source", "status", "record_count"}
                }
                | (
                    # The keyless public feed can be withdrawn upstream; the
                    # user has no key to check. Flag only the safe category.
                    {"public_feed": True}
                    if item.source == "PhishTank" and not keys.get("PHISHTANK_APP_KEY")
                    else {}
                )
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
            status.pop("progress", None)
            status["finished_at"] = datetime.now(timezone.utc).isoformat()
            write_private_json(root / "refresh-status.json", status)
        return status


_DONE_STAGES = frozenset({"skipped", "refreshed", "failed"})
_RAW_RECORDS = re.compile(r"([\d,]+) / ([\d,]+) raw records")


def _progress_recorder(root: Path, status: dict, total: int, outer=None):
    """Persist safe source/stage/percent aggregates; never upstream detail text.

    Sources do not announce download sizes, so the percentage counts finished
    sources plus a bounded in-source estimate (SGB pages, saving phase).
    """
    completed = 0

    def record(source, stage, detail=None):
        nonlocal completed
        fraction = 0.0
        items = None
        if source != "Cache maintenance" and stage in _DONE_STAGES:
            completed = min(total, completed + 1)
        elif stage == "saving":
            fraction = 0.9
        elif detail and (match := _RAW_RECORDS.search(detail)):
            seen, expected = (int(value.replace(",", "")) for value in match.groups())
            fraction = 0.85 * min(1.0, seen / expected) if expected else 0.0
            items = {"seen": seen, "total": expected}
        status["progress"] = {
            "source": source, "stage": stage, "completed": completed, "total": total,
            "percent": min(99, int(100 * (completed + fraction) / total)),
        } | ({"items": items} if items else {})
        write_private_json(root / "refresh-status.json", status)
        if outer is not None:
            outer(source, stage, detail)

    return record


def refresh_running(status: dict | None) -> bool:
    """A recorded refresh counts only while its process is alive."""
    if not status or not status.get("running"):
        return False
    pid = status.get("pid")
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def start_background_refresh(root: Path, credentials: dict | None = None, *, force: bool = False) -> bool:
    """Run a manual refresh outside the Streamlit script so reruns cannot abort it."""
    validate_root(root)
    if refresh_running(read_private_json(root / "refresh-status.json")):
        return False

    def run():
        try:
            refresh_workspace(root, credentials=credentials, force=force)
        except (OSError, ValueError, TypeError):
            pass  # No raw exceptions: upstream errors can carry credentials.

    threading.Thread(target=run, name="threatfusion-cti-refresh", daemon=True).start()
    return True


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
