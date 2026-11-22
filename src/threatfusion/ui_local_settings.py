"""Local installer controls; unavailable in normal or hosted runtime profiles."""

from __future__ import annotations

import os
from pathlib import Path

from .app_config import AppConfig, load_app_config
from .cti_cache import RETIRED_SOURCES
from .i18n import tr
from .memo import cached
from .local_setup import prepare_local_environment
from .local_workspace import (
    load_settings,
    validate_root,
)


def managed_root() -> Path | None:
    value = os.environ.get("THREATFUSION_LOCAL_INSTALL_DIR")
    if value is None:
        return None
    if os.environ.get("THREATFUSION_LOCAL_LOOPBACK") != "1":
        return None
    return validate_root(Path(value))


@cached(max_entries=4)
def _mode_config(root: Path, mode: str) -> AppConfig:
    return load_app_config(prepare_local_environment(root, mode, {}))


def resolve_managed_config(config: AppConfig) -> tuple[AppConfig, Path | None]:
    root = managed_root()
    if root is None:
        return config, None
    return _mode_config(root, load_settings(root)["mode"]), root


def needs_first_setup(root: Path) -> bool:
    """A real-CTI installation that has never attempted a source update."""
    return load_settings(root)["mode"] == "cti-only" and not (root / "refresh-status.json").exists()


def _next_download(root: Path, interval_hours: int) -> str | None:
    """Hours until the oldest fresh source is due, or None when one is due now."""
    from datetime import datetime, timedelta, timezone

    from .cti_cache import list_cti_cache_status

    try:
        statuses = list_cti_cache_status(root / "runtime/cti/threatfusion.sqlite")
    except (OSError, ValueError):
        return None
    times = []
    for item in statuses:
        try:
            refreshed = datetime.fromisoformat(item.refreshed_at)
        except (TypeError, ValueError):
            return None
        times.append(refreshed if refreshed.tzinfo else refreshed.replace(tzinfo=timezone.utc))
    if not times:
        return None
    remaining = min(times) + timedelta(hours=interval_hours) - datetime.now(timezone.utc)
    hours = remaining.total_seconds() / 3600
    return f"{hours:.1f}" if hours > 0.05 else None


def _refresh_summary(status: dict) -> tuple[str, str]:
    outcomes = [item for item in status.get("outcomes", []) if item.get("source") != "Cache maintenance"]
    relevant = [item for item in outcomes if item.get("source") not in RETIRED_SOURCES]
    failed = [item for item in relevant if item.get("status") == "failed"]
    refreshed = [item for item in relevant if item.get("status") == "refreshed"]
    if status.get("failed"):
        return "warning", tr("CTI update failed. Check your internet connection and retry; existing data is kept.")
    if relevant and not failed and not refreshed:
        return "info", tr("CTI is already up to date; nothing needed downloading. To download anyway, tick “Download again even if sources are still fresh”.")
    if failed and not refreshed and all(item.get("status") == "failed" for item in relevant):
        return "warning", tr("No CTI source could be reached. Check your internet connection; existing data is kept.")
    if failed:
        return "warning", tr("CTI update finished with problems. See Local setup & CTI updates.")
    return "success", tr("CTI update finished: {count} source(s) downloaded.", count=len(refreshed))


def _local_time(value) -> str:
    """An ISO timestamp as the viewer's local 'dd.mm.yyyy HH:MM'; the raw value if it does not parse."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value)).astimezone().strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError):
        return str(value) if value else "—"


