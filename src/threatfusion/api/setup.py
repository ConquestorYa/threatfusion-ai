"""Setup & CTI updates (managed installation) as JSON.

Mirrors ``ui_local_settings.render_local_settings``, ``render_refresh_progress``
and the CTI source table of ``streamlit_app``, reusing their helpers
(``_refresh_summary``, ``_next_download``, ``_local_time``, ``cti_status_rows``)
in the requested language. Writes go through the same functions
(``save_settings``, ``start_background_refresh``).

API keys (user decision, DEC-103): this API has no browser session, so keys
entered here are always saved to the owner-only credentials file (Streamlit's
"Save keys on this computer"), and "Forget" deletes that file. No key is kept
in process memory or ever returned. "Stop local application" stays in
Streamlit (it stops the Streamlit launcher, not this API).
A manual update from here uses the saved keys only.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .. import i18n
from .lookup import in_language
from .settings import ApiSettings, _managed_config

INTERVALS = (6, 12, 24)


class NotManaged(LookupError):
    """Setup exists only for a managed installation, as in Streamlit."""


def _root(settings: ApiSettings):
    if settings.local_root is None:
        raise NotManaged()
    return settings.local_root


def _refresh_blocks(status: dict) -> list[dict]:
    """``_render_refresh_status`` as blocks."""
    from ..cti_cache import RETIRED_SOURCES
    from ..local_workspace import refresh_running
    from ..ui_local_settings import _local_time

    tr = i18n.tr
    if not status:
        return [{"kind": "info", "text": tr("No refresh yet. Use Update CTI now to download source data.")}]
    blocks = [{"kind": "caption", "text": tr("Last attempt: {time}", time=_local_time(status.get("attempted_at")))}]
    if refresh_running(status):
        blocks.append({"kind": "info", "text": tr("A source update is running. Existing cached data remains available.")})
    if status.get("failed"):
        blocks.append({"kind": "warning", "text": tr("Update failed. Check network access and retry; existing data is preserved.")})
    for item in status.get("outcomes", []):
        source, result = item["source"], item["status"]
        if source in RETIRED_SOURCES:
            continue
        if source == "Cache maintenance" and result == "failed":
            blocks.append({"kind": "warning", "text": tr("Cache cleanup failed; completed source updates remain available. Retry maintenance later.")})
            continue
        if result == "failed" and source == "SGB":
            blocks.append({"kind": "warning", "text": tr("{source}: update failed; previous cache preserved. Check your internet connection or source availability.", source=tr(source))})
        elif result == "failed":
            blocks.append({"kind": "warning", "text": tr("{source}: update failed; previous cache preserved. Check source access and your key.", source=tr(source))})
        else:
            blocks.append({"kind": "caption", "text": tr(source) + " · " + (
                tr("Cache still fresh") if result == "fresh" else tr("{count} records updated", count=item["record_count"]))})
    for source in status.get("skipped", []):
        blocks.append({"kind": "caption", "text": tr("{source}: skipped (no API key).", source=source)})
    blocks.append({"kind": "caption", "text": tr("Existing analysis results are snapshots. Run the lookup or analysis again after a cache update.")})
    return blocks


def _progress(status: dict) -> dict | None:
    """``render_refresh_progress`` while an update runs."""
    from ..local_workspace import refresh_running

    tr = i18n.tr
    if not refresh_running(status):
        return None
    progress = status.get("progress") or {}
    percent = progress.get("percent", 0)
    percent = percent if type(percent) is int and 0 <= percent <= 100 else 0
    label = tr("Updating CTI sources: {done}/{total} finished · {percent}%",
               done=progress.get("completed", 0), total=progress.get("total") or 0, percent=percent)
    if progress.get("source"):
        label += " · " + str(progress["source"]) + " · " + tr(str(progress.get("stage", "")))
    items = progress.get("items")
    if isinstance(items, dict) and type(items.get("seen")) is int and type(items.get("total")) is int:
        label += " · " + tr("{seen} / {total} records", seen=f"{items['seen']:,}", total=f"{items['total']:,}")
    return {"percent": percent, "label": label, "caption": tr(
        "Existing cached data stays available until each source finishes. Download sizes are not known in advance, so the percentage counts finished sources.")}


def _sources(settings: ApiSettings, mode: str, language: str) -> dict | None:
    import sqlite3

    from ..cti_cache import list_cti_cache_status
    from ..dashboard import cti_status_rows

    tr = i18n.tr
    config = _managed_config(settings.local_root, mode)
    try:
        rows = cti_status_rows(list_cti_cache_status(config.db_path),
                               stale_after_by_source=config.cti_stale_after_by_source)
    except sqlite3.OperationalError:
        rows = []  # a refresh holds the cache
    if not rows:
        return None
    columns = list(rows[0])

    def cell(value):
        if language == "tr" and isinstance(value, str):
            return i18n._VALUE_TR.get(value, value)
        return value

    return {"title": tr("CTI sources"),
            "columns": [i18n._COLUMN_TR.get(c, c) if language == "tr" else c for c in columns],
            "rows": [[cell(row[c]) for c in columns] for row in rows],
            "caption": tr("CTI status describes the local cache, not a live feed connection.")}


def setup_state(settings: ApiSettings, language: str) -> dict:
    from ..local_workspace import KEY_NAMES, load_credentials, load_settings, read_private_json, refresh_running
    from ..ui_local_settings import _next_download, _refresh_summary

    if settings.local_root is None:
        return {"state": "not_managed"}
    root = settings.local_root
    with in_language(language):
        tr = i18n.tr
        values = load_settings(root)
        mode = values["mode"]
        result: dict = {
            "state": "ok",
            "caption": tr("This installation uses your own credentials. No developer keys are included."),
            "mode": {"title": tr("Operating mode"), "value": mode, "options": [
                {"value": "cti-only", "label": tr("Real CTI · ML trained on this computer")},
                {"value": "demo", "label": tr("Synthetic demo")}]},
            "application": {"title": tr("Application"), "caption": tr(
                "Reopen from the applications menu or run threatfusion-ai. Closing the browser tab does not stop the local server.")},
        }
        if mode == "demo":
            result["demo_note"] = tr("Demo data is synthetic. Switch to real CTI to configure sources and updates.")
            return result
        saved = load_credentials(root)
        sources = [(source, key) for source, key in (("ThreatFox", KEY_NAMES[0]), ("URLhaus", KEY_NAMES[1]))]
        missing = [source for source, key in sources if not saved.get(key)]
        result["keys"] = {
            "title": tr("API keys"),
            "fields": [{"name": "threatfox", "label": tr("{source} API key", source="ThreatFox")},
                       {"name": "urlhaus", "label": tr("{source} API key", source="URLhaus")}],
            "apply": tr("Apply keys"),
            "applied": tr("Keys applied. Empty fields remove keys from this selection."),
            "invalid": tr("Invalid API key format. No credentials were saved."),
            "forget": tr("Forget saved and session keys"),
            "caption": tr("SGB works without a key. ThreatFox and URLhaus require your own keys. Source access may fail; previous data is preserved."),
            "saved": tr("Saved keys: {sources}", sources=", ".join(s for s, key in sources if key in saved) or tr("None")),
            "missing": tr(
                "Without these keys only SGB's list is checked. One free abuse.ch key "
                "(about two minutes at [auth.abuse.ch](https://auth.abuse.ch/)) adds "
                "malware command-and-control servers (ThreatFox) and malware download "
                "addresses (URLhaus), the most useful sources for collected connections. "
                "Enter the same key in both fields. Missing now: {sources}.", sources=", ".join(missing)) if missing else None,
        }
        status = read_private_json(root / "refresh-status.json")
        running = refresh_running(status)
        due = _next_download(root, values["interval_hours"])
        finished = status.get("finished_at")
        summary = None
        if finished and not running:
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(finished)).total_seconds()
            except (TypeError, ValueError):
                age = 0
            if age < 120:
                kind, message = _refresh_summary(status)
                summary = {"kind": kind, "text": message, "finished_at": finished}
        result["cti"] = {
            "title": tr("CTI data"),
            "running": running,
            "force_label": tr("Download again even if sources are still fresh"),
            "force_help": tr("Applies to the next update only and clears when it starts. Normally sources are downloaded again only when older than the update interval."),
            "button": tr("Update CTI now"),
            "busy": tr("An update is already running."),
            "started": tr("CTI update started. You can keep using the app."),
            "due": tr("Sources are fresh; the next download is due in about {hours} h. Tick the box above to download now.", hours=due)
            if due is not None and not running else None,
            "progress": _progress(status),
            "summary": summary,
            "status": _refresh_blocks(status),
        }
        result["schedule"] = {
            "title": tr("Automatic updates"),
            "automatic": values["automatic"], "automatic_label": tr("Automatic updates while the app is running"),
            "interval_hours": values["interval_hours"], "interval_label": tr("Update interval (hours)"),
            "options": list(INTERVALS),
            "caption": tr("Automatic refresh uses only saved keys and public sources. It stops with the app and catches up on the next start."),
            "button": tr("Save update settings"),
        }
        result["sources"] = _sources(settings, mode, language)
        return result


def save_keys(settings: ApiSettings, threatfox: str, urlhaus: str) -> None:
    """``_apply_keys`` with storage always on; empty fields remove keys."""
    from ..local_workspace import KEY_NAMES, clean_credentials, save_credentials

    root = _root(settings)
    keys = clean_credentials({KEY_NAMES[0]: threatfox, KEY_NAMES[1]: urlhaus})  # ValueError on bad format
    save_credentials(root, keys)


def forget_keys(settings: ApiSettings) -> None:
    from ..local_workspace import forget_credentials

    forget_credentials(_root(settings))


def change_mode(settings: ApiSettings, mode: str) -> None:
    """``_change_mode``: only the mode changes; the update settings are kept."""
    from ..local_workspace import load_settings, save_settings

    root = _root(settings)
    values = load_settings(root)
    save_settings(root, mode=mode, interval_hours=values["interval_hours"], automatic=values["automatic"])


def save_schedule(settings: ApiSettings, automatic: bool, interval_hours: int) -> None:
    from ..local_workspace import load_settings, save_settings

    root = _root(settings)
    values = load_settings(root)
    save_settings(root, mode=values["mode"], interval_hours=interval_hours, automatic=automatic)


def start_refresh(settings: ApiSettings, force: bool) -> bool:
    """``_start_refresh`` with the saved keys (no browser-session keys here)."""
    from ..local_workspace import load_credentials, load_settings, start_background_refresh

    root = _root(settings)
    if load_settings(root)["mode"] == "demo":
        raise NotManaged()
    return start_background_refresh(root, credentials=load_credentials(root), force=force)
