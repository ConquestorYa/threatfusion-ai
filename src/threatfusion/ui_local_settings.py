"""Local installer controls; unavailable in normal or hosted runtime profiles."""

from __future__ import annotations

import os
from pathlib import Path

import streamlit as st

from .app_config import AppConfig, load_app_config
from .i18n import tr
from .local_setup import prepare_local_environment, request_local_control
from .local_workspace import (
    KEY_NAMES,
    clean_credentials,
    forget_credentials,
    load_credentials,
    load_settings,
    read_private_json,
    refresh_running,
    save_credentials,
    save_settings,
    start_background_refresh,
    validate_root,
)


def managed_root() -> Path | None:
    value = os.environ.get("THREATFUSION_LOCAL_INSTALL_DIR")
    if value is None:
        return None
    if os.environ.get("THREATFUSION_LOCAL_LOOPBACK") != "1":
        return None
    return validate_root(Path(value))


@st.cache_resource
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


def render_local_settings(root: Path) -> None:
    """Setup page: mode and keys on the left, CTI updates on the right."""
    settings = load_settings(root)
    st.caption(tr("This installation uses your own credentials. No developer keys are included."))
    left, right = st.columns(2, gap="large")
    with left:
        st.markdown(f"#### {tr('Operating mode')}")
        options = ("cti-only", "demo")
        # Read persisted selection; only an explicit widget callback changes it.
        st.session_state["local_mode"] = settings["mode"]
        mode = st.selectbox(
            tr("Operating mode"),
            options,
            format_func=lambda x: (
                tr("Real CTI · ML disabled")
                if x == "cti-only"
                else tr("Synthetic demo")
            ),
            key="local_mode",
            on_change=_change_mode,
            args=(root,),
            label_visibility="collapsed",
        )
        if mode == "demo":
            st.info(tr("Demo data is synthetic. Switch to real CTI to configure sources and updates."))
        else:
            saved = load_credentials(root)
            st.markdown(f"#### {tr('API keys')}")
            st.caption(
                tr(
                    "SGB and public PhishTank can be attempted without keys. ThreatFox and URLhaus require your own keys. Source access may fail; previous data is preserved."
                )
            )
            st.caption(
                tr(
                    "Saved keys: {sources}",
                    sources=", ".join(
                        source
                        for source, key in (
                            ("ThreatFox", KEY_NAMES[0]),
                            ("URLhaus", KEY_NAMES[1]),
                            ("PhishTank", KEY_NAMES[2]),
                        )
                        if key in saved
                    )
                    or tr("None"),
                )
            )
            with st.form("local_credentials", clear_on_submit=True):
                _ = {
                    key: st.text_input(
                        tr("{source} API key", source=source), type="password", key="local_key_" + key
                    )
                    for source, key in (
                        ("ThreatFox", KEY_NAMES[0]),
                        ("URLhaus", KEY_NAMES[1]),
                        (tr("PhishTank (optional)"), KEY_NAMES[2]),
                    )
                }
                st.checkbox(
                    tr("Save keys on this computer"),
                    value=False,
                    key="local_remember_keys",
                )
                st.caption(
                    tr(
                        "Optional storage is a plaintext owner-only (0600) file inside the private installation directory. Leave unchecked for browser-session use only."
                    )
                )
                st.form_submit_button(
                    tr("Apply keys"), on_click=_apply_keys, args=(root,)
                )
            if st.session_state.pop("_local_keys_applied", False):
                st.success(
                    tr("Keys applied. Empty fields remove keys from this selection.")
                )
            if st.session_state.pop("_local_keys_invalid", False):
                st.error(tr("Invalid API key format. No credentials were saved."))
            if st.button(tr("Forget saved and session keys"), key="local_forget_keys"):
                forget_credentials(root)
                st.session_state.pop("_local_session_keys", None)
                st.rerun()
    if mode != "demo":
        with right:
            st.markdown(f"#### {tr('CTI data')}")
            running = refresh_running(read_private_json(root / "refresh-status.json"))
            st.checkbox(
                tr("Download again even if sources are still fresh"),
                key="local_force_refresh", disabled=running,
                help=tr("Applies to the next update only and clears when it starts. Normally sources are downloaded again only when older than the update interval. PhishTank keeps its 24-hour limit."),
            )
            st.button(tr("Update CTI now"), key="local_refresh_cti", disabled=running, type="primary",
                      help=tr("An update is already running.") if running else None,
                      on_click=_start_refresh, args=(root, saved))
            if st.session_state.pop("_local_refresh_started", False):
                st.toast(tr("CTI update started. You can keep using the app."))
            due = _next_download(root, settings["interval_hours"])
            if due is not None and not running:
                st.caption(tr("Sources are fresh; the next download is due in about {hours} h. Tick the box above to download now.", hours=due))
            # Results belong next to the action that produced them.
            _render_refresh_status(root)
            st.markdown(f"#### {tr('Automatic updates')}")
            with st.form("local_schedule"):
                automatic = st.checkbox(
                    tr("Automatic updates while the app is running"),
                    value=settings["automatic"],
                )
                hours = st.selectbox(
                    tr("Update interval (hours)"),
                    (6, 12, 24),
                    index=(6, 12, 24).index(settings["interval_hours"]),
                )
                st.caption(
                    tr(
                        "Automatic refresh uses only saved keys and public sources. It stops with the app and catches up on the next start. PhishTank is checked at most once per 24 hours."
                    )
                )
                if st.form_submit_button(tr("Save update settings")):
                    save_settings(
                        root, mode=mode, interval_hours=hours, automatic=automatic
                    )
                    st.rerun()
    st.divider()
    st.markdown(f"#### {tr('Application')}")
    st.caption(
        tr(
            "Reopen from the applications menu or run threatfusion-ai. Closing the browser tab does not stop the local server."
        )
    )
    if st.button(tr("Stop local application"), key="local_stop_app"):
        request_local_control(root, "stop")
        st.info(tr("The local application is stopping. You can close this tab."))


def _change_mode(root: Path) -> None:
    settings = load_settings(root)
    save_settings(
        root,
        mode=st.session_state["local_mode"],
        interval_hours=settings["interval_hours"],
        automatic=settings["automatic"],
    )
    for key in (
        "analysis_result",
        "quick_lookup_result",
        "upload_fingerprint",
        "dns_parse_diagnostics",
        "dns_input_detection",
        "analysis_audit_metadata",
    ):
        st.session_state.pop(key, None)


def _apply_keys(root: Path) -> None:
    try:
        keys = clean_credentials(
            {key: st.session_state.get("local_key_" + key, "") for key in KEY_NAMES}
        )
        if st.session_state.get("local_remember_keys", False):
            save_credentials(root, keys)
        st.session_state["_local_session_keys"] = keys
        st.session_state["_local_keys_applied"] = True
    except (OSError, ValueError, TypeError):
        st.session_state["_local_keys_invalid"] = True
    finally:
        for key in KEY_NAMES:
            st.session_state["local_key_" + key] = ""
        st.session_state["local_remember_keys"] = False


def _start_refresh(root: Path, saved: dict) -> None:
    """Button callback: the force choice is one-shot and clears explicitly."""
    keys = st.session_state.get("_local_session_keys", saved)  # read at click time
    force = bool(st.session_state.get("local_force_refresh", False))
    # Runs outside this script: page interactions cannot abort it.
    st.session_state["_local_refresh_started"] = start_background_refresh(root, credentials=keys, force=force)
    st.session_state["local_force_refresh"] = False


def upstream_unavailable_sources(root: Path) -> frozenset[str]:
    """Keyless public feeds whose last attempt failed upstream (not offline)."""
    try:
        status = read_private_json(root / "refresh-status.json")
    except (OSError, ValueError):
        return frozenset()
    outcomes = [item for item in status.get("outcomes", []) if isinstance(item, dict)]
    attempted = [item for item in outcomes if item.get("source") != "Cache maintenance" and item.get("status") != "fresh"]
    if attempted and all(item.get("status") == "failed" for item in attempted):
        return frozenset()  # Everything failed: likely local connectivity.
    return frozenset(str(item["source"]) for item in outcomes
                     if item.get("status") == "failed" and item.get("public_feed"))


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
        if item.source == "PhishTank":
            continue
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
    relevant = [item for item in outcomes if not (item.get("status") == "failed" and item.get("public_feed"))]
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


@st.fragment(run_every="2s")
def render_refresh_progress(root: Path) -> None:
    """Main-workspace progress for a running CTI update, and its result."""
    from datetime import datetime, timezone

    status = read_private_json(root / "refresh-status.json")
    finished = status.get("finished_at")
    seen = st.session_state.setdefault("_local_refresh_seen", finished)
    if refresh_running(status):
        progress = status.get("progress") or {}
        percent = progress.get("percent", 0)
        percent = percent if type(percent) is int and 0 <= percent <= 100 else 0
        total = progress.get("total") or 0
        source = progress.get("source")
        label = tr("Updating CTI sources: {done}/{total} finished · {percent}%",
                   done=progress.get("completed", 0), total=total, percent=percent)
        if source:
            label += " · " + str(source) + " · " + tr(str(progress.get("stage", "")))
        items = progress.get("items")
        if isinstance(items, dict) and type(items.get("seen")) is int and type(items.get("total")) is int:
            label += " · " + tr("{seen} / {total} records", seen=f"{items['seen']:,}", total=f"{items['total']:,}")
        st.progress(percent / 100, text=label)
        st.caption(tr("Existing cached data stays available until each source finishes. Download sizes are not known in advance, so the percentage counts finished sources."))
        return
    if finished and finished != seen:
        st.session_state["_local_refresh_seen"] = finished
        # Earlier lookup/analysis results used the previous cache.
        st.session_state.pop("quick_lookup_result", None)
        st.session_state.pop("analysis_result", None)
        st.session_state["_local_refresh_notice"] = (*_refresh_summary(status), finished)
        # The sidebar button and source list sit outside this fragment.
        st.rerun(scope="app")
    notice = st.session_state.get("_local_refresh_notice")
    if notice and notice[2] == finished:
        kind, message, _ = notice
        if not st.session_state.get("_local_refresh_toasted") == finished:
            st.session_state["_local_refresh_toasted"] = finished
            st.toast(message)
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(finished)).total_seconds()
        except (TypeError, ValueError):
            age = 0
        if age < 120:
            getattr(st, kind)(message)


@st.fragment(run_every="10s")
def _render_refresh_status(root: Path) -> None:
    status = read_private_json(root / "refresh-status.json")
    if not status:
        st.info(tr("No refresh yet. Use Update CTI now to download source data."))
        return
    st.caption(tr("Last attempt: {time}", time=status.get("attempted_at", "—")))
    if refresh_running(status):
        st.info(
            tr("A source update is running. Existing cached data remains available.")
        )
    if status.get("failed"):
        st.warning(
            tr(
                "Update failed. Check network access and retry; existing data is preserved."
            )
        )
    attempted = [item for item in status.get("outcomes", [])
                 if item.get("source") != "Cache maintenance" and item.get("status") != "fresh"]
    # When every attempted source failed, the likely cause is local connectivity,
    # not a withdrawn public feed.
    unreachable = bool(attempted) and all(item.get("status") == "failed" for item in attempted)
    for item in status.get("outcomes", []):
        source, result = item["source"], item["status"]
        if source == "Cache maintenance" and result == "failed":
            st.warning(tr("Cache cleanup failed; completed source updates remain available. Retry maintenance later."))
            continue
        if result == "failed" and item.get("public_feed") and not unreachable:
            st.info(
                tr(
                    "{source}: the public keyless feed is currently unavailable from the source; nothing to fix on your side. Other sources are unaffected and previous data is kept.",
                    source=source,
                )
            )
        elif result == "failed" and source in {"SGB", "PhishTank"}:
            st.warning(
                tr(
                    "{source}: update failed; previous cache preserved. Check your internet connection or source availability.",
                    source=source,
                )
            )
        elif result == "failed":
            st.warning(
                tr(
                    "{source}: update failed; previous cache preserved. Check source access and your key.",
                    source=source,
                )
            )
        else:
            st.caption(
                source
                + " · "
                + (
                    tr("Cache still fresh")
                    if result == "fresh"
                    else tr("{count} records updated", count=item["record_count"])
                )
            )
    for source in status.get("skipped", []):
        st.caption(tr("{source}: skipped (no API key).", source=source))
    st.caption(
        tr(
            "Existing analysis results are snapshots. Run the lookup or analysis again after a cache update."
        )
    )
