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
    refresh_workspace,
    save_credentials,
    save_settings,
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


def render_local_settings(root: Path) -> None:
    settings = load_settings(root)
    with st.sidebar.expander(
        tr("Local setup & CTI updates"),
        expanded=settings["mode"] == "cti-only"
        and not (root / "refresh-status.json").exists(),
    ):
        st.caption(
            tr(
                "This installation uses your own credentials. No developer keys are included."
            )
        )
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
        )
        if mode == "demo":
            st.info(
                tr(
                    "Demo data is synthetic. Switch to real CTI to configure sources and updates."
                )
            )
        else:
            st.caption(
                tr(
                    "SGB and public PhishTank can be attempted without keys. ThreatFox and URLhaus require your own keys. Source access may fail; previous data is preserved."
                )
            )
            saved = load_credentials(root)
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
                        source + " API key", type="password", key="local_key_" + key
                    )
                    for source, key in (
                        ("ThreatFox", KEY_NAMES[0]),
                        ("URLhaus", KEY_NAMES[1]),
                        ("PhishTank (optional)", KEY_NAMES[2]),
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
            if st.button(tr("Update CTI now"), key="local_refresh_cti"):
                keys = st.session_state.get("_local_session_keys", saved)
                with st.status(tr("Updating source caches…")) as progress_view:
                    refresh_workspace(
                        root,
                        credentials=keys,
                        progress=lambda source, stage, detail: progress_view.update(
                            label=source + " · " + tr(stage)
                        ),
                    )
                st.session_state.pop("quick_lookup_result", None)
                st.session_state.pop("analysis_result", None)
                st.rerun()
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
            _render_refresh_status(root)
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


@st.fragment(run_every="10s")
def _render_refresh_status(root: Path) -> None:
    status = read_private_json(root / "refresh-status.json")
    if not status:
        st.info(tr("No refresh yet. Use Update CTI now to download source data."))
        return
    st.caption(tr("Last attempt: {time}", time=status.get("attempted_at", "—")))
    if status.get("running"):
        st.info(
            tr("A source update is running. Existing cached data remains available.")
        )
    if status.get("failed"):
        st.warning(
            tr(
                "Update failed. Check network access and retry; existing data is preserved."
            )
        )
    for item in status.get("outcomes", []):
        source, result = item["source"], item["status"]
        if result == "failed":
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
