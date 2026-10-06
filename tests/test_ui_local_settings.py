from __future__ import annotations

import sys

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion import local_workspace as workspace
from threatfusion import ui_local_settings as ui
from threatfusion.app_config import load_app_config
from threatfusion.cti_cache import initialize_cti_cache
from threatfusion.cti_refresh import CTIRefreshOutcome

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux installation UI")


@pytest.fixture
def managed(tmp_path, monkeypatch):
    root = tmp_path / "installation"
    root.mkdir(mode=0o700)
    (root / ".threatfusion-install").write_text("1\n")
    root.joinpath("runtime/cti").mkdir(parents=True)
    initialize_cti_cache(root / "runtime/cti/threatfusion.sqlite")
    monkeypatch.setenv("THREATFUSION_LOCAL_INSTALL_DIR", str(root))
    monkeypatch.setenv("THREATFUSION_LOCAL_LOOPBACK", "1")
    ui._mode_config.clear()
    return root


def local_app(root):
    return AppTest.from_string(
        f"from pathlib import Path\nfrom threatfusion.ui_local_settings import render_local_settings\nrender_local_settings(Path({str(root)!r}))"
    ).run(timeout=15)


def button(app, label):
    return next(b for b in app.button if b.label == label)


def test_hosted_and_developer_runtime_cannot_access_local_settings(monkeypatch):
    monkeypatch.delenv("THREATFUSION_LOCAL_INSTALL_DIR", raising=False)
    assert ui.managed_root() is None
    monkeypatch.setenv("THREATFUSION_LOCAL_INSTALL_DIR", "/private/not-authorized")
    monkeypatch.delenv("THREATFUSION_LOCAL_LOOPBACK", raising=False)
    assert ui.managed_root() is None
    config = load_app_config(
        {"THREATFUSION_PUBLIC_MODE": "1", "THREATFUSION_MODEL_SHA256": "a" * 64}
    )
    assert ui.resolve_managed_config(config) == (config, None)


def test_real_mode_works_without_ml_and_can_switch_to_isolated_demo(managed):
    config, root = ui.resolve_managed_config(load_app_config({}))
    assert root == managed and config.cti_only and not config.public_mode
    assert not config.history_enabled
    assert config.db_path == managed / "runtime/cti/threatfusion.sqlite"
    app = local_app(managed)
    assert not app.exception
    app.selectbox(key="local_mode").select("demo").run(timeout=15)
    assert not app.exception
    assert workspace.load_settings(managed)["mode"] == "demo"
    config, _ = ui.resolve_managed_config(load_app_config({}))
    assert not config.cti_only and config.model_sha256
    assert config.db_path == managed / "runtime/demo/bundle/threatfusion.sqlite"
    assert all(b.key != "local_refresh_cti" for b in app.button)


def test_session_keys_are_not_persisted_or_echoed_and_saved_keys_can_be_forgotten(
    managed,
):
    app = local_app(managed)
    app.text_input(key="local_key_THREATFOX_AUTH_KEY").set_value("session-test-only")
    button(app, "Apply keys").click().run()
    assert not app.exception and not (managed / "credentials.json").exists()
    assert (
        app.session_state["_local_session_keys"]["THREATFOX_AUTH_KEY"]
        == "session-test-only"
    )
    app.text_input(key="local_key_URLHAUS_AUTH_KEY").set_value("saved-test-only")
    next(c for c in app.checkbox if c.label == "Save keys on this computer").check()
    button(app, "Apply keys").click().run()
    assert not app.exception
    assert workspace.load_credentials(managed) == {
        "URLHAUS_AUTH_KEY": "saved-test-only"
    }
    assert "saved-test-only" not in "\n".join(str(c.value) for c in app.caption)
    button(app, "Forget saved and session keys").click().run()
    assert not app.exception and workspace.load_credentials(managed) == {}


def test_manual_refresh_uses_session_keys_and_exposes_only_safe_status(
    managed, monkeypatch
):
    seen = []

    def refresh(path, **kwargs):
        seen.append(kwargs["threatfox_key"])
        kwargs["progress"]("ThreatFox", "failed", "private-url-key")
        return (CTIRefreshOutcome("ThreatFox", "failed", detail="private-url-key"),)

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    app = local_app(managed)
    app.session_state["_local_session_keys"] = {
        "THREATFOX_AUTH_KEY": "session-only-key"
    }
    button(app, "Update CTI now").click().run(timeout=15)
    assert not app.exception and seen == ["session-only-key"]
    assert "private-url-key" not in "\n".join(str(c.value) for c in app.caption)
    assert any("previous cache preserved" in str(w.value) for w in app.warning)
    assert not (managed / "credentials.json").exists()


def test_auto_update_is_explicit_and_interval_is_saved(managed):
    app = local_app(managed)
    assert not workspace.load_settings(managed)["automatic"]
    next(
        c
        for c in app.checkbox
        if c.label == "Automatic updates while the app is running"
    ).check()
    next(c for c in app.selectbox if c.label == "Update interval (hours)").select(12)
    button(app, "Save update settings").click().run()
    assert not app.exception
    assert workspace.load_settings(managed) == {
        "mode": "cti-only",
        "interval_hours": 12,
        "automatic": True,
    }


def test_other_sessions_mode_changes_are_respected(managed):
    app = local_app(managed)
    workspace.save_settings(managed, mode="demo", interval_hours=6, automatic=False)
    app.run()
    assert not app.exception
    assert workspace.load_settings(managed)["mode"] == "demo"
    assert app.selectbox(key="local_mode").value == "demo"
