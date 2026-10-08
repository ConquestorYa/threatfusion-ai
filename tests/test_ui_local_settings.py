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
    wait_finished(managed)
    app.run(timeout=15)
    assert not app.exception and seen == ["session-only-key"]
    assert "private-url-key" not in "\n".join(str(c.value) for c in app.caption)
    assert any("previous cache preserved" in str(w.value) for w in app.warning)
    assert not (managed / "credentials.json").exists()


def wait_finished(root, timeout=10):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = workspace.read_private_json(root / "refresh-status.json")
        if status.get("finished_at") and not status.get("running"):
            return status
        time.sleep(0.05)
    raise AssertionError("background refresh did not finish")


def test_running_update_survives_reruns_disables_button_and_shows_progress(managed, monkeypatch):
    import threading
    release, started, calls = threading.Event(), threading.Event(), []

    def refresh(path, **kwargs):
        calls.append(1)
        kwargs["progress"]("PhishTank", "refreshed", "1 active records")
        started.set()
        assert release.wait(10)
        return (CTIRefreshOutcome("PhishTank", "refreshed", record_count=1),)

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    app = local_app(managed)
    button(app, "Update CTI now").click().run(timeout=15)
    assert started.wait(10)
    # A page interaction during the update used to abort it mid-source.
    app.run(timeout=15)
    assert button(app, "Update CTI now").disabled
    progress = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_local_settings import render_refresh_progress\n"
        f"render_refresh_progress(Path({str(managed)!r}))"
    ).run(timeout=15)
    bar = progress.get("progress")[0]
    assert "1/2 finished" in bar.proto.text and "50%" in bar.proto.text
    release.set()
    status = wait_finished(managed)
    assert calls == [1] and status["outcomes"][0]["status"] == "refreshed"
    assert "progress" not in status
    app.run(timeout=15)
    assert not button(app, "Update CTI now").disabled


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


def test_keyless_phishtank_outage_is_information_not_a_key_problem(managed, monkeypatch):
    def refresh(path, **kwargs):
        return (CTIRefreshOutcome("PhishTank", "failed", detail="redirected"),
                CTIRefreshOutcome("SGB", "refreshed", record_count=3))

    monkeypatch.setattr(workspace, "refresh_configured_sources", refresh)
    status = workspace.refresh_workspace(managed, credentials={})
    assert status["outcomes"][0] == {"source": "PhishTank", "status": "failed",
                                     "record_count": 0, "public_feed": True}
    app = local_app(managed)
    assert not app.exception
    assert any("public keyless feed is currently unavailable" in str(i.value) for i in app.info)
    assert not any("PhishTank" in str(w.value) for w in app.warning)
    keyed = workspace.refresh_workspace(managed, credentials={"PHISHTANK_APP_KEY": "own-app-key"})
    assert "public_feed" not in keyed["outcomes"][0]


@pytest.mark.parametrize("outcomes,failed,kind,text", [
    ([("ThreatFox", "fresh"), ("PhishTank", "failed", True), ("SGB", "fresh")], False, "info", "already up to date"),
    ([("PhishTank", "failed", True), ("SGB", "failed")], False, "warning", "No CTI source could be reached"),
    ([("SGB", "refreshed"), ("ThreatFox", "failed")], False, "warning", "finished with problems"),
    ([("SGB", "refreshed"), ("PhishTank", "failed", True)], False, "success", "1 source(s) downloaded"),
    ([], True, "warning", "update failed"),
])
def test_refresh_result_summary_explains_the_outcome(outcomes, failed, kind, text):
    status = {"failed": failed, "outcomes": [
        {"source": o[0], "status": o[1], "record_count": 0} | ({"public_feed": True} if len(o) > 2 else {})
        for o in outcomes]}
    assert ui._refresh_summary(status)[0] == kind and text in ui._refresh_summary(status)[1]


def test_force_option_reaches_the_source_refresh(managed, monkeypatch):
    seen = []
    monkeypatch.setattr(workspace, "refresh_configured_sources",
                        lambda path, **kwargs: seen.append(kwargs["force"]) or ())
    app = local_app(managed)
    next(c for c in app.checkbox if c.label == "Download again even if sources are still fresh").check()
    button(app, "Update CTI now").click().run(timeout=15)
    wait_finished(managed)
    assert seen == [True]
    workspace.refresh_workspace(managed, credentials={})
    assert seen == [True, False]


def test_offline_failures_do_not_blame_phishtank_or_keys(managed, monkeypatch):
    monkeypatch.setattr(workspace, "refresh_configured_sources", lambda path, **kwargs: (
        CTIRefreshOutcome("PhishTank", "failed"), CTIRefreshOutcome("SGB", "failed")))
    workspace.refresh_workspace(managed, credentials={})
    app = local_app(managed)
    text = "\n".join(str(w.value) for w in app.warning)
    assert "Check your internet connection or source availability" in text
    assert "your key" not in text
    assert not any("public keyless feed" in str(i.value) for i in app.info)


def test_lookup_validation_messages_have_turkish_translations():
    import re
    from pathlib import Path
    from threatfusion.i18n import _TR
    sources = "".join(Path("src/threatfusion", name).read_text() for name in ("quick_lookup.py", "normalization.py"))
    messages = set(re.findall(r'raise ValueError\("([^"]+)"\)', sources))
    assert len(messages) >= 10 and not messages - set(_TR)


def test_upstream_outage_reaches_source_card_and_sits_under_the_button(managed):
    from threatfusion.ui_components import source_status_html
    outcomes = [{"source": "SGB", "status": "refreshed", "record_count": 3},
                {"source": "PhishTank", "status": "failed", "record_count": 0, "public_feed": True}]
    workspace.write_private_json(managed / "refresh-status.json",
                                 {"attempted_at": "2026-10-08T20:00:00+00:00", "running": False,
                                  "finished_at": "2026-10-08T20:01:00+00:00", "outcomes": outcomes})
    assert ui.upstream_unavailable_sources(managed) == frozenset({"PhishTank"})
    row = {"Source": "PhishTank", "Status": "Not cached", "Records": None, "Age": "Unknown",
           "Upstream unavailable": True}
    assert "Public keyless feed currently unavailable from the source" in source_status_html(row)
    app = local_app(managed)
    labels = [getattr(e, "label", None) or str(getattr(e, "value", "")) for e in app.sidebar]
    note = next(i for i, v in enumerate(labels) if "public keyless feed" in v)
    assert labels.index("Update CTI now") < note < labels.index("Automatic updates while the app is running")


def test_offline_attempt_does_not_mark_public_feeds_as_upstream_outages(managed):
    workspace.write_private_json(managed / "refresh-status.json", {"outcomes": [
        {"source": "SGB", "status": "failed", "record_count": 0},
        {"source": "PhishTank", "status": "failed", "record_count": 0, "public_feed": True}]})
    assert ui.upstream_unavailable_sources(managed) == frozenset()
    (managed / "refresh-status.json").unlink()
    assert ui.upstream_unavailable_sources(managed) == frozenset()


def test_force_option_is_one_shot_and_disabled_while_running(managed, monkeypatch):
    seen = []
    monkeypatch.setattr(workspace, "refresh_configured_sources",
                        lambda path, **kwargs: seen.append(kwargs["force"]) or ())
    app = local_app(managed)

    def box():
        return next(c for c in app.checkbox if c.label == "Download again even if sources are still fresh")

    box().check()
    button(app, "Update CTI now").click().run(timeout=15)
    assert any("CTI update started" in str(t.value) for t in app.toast)
    wait_finished(managed)
    app.run(timeout=15)
    assert box().value is False
    button(app, "Update CTI now").click().run(timeout=15)
    wait_finished(managed)
    assert seen == [True, False]
