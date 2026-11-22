from __future__ import annotations


import pytest
from threatfusion import local_workspace as workspace
from threatfusion import ui_local_settings as ui
from threatfusion.app_config import load_app_config
from threatfusion.cti_cache import initialize_cti_cache



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


def wait_finished(root, timeout=10):
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = workspace.read_private_json(root / "refresh-status.json")
        if status.get("finished_at") and not status.get("running"):
            return status
        time.sleep(0.05)
    raise AssertionError("background refresh did not finish")


@pytest.mark.parametrize("outcomes,failed,kind,text", [
    ([("ThreatFox", "fresh"), ("SGB", "fresh")], False, "info", "already up to date"),
    ([("URLhaus", "failed"), ("SGB", "failed")], False, "warning", "No CTI source could be reached"),
    ([("SGB", "refreshed"), ("ThreatFox", "failed")], False, "warning", "finished with problems"),
    ([("SGB", "refreshed")], False, "success", "1 source(s) downloaded"),
    ([], True, "warning", "update failed"),
])
def test_refresh_result_summary_explains_the_outcome(outcomes, failed, kind, text):
    status = {"failed": failed, "outcomes": [
        {"source": o[0], "status": o[1], "record_count": 0} for o in outcomes]}
    assert ui._refresh_summary(status)[0] == kind and text in ui._refresh_summary(status)[1]


def test_lookup_validation_messages_have_turkish_translations():
    import re
    from pathlib import Path
    from threatfusion.i18n import _TR
    sources = "".join(Path("src/threatfusion", name).read_text() for name in ("quick_lookup.py", "normalization.py"))
    messages = set(re.findall(r'raise ValueError\("([^"]+)"\)', sources))
    assert len(messages) >= 10 and not messages - set(_TR)


