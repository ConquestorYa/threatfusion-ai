"""Setup & CTI updates from the loopback API (managed installation)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings, resolve_settings
from threatfusion.local_workspace import load_settings

ORIGIN = "http://127.0.0.1:8600"
HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}


@pytest.fixture
def install(tmp_path):
    from scripts.demo_review_snapshot import main

    root = tmp_path / "install"
    assert main(["--managed", str(root)]) == 0
    return root


@pytest.fixture
def client(install):
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(install), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    return TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)


def test_state_mirrors_the_streamlit_setup_page(client):
    body = client.get("/api/setup").json()
    assert body["state"] == "ok" and body["mode"]["value"] == "cti-only"
    assert body["keys"]["saved"] == "Saved keys: None"
    assert "Missing now: ThreatFox, URLhaus." in body["keys"]["missing"]
    cti = body["cti"]
    assert cti["running"] is False and cti["progress"] is None
    assert [b["text"] for b in cti["status"]][1:4] == [
        "SGB · Cache still fresh", "ThreatFox: skipped (no API key).", "URLhaus: skipped (no API key)."]
    assert cti["summary"]["kind"] == "info"  # finished < 2 minutes ago, nothing downloaded
    assert body["schedule"]["options"] == [6, 12, 24] and body["schedule"]["automatic"] is False
    assert body["sources"]["columns"][0] == "Source" and body["sources"]["rows"][0][0] == "Synthetic demo"
    turkish = client.get("/api/setup", params={"lang": "tr"}).json()
    assert turkish["cti"]["button"] == "CTI verilerini şimdi güncelle"


def test_app_info_follows_streamlit_screen_rules(client, install):
    assert client.get("/api/app").json()["setup_available"] is True
    assert client.get("/api/app").json()["first_setup"] is False
    (install / "refresh-status.json").unlink()
    assert client.get("/api/app").json()["first_setup"] is True  # first run opens Setup
    developer = TestClient(create_app(lambda: ApiSettings(True, None, None), environment={}), base_url=ORIGIN)
    assert developer.get("/api/app").json()["setup_available"] is False
    assert developer.get("/api/setup").json() == {"state": "not_managed"}


def test_mode_and_schedule_are_saved_privately(client, install):
    assert client.put("/api/setup/schedule", json={"automatic": True, "interval_hours": 12}, headers=HEADERS).status_code == 204
    assert load_settings(install) == {"mode": "cti-only", "interval_hours": 12, "automatic": True}
    assert oct((install / "workspace.json").stat().st_mode & 0o777) == "0o600"
    assert client.put("/api/setup/schedule", json={"automatic": True, "interval_hours": 7}, headers=HEADERS).status_code == 422
    assert client.put("/api/setup/mode", json={"mode": "demo"}, headers=HEADERS).status_code == 204
    assert load_settings(install) == {"mode": "demo", "interval_hours": 12, "automatic": True}
    demo = client.get("/api/setup").json()
    assert "keys" not in demo and demo["demo_note"].startswith("Demo data is synthetic")
    assert client.post("/api/setup/refresh", json={}, headers=HEADERS).status_code == 404
    assert client.put("/api/setup/mode", json={"mode": "cti-only"}, headers=HEADERS).status_code == 204


def test_refresh_uses_saved_keys_only_and_is_one_shot(client, install, monkeypatch):
    calls = []

    def fake(root, credentials=None, *, force=False):
        calls.append((root, credentials, force))
        return True

    monkeypatch.setattr("threatfusion.local_workspace.start_background_refresh", fake)
    response = client.post("/api/setup/refresh", json={"force": True}, headers=HEADERS)
    assert response.json() == {"started": True}
    assert calls == [(install, {}, True)]


def test_writes_are_refused_cross_site_and_reads_need_loopback(client):
    for method, path, body in (("put", "/api/setup/mode", {"mode": "demo"}),
                               ("put", "/api/setup/schedule", {"automatic": True, "interval_hours": 6}),
                               ("post", "/api/setup/refresh", {"force": True})):
        response = getattr(client, method)(path, json=body, headers={"Origin": "https://evil.example"})
        assert response.status_code == 403
    assert client.get("/api/setup", headers={"Host": "evil.example"}).status_code == 403


def test_running_refresh_shows_progress(client, install):
    import os

    status = json.loads((install / "refresh-status.json").read_text())
    status.update(running=True, pid=os.getpid(), progress={"percent": 40, "completed": 2, "total": 5,
                                                           "source": "SGB", "stage": "downloading"})
    (install / "refresh-status.json").write_text(json.dumps(status))
    cti = client.get("/api/setup").json()["cti"]
    assert cti["running"] is True and cti["progress"]["percent"] == 40
    assert cti["progress"]["label"].startswith("Updating CTI sources: 2/5 finished · 40%")
    assert cti["due"] is None
