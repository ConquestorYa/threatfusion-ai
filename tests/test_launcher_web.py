"""The launcher opens the pre-built React workspace and its API, and Stop ends it (DEC-108)."""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from threatfusion import local_setup

REPO = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux launcher and Unix control socket")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_web_page_ships_with_the_source():
    """Installations download the source archive; the page must be in it, built and self-contained."""
    dist = local_setup.web_page_dir(REPO)
    index = (dist / "index.html").read_text()
    assets = [part.split('"', 1)[0] for part in index.split('="/assets/')[1:]]
    assert assets and all((dist / "assets" / name).is_file() for name in assets)
    assert "http://" not in index and "https://" not in index  # no CDN: fonts and scripts are local
    assert '<script src="/theme-init.js"></script>' in index  # dark before first paint (CSP: no inline script)
    tracked = subprocess.run(["git", "ls-files", "web/dist"], cwd=REPO, capture_output=True, text=True, check=True)
    assert "web/dist/index.html" in tracked.stdout.split()
    assert not list(dist.rglob("*.map"))


def test_launcher_commands_are_loopback_only():
    command = local_setup.api_command(REPO, 8600)
    assert command[1:5] == ["-m", "threatfusion.api", "--port", "8600"]
    assert command[-1] == str(REPO / "web" / "dist") and "--host" not in command


def test_missing_page_falls_back_to_streamlit(tmp_path, monkeypatch, capsys):
    started = []

    class Stop(Exception):
        pass

    def popen(command, **kwargs):
        started.append(command)
        raise Stop

    monkeypatch.setattr(local_setup.subprocess, "Popen", popen)
    monkeypatch.setattr(local_setup.signal, "signal", lambda *args: None)
    with pytest.raises(Stop):
        local_setup.run_local_server(tmp_path, {}, port=_free_port(), open_browser=False)
    assert "streamlit" in started[0] and "Streamlit arayüzü açılıyor" in capsys.readouterr().out
    with pytest.raises(ValueError):
        local_setup.run_local_server(tmp_path, {}, interface="other")


def test_real_launcher_serves_the_page_and_stops_from_the_setup_button(tmp_path):
    from scripts.demo_review_snapshot import main

    root = tmp_path / "install"
    assert main(["--managed", str(root)]) == 0
    port = _free_port()
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(REPO / 'src')!r})\n"
        "from pathlib import Path\n"
        "from threatfusion.local_setup import prepare_local_environment, run_local_server\n"
        f"root = Path({str(root)!r})\n"
        "environment = prepare_local_environment(root, 'cti-only', {})\n"
        f"raise SystemExit(run_local_server(Path({str(REPO)!r}), environment, port={port}, "
        "open_browser=False, install_dir=root))\n"
    )
    process = subprocess.Popen([sys.executable, "-c", script], cwd=tmp_path, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    url = f"http://127.0.0.1:{port}"
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        deadline = time.monotonic() + 60
        while True:
            assert process.poll() is None, process.stdout.read()
            try:
                with http.open(url + "/api/health", timeout=1) as response:
                    if json.loads(response.read()) == {"status": "ok"}:
                        break
            except OSError:
                pass
            assert time.monotonic() < deadline, "launcher did not become ready"
            time.sleep(0.2)
        with http.open(url + "/", timeout=5) as response:
            assert '<div id="root">' in response.read().decode()
        with http.open(url + "/api/app", timeout=5) as response:
            assert json.loads(response.read())["setup_available"] is True
        assert local_setup.request_local_control(root, "status") == {"running": True, "url": url}
        stop = urllib.request.Request(url + "/api/app/stop", data=b"{}", method="POST", headers={
            "Content-Type": "application/json", "Origin": url, "Sec-Fetch-Site": "same-origin"})
        with http.open(stop, timeout=5) as response:
            assert json.loads(response.read()) == {"stopping": True}
        assert process.wait(timeout=30) == 0
        output = process.stdout.read()
        assert "[4/4] Uygulama hazır" in output and "Traceback" not in output
        with socket.socket() as client:
            assert client.connect_ex(("127.0.0.1", port)) != 0, "orphan server"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


def test_stop_outside_the_launcher_reports_not_running(tmp_path):
    from fastapi.testclient import TestClient
    from scripts.demo_review_snapshot import main

    from threatfusion.api.app import create_app
    from threatfusion.api.settings import ApiSettings, resolve_settings

    root = tmp_path / "install"
    assert main(["--managed", str(root)]) == 0
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(root), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    origin = "http://127.0.0.1:8600"
    headers = {"Origin": origin, "Sec-Fetch-Site": "same-origin"}
    client = TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=origin)
    assert client.post("/api/app/stop", json={}, headers=headers).json() == {"stopping": False}
    assert client.post("/api/app/stop", json={}).status_code == 403  # cross-site pages cannot stop it
    unmanaged = TestClient(create_app(lambda: ApiSettings(True, None, None), environment={}), base_url=origin)
    assert unmanaged.post("/api/app/stop", json={}, headers=headers).status_code == 404
