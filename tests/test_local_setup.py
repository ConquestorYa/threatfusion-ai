from __future__ import annotations

import hashlib
import io
import socket
from dataclasses import replace
from pathlib import Path

import pytest

from threatfusion import local_setup
from threatfusion.cti_cache import load_ioc_records, replace_source_records
from threatfusion.cti_refresh import CTIRefreshOutcome
from threatfusion.models import IOCRecord, IOCType


def test_demo_first_run_is_offline_private_and_repeatable(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("first run must not collect external CTI")

    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(local_setup, "refresh_configured_sources", no_network)
    inherited = {
        "PATH": "keep",
        "THREATFUSION_DB_PATH": "/private/developer.sqlite",
        "THREATFUSION_MODEL_DIR": "/private/experimental-model",
        "THREATFUSION_MODEL_SHA256": "untrusted",
        "THREATFUSION_EVALUATION_REPORT": "/private/holdout.json",
        "STREAMLIT_SERVER_ADDRESS": "0.0.0.0",
        "THREATFOX_AUTH_KEY": "private-key",
        "URLHAUS_AUTH_KEY": "private-key",
        "PHISHTANK_APP_KEY": "private-key",
    }
    first = local_setup.prepare_local_environment(tmp_path, "demo", inherited)
    model = tmp_path / "runtime/demo/bundle/models/development-001/model.joblib"
    checksum = hashlib.sha256(model.read_bytes()).hexdigest()
    second = local_setup.prepare_local_environment(tmp_path, "demo", inherited)
    assert first == second
    assert first["PATH"] == "keep"
    assert first["THREATFUSION_PUBLIC_MODE"] == "1"
    assert first["THREATFUSION_CTI_ONLY"] == "0"
    assert (
        first["THREATFUSION_MODEL_SHA256"]
        == (tmp_path / "runtime/demo/trusted-model.sha256").read_text().strip()
    )
    assert not any("AUTH_KEY" in name or "APP_KEY" in name for name in first)
    assert "STREAMLIT_SERVER_ADDRESS" not in first
    assert first["THREATFUSION_DB_PATH"].startswith(str(tmp_path))
    assert hashlib.sha256(model.read_bytes()).hexdigest() == checksum
    assert len(load_ioc_records(first["THREATFUSION_DB_PATH"])) == 4


@pytest.mark.parametrize("damaged", ["model", "pin", "database"])
def test_corrupt_existing_demo_is_preserved_and_refused(tmp_path, damaged):
    values = local_setup.prepare_local_environment(tmp_path, "demo", {})
    paths = {
        "model": tmp_path / "runtime/demo/bundle/models/development-001/model.joblib",
        "pin": tmp_path / "runtime/demo/trusted-model.sha256",
        "database": tmp_path / "runtime/demo/bundle/threatfusion.sqlite",
    }
    path = paths[damaged]
    if damaged == "database":
        path.unlink()
    else:
        path.write_bytes(b"corrupt existing data")
    with pytest.raises((ValueError, OSError)):
        local_setup.prepare_local_environment(tmp_path, "demo", {})
    if damaged == "database":
        assert not path.exists()
    else:
        assert path.read_bytes() == b"corrupt existing data"
    assert values["THREATFUSION_CTI_ONLY"] == "0"


def test_real_model_cannot_be_selected_as_demo(tmp_path, monkeypatch):
    local_setup.prepare_local_environment(tmp_path, "demo", {})
    original = local_setup.load_trusted_ml_artifact

    def real_model(*args, **kwargs):
        artifact = original(*args, **kwargs)
        return replace(
            artifact, metadata=replace(artifact.metadata, evaluation_status="evaluated")
        )

    monkeypatch.setattr(local_setup, "load_trusted_ml_artifact", real_model)
    with pytest.raises(ValueError, match="synthetic-only"):
        local_setup.prepare_local_environment(tmp_path, "demo", {})


def test_cti_mode_has_no_ml_and_preserves_its_data_across_modes(tmp_path, monkeypatch):
    def reject_model(*args, **kwargs):
        raise AssertionError("cti-only cannot load a model")

    with monkeypatch.context() as context:
        context.setattr(local_setup, "load_trusted_ml_artifact", reject_model)
        values = local_setup.prepare_local_environment(tmp_path, "cti-only", {})
    db = values["THREATFUSION_DB_PATH"]
    replace_source_records(
        db, "Test", [IOCRecord("private.example", IOCType.DOMAIN, "Test")]
    )
    assert values["THREATFUSION_CTI_ONLY"] == "1"
    assert "THREATFUSION_MODEL_SHA256" not in values
    assert not (tmp_path / "runtime/cti/no-ml-artifact").exists()
    local_setup.prepare_local_environment(tmp_path, "demo", {})
    again = local_setup.prepare_local_environment(tmp_path, "cti-only", {})
    assert again == values
    assert [item.value for item in load_ioc_records(db)] == ["private.example"]


def test_refresh_never_prints_credential_bearing_errors(tmp_path, monkeypatch, capsys):
    secret = "https://upstream.example/private-api-key"

    def refresh(db, **kwargs):
        assert kwargs["threatfox_key"] == "private-api-key"
        kwargs["progress"]("ThreatFox", "failed", secret)
        return [
            CTIRefreshOutcome(
                "ThreatFox", "failed", error_type="HTTPError", detail=secret
            ),
            CTIRefreshOutcome("SGB", "refreshed", record_count=3),
            CTIRefreshOutcome("PhishTank", "fresh"),
        ]

    monkeypatch.setattr(local_setup, "refresh_configured_sources", refresh)
    local_setup.refresh_local_cti(tmp_path, {"THREATFOX_AUTH_KEY": "private-api-key"})
    output = capsys.readouterr().out
    assert "private-api-key" not in output
    assert "https://" not in output
    assert "HTTPError" in output
    assert "API anahtarı yok" in output
    assert "3 kayıt" in output


@pytest.mark.parametrize("mode", ["unknown", "", "experimental"])
def test_invalid_mode_cannot_create_data(tmp_path, mode):
    with pytest.raises(ValueError):
        local_setup.prepare_local_environment(tmp_path, mode, {})
    assert not (tmp_path / "runtime").exists()


@pytest.mark.parametrize("port", [0, 80, 1023, 65536])
def test_invalid_ports_are_refused(port):
    with pytest.raises(ValueError):
        local_setup.choose_local_port(port)


def test_busy_port_is_refused_without_stopping_its_owner():
    with socket.socket() as existing:
        existing.bind(("127.0.0.1", 0))
        port = existing.getsockname()[1]
        with pytest.raises(ValueError, match="busy"):
            local_setup.choose_local_port(port)
        assert existing.getsockname()[1] == port


def test_default_port_falls_back_and_command_is_loopback_only(monkeypatch):
    binds = []

    class Listener:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            binds.append(address)
            if address[1] == 8501:
                raise OSError("busy")

    monkeypatch.setattr(socket, "socket", lambda *args: Listener())
    assert local_setup.choose_local_port() == 8502
    assert binds == [("127.0.0.1", 8501), ("127.0.0.1", 8502)]
    command = local_setup.streamlit_command(Path("source"), 8502)
    assert "--server.address=127.0.0.1" in command
    assert "--server.enableXsrfProtection=true" in command
    assert "--browser.gatherUsageStats=false" in command


@pytest.mark.parametrize("healthy", [True, False])
def test_browser_waits_for_health_and_child_is_stopped(tmp_path, monkeypatch, healthy):
    calls = []

    class Process:
        pid = 123456

        def poll(self):
            return None

        def wait(self, **kwargs):
            calls.append("wait")
            return 0

    class Event:
        def __init__(self):
            self.count = 0

        def wait(self, interval):
            self.count += 1
            return self.count > 1

        def is_set(self):
            return False

    class Response(io.BytesIO):
        status = 200

    class HTTP:
        def open(self, *args, **kwargs):
            calls.append("health")
            return Response(b"ok" if healthy else b"failed")

    monkeypatch.setattr(local_setup, "choose_local_port", lambda port: 18501)
    monkeypatch.setattr(local_setup.threading, "Event", Event)
    monkeypatch.setattr(
        local_setup.subprocess, "Popen", lambda *args, **kwargs: Process()
    )
    monkeypatch.setattr(
        local_setup.urllib.request, "build_opener", lambda *args: HTTP()
    )
    monkeypatch.setattr(local_setup.signal, "signal", lambda *args: None)
    monkeypatch.setattr(
        local_setup.os, "killpg", lambda *args: calls.append("stop"), raising=False
    )

    def browser(url):
        assert calls == ["health"]
        assert url == "http://127.0.0.1:18501"
        calls.append("browser")
        raise OSError("headless desktop")

    monkeypatch.setattr(local_setup.webbrowser, "open", browser)
    if healthy:
        assert local_setup.run_local_server(tmp_path, {}, readiness_timeout=0) == 0
        assert "browser" in calls
    else:
        with pytest.raises(RuntimeError, match="ready in time"):
            local_setup.run_local_server(tmp_path, {}, readiness_timeout=0)
        assert "browser" not in calls
    assert calls[-2:] == ["stop", "wait"]
