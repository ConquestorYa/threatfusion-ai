from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from threatfusion.demo_runtime import create_public_demo_runtime
from threatfusion.ml_artifact import (
    compute_ml_artifact_checksum,
    load_trusted_ml_artifact,
    write_ml_artifact,
)
from threatfusion.public_demo_hosting import (
    public_demo_environment,
    render_public_demo_proxy,
)


def test_proxy_configuration_ignores_forwarded_headers_unless_trust_is_configured():
    template = Path("deploy/public-demo/nginx.conf.template").read_text()
    direct = render_public_demo_proxy(template, "10000")
    assert "set_real_ip_from" not in direct
    assert "real_ip_header" not in direct
    assert "listen 10000;" in direct
    assert "proxy_request_buffering off" in direct
    assert "access_log off" in direct
    assert "limit_req_status 429" in direct
    proxied = render_public_demo_proxy(template, "10001", "10.0.0.0/8,173.245.48.0/20")
    assert "set_real_ip_from 10.0.0.0/8;" in proxied
    assert "real_ip_recursive on;" in proxied
    assert "__PORT__" not in proxied
    assert "__TRUSTED_PROXIES__" not in proxied


@pytest.mark.parametrize("port", ["bad", "80", "8501", "65536", "10000; return 200;"])
def test_proxy_refuses_unsafe_port(port):
    with pytest.raises(ValueError, match="PORT"):
        render_public_demo_proxy("__PORT__ __TRUSTED_PROXIES__", port)


@pytest.mark.parametrize(
    "proxies", ["0.0.0.0/0", "::/0", "10.0.0.1/8", "10.0.0.0/8; access_log on"]
)
def test_proxy_refuses_unsafe_proxy_trust(proxies):
    with pytest.raises(ValueError):
        render_public_demo_proxy("__PORT__ __TRUSTED_PROXIES__", "10000", proxies)


@pytest.fixture
def demo(tmp_path):
    runtime = tmp_path / "runtime"
    _, model = create_public_demo_runtime(runtime)
    pin = tmp_path / "build-owned.sha256"
    pin.write_text(compute_ml_artifact_checksum(model))
    return runtime, model, pin


def test_public_demo_forces_synthetic_public_paths_and_removes_feed_credentials(demo):
    runtime, model, pin = demo
    env = public_demo_environment(
        runtime,
        pin,
        {
            "PORT": "10000",
            "THREATFUSION_PUBLIC_MODE": "0",
            "THREATFUSION_CTI_ONLY": "1",
            "THREATFOX_AUTH_KEY": "...",
            "URLHAUS_AUTH_KEY": "...",
            "PHISHTANK_APP_KEY": "...",
            "THREATFUSION_EVALUATION_REPORT": "private-report.json",
        },
    )
    assert env["THREATFUSION_PUBLIC_MODE"] == "1"
    assert env["THREATFUSION_CTI_ONLY"] == "0"
    assert env["THREATFUSION_MODEL_DIR"] == str(model)
    assert env["THREATFUSION_MODEL_SHA256"] == pin.read_text()
    assert all(
        key not in env
        for key in ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY")
    )
    assert "private-report.json" not in env.values()


def test_public_demo_pin_must_be_outside_mutable_runtime(demo):
    runtime, model, _ = demo
    with pytest.raises(ValueError, match="outside"):
        public_demo_environment(runtime, model / "artifact.sha256", {})


def test_public_demo_rejects_bad_independent_pin(demo):
    runtime, _, pin = demo
    pin.write_text("a" * 64)
    with pytest.raises(ValueError, match="checksum"):
        public_demo_environment(runtime, pin, {})


def test_public_demo_refuses_real_development_artifact(demo):
    runtime, model, pin = demo
    artifact = load_trusted_ml_artifact(model)
    write_ml_artifact(
        replace(
            artifact,
            metadata=replace(artifact.metadata, evaluation_status="development_only"),
        ),
        model,
        overwrite=True,
    )
    pin.write_text(compute_ml_artifact_checksum(model))
    with pytest.raises(ValueError, match="synthetic"):
        public_demo_environment(runtime, pin, {})
