"""Deployment-only public demo configuration; no live CTI collection."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from pathlib import Path

from .ml_artifact import load_trusted_ml_artifact


def render_public_demo_proxy(
    template: str, port: str, trusted_proxies: str = ""
) -> str:
    try:
        parsed_port = int(port)
    except ValueError as error:
        raise ValueError("PORT must be an integer") from error
    if not 1024 <= parsed_port <= 65535 or parsed_port == 8501:
        raise ValueError("PORT must be an unprivileged port other than 8501")
    networks = [
        ipaddress.ip_network(value.strip(), strict=True)
        for value in trusted_proxies.split(",")
        if value.strip()
    ]
    if any(network.prefixlen == 0 for network in networks):
        raise ValueError("trusting all proxy addresses is not permitted")
    directives = "\n    ".join(f"set_real_ip_from {network};" for network in networks)
    if networks:
        directives += "\n    real_ip_header X-Forwarded-For;\n    real_ip_recursive on;"
    return template.replace("__PORT__", str(parsed_port)).replace(
        "__TRUSTED_PROXIES__",
        directives,
    )


def public_demo_environment(
    runtime_dir: Path,
    expected_checksum_path: Path,
    environment: Mapping[str, str],
) -> dict[str, str]:
    """Pin the demo model against a separate build-owned trust file."""
    runtime = runtime_dir.resolve()
    checksum_path = expected_checksum_path.resolve()
    if checksum_path.is_relative_to(runtime):
        raise ValueError("expected checksum must be outside the runtime bundle")
    model_dir = runtime / "models/development-001"
    expected = checksum_path.read_text(encoding="ascii").strip()
    artifact = load_trusted_ml_artifact(model_dir, expected_checksum=expected)
    if artifact.metadata.evaluation_status != "demo_only_synthetic":
        raise ValueError("public demo hosting requires a synthetic demo artifact")
    if not (runtime / "threatfusion.sqlite").is_file():
        raise ValueError("synthetic demo CTI cache is missing")
    values = dict(environment)
    values.update(
        {
            "THREATFUSION_PUBLIC_MODE": "1",
            "THREATFUSION_CTI_ONLY": "0",
            "THREATFUSION_DB_PATH": str(runtime / "threatfusion.sqlite"),
            "THREATFUSION_MODEL_DIR": str(model_dir),
            "THREATFUSION_MODEL_SHA256": expected,
            # Ignore a developer's local report setting in this presentation service.
            "THREATFUSION_EVALUATION_REPORT": str(
                runtime / "no-evaluation-report.json"
            ),
        }
    )
    for key in ("THREATFOX_AUTH_KEY", "URLHAUS_AUTH_KEY", "PHISHTANK_APP_KEY"):
        values.pop(key, None)
    return values
