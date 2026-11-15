"""Where the API finds the collector snapshot, mirroring the Streamlit workspace."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ApiSettings:
    """Resolved paths. ``state_dir`` is None when no collector is configured."""

    collector_available: bool
    state_dir: Path | None
    cti_db_path: Path | None


def resolve_settings(environment: Mapping[str, str] | None = None) -> ApiSettings:
    """Same rule as the Streamlit page: a managed install in CTI-only mode, or
    a non-public developer configuration with THREATFUSION_COLLECTOR_STATE_DIR."""
    from ..app_config import load_app_config
    from ..local_workspace import load_settings, validate_root

    environment = os.environ if environment is None else environment
    install = environment.get("THREATFUSION_LOCAL_INSTALL_DIR")
    if install is not None and environment.get("THREATFUSION_LOCAL_LOOPBACK") == "1":
        root = validate_root(Path(install))
        if load_settings(root)["mode"] != "cti-only":
            return ApiSettings(False, None, None)  # the synthetic demo has no collector
        return ApiSettings(True, root / "collector", root / "runtime/cti/threatfusion.sqlite")
    config = load_app_config(dict(environment))
    if config.public_mode:
        return ApiSettings(False, None, None)
    return ApiSettings(True, config.collector_state_dir, config.db_path)
