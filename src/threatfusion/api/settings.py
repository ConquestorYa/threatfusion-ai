"""Where the API finds its data, mirroring the Streamlit workspace."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class ApiSettings:
    """Resolved paths. ``state_dir`` is None when no collector is configured."""

    collector_available: bool
    state_dir: Path | None
    cti_db_path: Path | None
    # Quick lookup / Setup: the same runtime values Streamlit reads from AppConfig.
    public_mode: bool = False
    cti_only: bool = True
    model_dir: Path | None = None
    model_sha256: str | None = None
    local_root: Path | None = None
    # Model evaluation / Analysis history: the same AppConfig values as Streamlit.
    evaluation_report_path: Path | None = None
    history_enabled: bool = False
    cti_stale_hours_by_source: tuple = ()


@lru_cache(maxsize=4)
def _managed_config(root: Path, mode: str):
    """``ui_local_settings._mode_config`` without Streamlit's cache."""
    from ..app_config import load_app_config
    from ..local_setup import prepare_local_environment

    return load_app_config(prepare_local_environment(root, mode, {}))


def resolve_settings(environment: Mapping[str, str] | None = None) -> ApiSettings:
    """Same rule as the Streamlit page: a managed install in CTI-only mode, or
    a non-public developer configuration with THREATFUSION_COLLECTOR_STATE_DIR."""
    from ..app_config import load_app_config
    from ..local_workspace import load_settings, validate_root

    environment = os.environ if environment is None else environment
    install = environment.get("THREATFUSION_LOCAL_INSTALL_DIR")
    if install is not None and environment.get("THREATFUSION_LOCAL_LOOPBACK") == "1":
        root = validate_root(Path(install))
        mode = load_settings(root)["mode"]
        config = _managed_config(root, mode)
        available = mode == "cti-only"  # the synthetic demo has no collector
        return ApiSettings(available, root / "collector" if available else None, config.db_path,
                           public_mode=config.public_mode, cti_only=config.cti_only, model_dir=config.model_dir,
                           model_sha256=config.model_sha256, local_root=root,
                           evaluation_report_path=config.evaluation_report_path,
                           history_enabled=config.history_enabled,
                           cti_stale_hours_by_source=tuple(config.cti_stale_hours_by_source))
    config = load_app_config(dict(environment))
    if config.public_mode:
        return ApiSettings(False, None, config.db_path, public_mode=True, cti_only=config.cti_only,
                           model_dir=config.model_dir, model_sha256=config.model_sha256,
                           evaluation_report_path=config.evaluation_report_path,
                           history_enabled=config.history_enabled,
                           cti_stale_hours_by_source=tuple(config.cti_stale_hours_by_source))
    return ApiSettings(True, config.collector_state_dir, config.db_path, public_mode=False,
                       cti_only=config.cti_only, model_dir=config.model_dir, model_sha256=config.model_sha256,
                       evaluation_report_path=config.evaluation_report_path,
                       history_enabled=config.history_enabled,
                       cti_stale_hours_by_source=tuple(config.cti_stale_hours_by_source))
