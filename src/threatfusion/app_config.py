from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    db_path: Path
    model_dir: Path
    evaluation_report_path: Path
    public_mode: bool

    @property
    def history_enabled(self) -> bool:
        return not self.public_mode


_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError("boolean environment value is invalid")


def _path_value(
    environment: Mapping[str, str],
    name: str,
    default: str,
) -> Path:
    raw = environment.get(name, default).strip()
    if not raw:
        raise ValueError(f"{name} must not be empty")
    return Path(raw)


def load_app_config(
    environment: Mapping[str, str] | None = None,
) -> AppConfig:
    """Load non-secret dashboard/runtime configuration from environment."""
    values = os.environ if environment is None else environment
    return AppConfig(
        db_path=_path_value(
            values,
            "THREATFUSION_DB_PATH",
            "data/threatfusion.sqlite",
        ),
        model_dir=_path_value(
            values,
            "THREATFUSION_MODEL_DIR",
            "data/models/development-001",
        ),
        evaluation_report_path=_path_value(
            values,
            "THREATFUSION_EVALUATION_REPORT",
            "data/evaluation/final_holdout.json",
        ),
        public_mode=_parse_bool(
            values.get("THREATFUSION_PUBLIC_MODE"),
            default=False,
        ),
    )
