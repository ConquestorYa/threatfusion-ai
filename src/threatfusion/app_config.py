from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    db_path: Path
    model_dir: Path
    evaluation_report_path: Path
    public_mode: bool
    model_sha256: str | None
    cti_stale_hours_by_source: tuple[tuple[str, float], ...]
    cti_only: bool = False

    @property
    def history_enabled(self) -> bool:
        return not self.public_mode and not self.cti_only

    @property
    def cti_stale_after_by_source(self) -> dict[str, timedelta]:
        return {
            source: timedelta(hours=hours)
            for source, hours in self.cti_stale_hours_by_source
        }


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


def _optional_sha256(
    environment: Mapping[str, str],
    name: str,
) -> str | None:
    raw = environment.get(name)
    if raw is None or not raw.strip():
        return None
    normalized = raw.strip().casefold()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{name} must be a 64-character SHA-256 hex digest")
    return normalized


def _positive_float(
    environment: Mapping[str, str],
    name: str,
    default: float,
) -> float:
    raw = environment.get(name)
    if raw is None:
        return default
    try:
        value = float(raw.strip())
    except ValueError as error:
        raise ValueError(f"{name} must be a positive number") from error
    if value <= 0:
        raise ValueError(f"{name} must be a positive number")
    return value


def load_app_config(
    environment: Mapping[str, str] | None = None,
) -> AppConfig:
    """Load non-secret dashboard/runtime configuration from environment."""
    values = os.environ if environment is None else environment
    public_mode = _parse_bool(
        values.get("THREATFUSION_PUBLIC_MODE"),
        default=False,
    )
    model_sha256 = _optional_sha256(values, "THREATFUSION_MODEL_SHA256")
    cti_only = _parse_bool(values.get("THREATFUSION_CTI_ONLY"), default=False)
    if public_mode and not cti_only and model_sha256 is None:
        raise ValueError(
            "THREATFUSION_MODEL_SHA256 is required when "
            "THREATFUSION_PUBLIC_MODE=1"
        )

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
        public_mode=public_mode,
        model_sha256=model_sha256,
        cti_only=cti_only,
        cti_stale_hours_by_source=(
            (
                "ThreatFox",
                _positive_float(
                    values,
                    "THREATFUSION_CTI_STALE_HOURS_THREATFOX",
                    24.0,
                ),
            ),
            (
                "URLhaus",
                _positive_float(
                    values,
                    "THREATFUSION_CTI_STALE_HOURS_URLHAUS",
                    24.0,
                ),
            ),
            (
                "SGB",
                _positive_float(
                    values,
                    "THREATFUSION_CTI_STALE_HOURS_SGB",
                    24.0,
                ),
            ),
            ("PhishTank", 24.0),
        ),
    )
