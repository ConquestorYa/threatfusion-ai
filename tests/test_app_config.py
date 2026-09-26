from datetime import timedelta
from pathlib import Path

import pytest

from threatfusion.app_config import load_app_config


def test_default_config_is_local_mode() -> None:
    config = load_app_config({})

    assert config.db_path == Path("data/threatfusion.sqlite")
    assert config.model_dir == Path("data/models/development-001")
    assert config.evaluation_report_path == Path(
        "data/evaluation/final_holdout.json"
    )
    assert config.public_mode is False
    assert config.history_enabled is True
    assert config.cti_stale_after_by_source == {
        "ThreatFox": timedelta(hours=24),
        "URLhaus": timedelta(hours=24),
        "SGB": timedelta(hours=24),
        "PhishTank": timedelta(hours=6),
    }


def test_public_mode_disables_history_and_supports_custom_paths() -> None:
    config = load_app_config(
        {
            "THREATFUSION_PUBLIC_MODE": "true",
            "THREATFUSION_DB_PATH": "/runtime/threatfusion.sqlite",
            "THREATFUSION_MODEL_DIR": "/runtime/model",
            "THREATFUSION_EVALUATION_REPORT": "/runtime/evaluation/final_holdout.json",
        }
    )

    assert config.public_mode is True
    assert config.history_enabled is False
    assert config.db_path == Path("/runtime/threatfusion.sqlite")
    assert config.model_dir == Path("/runtime/model")
    assert config.evaluation_report_path == Path(
        "/runtime/evaluation/final_holdout.json"
    )


@pytest.mark.parametrize("value", ["1", "TRUE", "yes", "On"])
def test_truthy_public_mode_values(value: str) -> None:
    assert load_app_config({"THREATFUSION_PUBLIC_MODE": value}).public_mode


@pytest.mark.parametrize("value", ["0", "FALSE", "no", "Off"])
def test_false_public_mode_values(value: str) -> None:
    assert not load_app_config({"THREATFUSION_PUBLIC_MODE": value}).public_mode


def test_invalid_public_mode_value_is_rejected() -> None:
    with pytest.raises(ValueError, match="boolean"):
        load_app_config({"THREATFUSION_PUBLIC_MODE": "sometimes"})


def test_empty_runtime_path_is_rejected() -> None:
    with pytest.raises(ValueError, match="THREATFUSION_DB_PATH"):
        load_app_config({"THREATFUSION_DB_PATH": "   "})



def test_empty_evaluation_report_path_is_rejected() -> None:
    with pytest.raises(ValueError, match="THREATFUSION_EVALUATION_REPORT"):
        load_app_config({"THREATFUSION_EVALUATION_REPORT": "   "})

def test_cti_source_freshness_thresholds_are_configurable() -> None:
    config = load_app_config(
        {
            "THREATFUSION_CTI_STALE_HOURS_THREATFOX": "6",
            "THREATFUSION_CTI_STALE_HOURS_URLHAUS": "12.5",
            "THREATFUSION_CTI_STALE_HOURS_SGB": "48",
            "THREATFUSION_CTI_STALE_HOURS_PHISHTANK": "3",
        }
    )

    assert config.cti_stale_after_by_source == {
        "ThreatFox": timedelta(hours=6),
        "URLhaus": timedelta(hours=12.5),
        "SGB": timedelta(hours=48),
        "PhishTank": timedelta(hours=3),
    }


@pytest.mark.parametrize("value", ["0", "-1", "not-a-number"])
def test_invalid_cti_freshness_threshold_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="positive number"):
        load_app_config(
            {"THREATFUSION_CTI_STALE_HOURS_THREATFOX": value}
        )

