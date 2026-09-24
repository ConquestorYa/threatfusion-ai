from pathlib import Path

import pytest

from threatfusion.app_config import load_app_config


def test_default_config_is_local_mode() -> None:
    config = load_app_config({})

    assert config.db_path == Path("data/threatfusion.sqlite")
    assert config.model_dir == Path("data/models/development-001")
    assert config.public_mode is False
    assert config.history_enabled is True


def test_public_mode_disables_history_and_supports_custom_paths() -> None:
    config = load_app_config(
        {
            "THREATFUSION_PUBLIC_MODE": "true",
            "THREATFUSION_DB_PATH": "/runtime/threatfusion.sqlite",
            "THREATFUSION_MODEL_DIR": "/runtime/model",
        }
    )

    assert config.public_mode is True
    assert config.history_enabled is False
    assert config.db_path == Path("/runtime/threatfusion.sqlite")
    assert config.model_dir == Path("/runtime/model")


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
