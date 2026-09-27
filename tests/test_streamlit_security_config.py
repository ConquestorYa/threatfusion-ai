from pathlib import Path
import tomllib


def test_streamlit_hides_uncaught_exception_details() -> None:
    config_path = Path(".streamlit/config.toml")
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))

    assert config["client"]["showErrorDetails"] == "none"
