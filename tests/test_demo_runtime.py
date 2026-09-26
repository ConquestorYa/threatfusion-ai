from __future__ import annotations

import socket

import pytest

from threatfusion.cti_cache import load_ioc_records
from threatfusion.demo_runtime import (
    build_public_demo_model_samples,
    create_public_demo_runtime,
)
from threatfusion.ml_artifact import load_trusted_ml_artifact


def test_public_demo_model_samples_are_balanced_and_synthetic() -> None:
    samples = build_public_demo_model_samples(40)

    assert len(samples) == 80
    assert sum(sample.label == 0 for sample in samples) == 40
    assert sum(sample.label == 1 for sample in samples) == 40
    assert {sample.source for sample in samples} == {"ThreatFusion Demo"}
    assert all(
        sample.domain.endswith(("example.com", "example.net"))
        for sample in samples
    )


def test_public_demo_model_samples_require_minimum_size() -> None:
    with pytest.raises(ValueError, match="at least 30"):
        build_public_demo_model_samples(29)


def test_public_demo_runtime_contains_cti_and_loadable_model(tmp_path) -> None:
    output = tmp_path / "runtime"

    db_path, model_dir = create_public_demo_runtime(output)

    records = load_ioc_records(db_path)
    artifact = load_trusted_ml_artifact(model_dir)

    assert len(records) == 4
    assert {record.source for record in records} == {"ThreatFusion Demo"}
    assert artifact.metadata.evaluation_status == "development_only"
    assert (model_dir / "model.joblib").exists()
    assert (model_dir / "metadata.json").exists()


def test_public_demo_runtime_refuses_nonempty_output(tmp_path) -> None:
    output = tmp_path / "runtime"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError, match="overwrite"):
        create_public_demo_runtime(output)

    assert marker.read_text(encoding="utf-8") == "keep"


def test_public_demo_runtime_overwrite_rebuilds_cleanly(tmp_path) -> None:
    output = tmp_path / "runtime"
    output.mkdir()
    marker = output / "stale.txt"
    marker.write_text("stale", encoding="utf-8")

    db_path, model_dir = create_public_demo_runtime(
        output,
        overwrite=True,
    )

    assert db_path.exists()
    assert model_dir.exists()
    assert not marker.exists()


def test_public_demo_runtime_generation_does_not_network(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("public demo runtime generation must not network")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    db_path, model_dir = create_public_demo_runtime(tmp_path / "runtime")

    assert db_path.exists()
    assert model_dir.exists()
