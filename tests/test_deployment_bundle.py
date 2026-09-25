from __future__ import annotations

import socket
import sqlite3
from datetime import datetime, timezone

import pytest

from threatfusion.cti_cache import load_ioc_records, replace_source_records
from threatfusion.deployment_bundle import create_deployment_bundle
from threatfusion.ml_artifact import (
    load_trusted_ml_artifact,
    train_selected_model_artifact,
    write_ml_artifact,
)
from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_evaluation_report import (
    FrozenHoldoutReport,
    HoldoutMetricReport,
    write_frozen_holdout_report,
)
from threatfusion.models import IOCRecord, IOCType


def make_model_samples(count_per_label: int = 30) -> list[DomainSample]:
    return [
        *[
            DomainSample(f"bad-{index:03d}.example", 1, "ThreatFox")
            for index in range(count_per_label)
        ],
        *[
            DomainSample(f"good-{index:03d}.example", 0, "Tranco")
            for index in range(count_per_label)
        ],
    ]


def make_evaluation_report(path):
    metric = HoldoutMetricReport(
        threshold=0.8,
        precision=0.5,
        recall=0.4,
        f1=0.4444,
        false_positive_rate=0.01,
        true_negative=99,
        false_positive=1,
        false_negative=6,
        true_positive=4,
    )
    report = FrozenHoldoutReport(
        schema_version=1,
        protocol="fresh_collection_disjoint",
        generated_at="2026-09-25T12:00:00+00:00",
        model_name="model-a",
        development_snapshot_date="2026-09-23",
        holdout_snapshot_date="2026-09-25",
        input_count=120,
        retained_count=110,
        overlap_removed=10,
        malicious_count=10,
        benign_count=100,
        high=metric,
        medium=metric,
        low=metric,
        source_recalls=(),
    )
    write_frozen_holdout_report(report, path)
    return path


def prepare_sources(tmp_path):
    source_db = tmp_path / "source.sqlite"
    refresh_time = datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc)

    replace_source_records(
        source_db,
        "ThreatFox",
        [IOCRecord("known.example", IOCType.DOMAIN, "ThreatFox")],
        refreshed_at=refresh_time,
    )
    replace_source_records(
        source_db,
        "SGB",
        [IOCRecord("203.0.113.8", IOCType.IPV4, "SGB")],
        refreshed_at=refresh_time,
    )

    with sqlite3.connect(source_db) as connection:
        connection.execute(
            "CREATE TABLE analysis_runs (id INTEGER PRIMARY KEY, secret TEXT)"
        )
        connection.execute(
            "INSERT INTO analysis_runs (secret) VALUES (?)",
            ("local-history-marker",),
        )
        connection.execute(
            """
            CREATE TABLE analyst_feedback (
                analysis_run_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                label TEXT NOT NULL,
                note TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO analyst_feedback (
                analysis_run_id,
                domain,
                label,
                note
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                1,
                "review.example",
                "uncertain",
                "private-analyst-note-marker",
            ),
        )

    model_dir = tmp_path / "model"
    artifact = train_selected_model_artifact(make_model_samples())
    write_ml_artifact(artifact, model_dir)

    return source_db, model_dir


def test_bundle_contains_cti_and_model_but_not_analysis_history(tmp_path) -> None:
    source_db, model_dir = prepare_sources(tmp_path)

    bundle = create_deployment_bundle(
        source_db,
        model_dir,
        tmp_path / "runtime",
    )

    assert bundle.db_path.exists()
    assert (bundle.model_dir / "model.joblib").exists()
    assert (bundle.model_dir / "metadata.json").exists()
    assert len(load_ioc_records(bundle.db_path)) == 2
    assert bundle.evaluation_report_path is None
    assert [status.source for status in bundle.cti_status] == [
        "SGB",
        "ThreatFox",
    ]
    load_trusted_ml_artifact(bundle.model_dir)

    with sqlite3.connect(bundle.db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        dump = "\n".join(connection.iterdump())

    assert "cti_records" in tables
    assert "cti_refreshes" in tables
    assert "analysis_runs" not in tables
    assert "analysis_assessments" not in tables
    assert "analyst_feedback" not in tables
    assert "local-history-marker" not in dump
    assert "private-analyst-note-marker" not in dump


def test_bundle_refuses_nonempty_output_without_overwrite(tmp_path) -> None:
    source_db, model_dir = prepare_sources(tmp_path)
    output = tmp_path / "runtime"
    output.mkdir()
    (output / "keep.txt").write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="overwrite"):
        create_deployment_bundle(source_db, model_dir, output)


def test_bundle_overwrite_replaces_existing_output(tmp_path) -> None:
    source_db, model_dir = prepare_sources(tmp_path)
    output = tmp_path / "runtime"
    output.mkdir()
    stale = output / "stale.txt"
    stale.write_text("stale", encoding="utf-8")

    bundle = create_deployment_bundle(
        source_db,
        model_dir,
        output,
        overwrite=True,
    )

    assert bundle.db_path.exists()
    assert not stale.exists()


def test_bundle_rejects_output_that_contains_source_files(tmp_path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    source_db = source_dir / "source.sqlite"
    model_dir = source_dir / "model"

    source_db.touch()
    model_dir.mkdir()

    with pytest.raises(ValueError, match="source"):
        create_deployment_bundle(
            source_db,
            model_dir,
            tmp_path,
            overwrite=True,
        )


def test_bundle_creation_does_not_perform_networking(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_db, model_dir = prepare_sources(tmp_path)

    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("deployment bundle creation must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    bundle = create_deployment_bundle(
        source_db,
        model_dir,
        tmp_path / "runtime",
    )

    assert bundle.db_path.exists()



def test_bundle_optionally_includes_valid_evaluation_report(tmp_path) -> None:
    source_db, model_dir = prepare_sources(tmp_path)
    report_path = make_evaluation_report(tmp_path / "final_holdout.json")

    bundle = create_deployment_bundle(
        source_db,
        model_dir,
        tmp_path / "runtime-with-report",
        source_evaluation_report=report_path,
    )

    assert bundle.evaluation_report_path is not None
    assert bundle.evaluation_report_path.exists()
    assert bundle.evaluation_report_path.parent.name == "evaluation"
    assert (
        bundle.evaluation_report_path.read_text(encoding="utf-8")
        == report_path.read_text(encoding="utf-8")
    )


def test_bundle_rejects_missing_evaluation_report(tmp_path) -> None:
    source_db, model_dir = prepare_sources(tmp_path)

    with pytest.raises(FileNotFoundError, match="evaluation report"):
        create_deployment_bundle(
            source_db,
            model_dir,
            tmp_path / "runtime-missing-report",
            source_evaluation_report=tmp_path / "missing.json",
        )
