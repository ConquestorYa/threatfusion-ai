from __future__ import annotations

import importlib
import json
import socket
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from threatfusion.cti_cache import replace_source_records
from threatfusion.ml_artifact import (
    compute_ml_artifact_checksum,
    load_trusted_ml_artifact,
    train_selected_model_artifact,
    write_ml_artifact,
)
from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_holdout import prepare_disjoint_holdout
from threatfusion.ml_snapshot import build_domain_snapshot_from_samples
from threatfusion.ml_snapshot_io import read_domain_snapshot, write_domain_snapshot
from threatfusion.models import IOCRecord, IOCType


@pytest.fixture
def builder_inputs(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    builder = importlib.import_module("scripts.build_ml_fresh_disjoint_holdout")
    malicious = [DomainSample(f"bad-{i}.example", 1, "SGB") for i in range(30)]
    benign = [f"good-{i}.example" for i in range(30)]
    development = build_domain_snapshot_from_samples(
        malicious,
        benign,
        benign_snapshot_id="development",
        benign_snapshot_date="2026-09-23",
    )
    development_dir = tmp_path / "development"
    write_domain_snapshot(development, development_dir)
    artifact_dir = tmp_path / "model"
    write_ml_artifact(train_selected_model_artifact(development.samples), artifact_dir)
    db = tmp_path / "cache.sqlite"
    refresh = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
    for source in ("ThreatFox", "URLhaus", "SGB"):
        replace_source_records(
            db,
            source,
            [
                IOCRecord("BAD-0.EXAMPLE.", IOCType.DOMAIN, source),
                IOCRecord(
                    "fresh.example",
                    IOCType.DOMAIN,
                    source,
                    first_seen=datetime(2026, 9, 1, tzinfo=timezone.utc),
                ),
            ],
            refreshed_at=refresh,
        )
    csv = tmp_path / "benign.csv"
    csv.write_text(
        "query_name\nGOOD-0.EXAMPLE.\nbenign-fresh.example\n", encoding="utf-8"
    )
    output = tmp_path / "holdout"
    args = [
        "--db-path",
        str(db),
        "--artifact-dir",
        str(artifact_dir),
        "--expected-artifact-sha256",
        compute_ml_artifact_checksum(artifact_dir),
        "--development-snapshot-dir",
        str(development_dir),
        "--benign-dns-csv",
        str(csv),
        "--confirm-benign-label",
        "--benign-source-id",
        "fresh-window",
        "--holdout-snapshot-date",
        "2026-10-04",
        "--cti-refresh-after",
        "2026-10-03T20:41:49Z",
        "--output-dir",
        str(output),
    ]
    return builder, args, output, development, db


def test_builder_persists_disjoint_classes_without_temporal_claim(
    builder_inputs,
    monkeypatch,
    capsys,
):
    builder, args, output, development, _ = builder_inputs

    def fail(*args, **kwargs):
        raise AssertionError("holdout construction must not contact the network")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)
    assert builder.main(args) == 0
    snapshot = read_domain_snapshot(output)
    assert {sample.domain for sample in snapshot.samples} == {
        "fresh.example",
        "benign-fresh.example",
    }
    assert (
        prepare_disjoint_holdout(development.samples, snapshot.samples).overlap_removed
        == 0
    )
    metadata = json.loads((output / "metadata.json").read_text())["experiment_metadata"]
    assert metadata["evaluation_protocol"] == "fresh_collection_disjoint"
    assert metadata["temporal_first_seen_filter_applied"] is False
    assert metadata["development_overlap_removed"] == 1
    assert metadata["benign_development_overlap_removed"] == 1
    assert metadata["malicious_retained_domains"] == 1
    assert snapshot.samples[0].first_seen == datetime(2026, 9, 1, tzinfo=timezone.utc)
    stdout = capsys.readouterr().out
    assert "fresh.example" not in stdout
    assert "BAD-0.EXAMPLE" not in stdout


def test_builder_refuses_empty_disjoint_malicious_class(builder_inputs):
    builder, args, output, _, db = builder_inputs
    for source in ("ThreatFox", "URLhaus", "SGB"):
        replace_source_records(
            db,
            source,
            [IOCRecord("bad-0.example", IOCType.DOMAIN, source)],
            refreshed_at=datetime(2026, 10, 4, 12, tzinfo=timezone.utc),
        )
    with pytest.raises(SystemExit, match="both malicious and benign"):
        builder.main(args)
    assert not output.exists()


def test_builder_requires_confirmed_benign_label(builder_inputs):
    builder, args, output, _, _ = builder_inputs
    args.remove("--confirm-benign-label")
    with pytest.raises(SystemExit, match="confirm-benign-label"):
        builder.main(args)
    assert not output.exists()


def test_builder_rejects_pre_cutoff_refresh(builder_inputs):
    builder, args, output, _, db = builder_inputs
    replace_source_records(
        db,
        "SGB",
        [IOCRecord("fresh.example", IOCType.DOMAIN, "SGB")],
        refreshed_at=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )
    with pytest.raises(SystemExit, match="refreshed after"):
        builder.main(args)
    assert not output.exists()


def test_builder_preserves_existing_holdout(builder_inputs):
    builder, args, output, _, _ = builder_inputs
    assert builder.main(args) == 0
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(SystemExit, match="must be empty"):
        builder.main(args)
    assert before == {path.name: path.read_bytes() for path in output.iterdir()}


def _evaluator_inputs(builder_inputs):
    builder, args, output, _, _ = builder_inputs
    builder.main(args)
    evaluator = importlib.import_module("scripts.evaluate_ml_final_holdout")
    evaluation_args = []
    for flag in (
        "--artifact-dir",
        "--expected-artifact-sha256",
        "--development-snapshot-dir",
    ):
        evaluation_args.extend((flag, args[args.index(flag) + 1]))
    report = output.parent / "report.json"
    evaluation_args.extend(
        ("--holdout-snapshot-dir", str(output), "--json-output", str(report))
    )
    return evaluator, evaluation_args, output, report


def test_evaluator_records_artifact_checksum(builder_inputs):
    evaluator, args, _, report = _evaluator_inputs(builder_inputs)
    assert evaluator.main(args) == 0
    raw = json.loads(report.read_text())
    assert raw["schema_version"] == 4
    assert raw["artifact_sha256"] == args[args.index("--expected-artifact-sha256") + 1]
    assert raw["protocol"] == "fresh_collection_disjoint"
    assert raw["overlap_removed"] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("frozen_artifact_sha256", "a" * 64),
        ("development_benign_snapshot_id", "different-development"),
        ("development_benign_snapshot_date", "2026-09-22"),
    ],
)
def test_evaluator_rejects_wrong_collection_provenance(builder_inputs, field, value):
    evaluator, args, output, report = _evaluator_inputs(builder_inputs)
    path = output / "metadata.json"
    raw = json.loads(path.read_text())
    raw["experiment_metadata"][field] = value
    path.write_text(json.dumps(raw))
    with pytest.raises(SystemExit, match="does not match"):
        evaluator.main(args)
    assert not report.exists()


@pytest.mark.parametrize("cutoff", [None, "2026-10-02T20:41:49Z"])
def test_evaluator_cannot_drop_or_change_recorded_temporal_cutoff(
    builder_inputs, cutoff
):
    evaluator, args, output, report = _evaluator_inputs(builder_inputs)
    path = output / "metadata.json"
    raw = json.loads(path.read_text())
    raw["experiment_metadata"].update(
        {
            "evaluation_protocol": "post_freeze_temporal_malicious_plus_confirmed_benign_dns",
            "malicious_first_seen_after": "2026-10-03T20:41:49Z",
        }
    )
    path.write_text(json.dumps(raw))
    if cutoff:
        args.extend(("--malicious-first-seen-after", cutoff))
    with pytest.raises(SystemExit, match="recorded post-freeze cutoff"):
        evaluator.main(args)
    assert not report.exists()


def test_final_workflow_refuses_synthetic_demo_artifact(builder_inputs):
    builder, args, output, _, _ = builder_inputs
    model_dir = Path(args[args.index("--artifact-dir") + 1])
    artifact = load_trusted_ml_artifact(model_dir)
    demo = replace(
        artifact,
        metadata=replace(artifact.metadata, evaluation_status="demo_only_synthetic"),
    )
    write_ml_artifact(demo, model_dir, overwrite=True)
    args[args.index("--expected-artifact-sha256") + 1] = compute_ml_artifact_checksum(
        model_dir
    )
    with pytest.raises(SystemExit, match="synthetic demo"):
        builder.main(args)
    assert not output.exists()
    evaluator = importlib.import_module("scripts.evaluate_ml_final_holdout")
    with pytest.raises(SystemExit, match="synthetic demo"):
        evaluator.main(
            [
                "--artifact-dir",
                str(model_dir),
                "--development-snapshot-dir",
                str(output.parent / "development"),
                "--holdout-snapshot-dir",
                str(output),
            ]
        )
