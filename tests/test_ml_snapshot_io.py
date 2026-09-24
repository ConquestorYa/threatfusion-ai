from __future__ import annotations

import csv
import json
import socket
from pathlib import Path

import pytest

from threatfusion.ml_dataset import DomainSample
from threatfusion.ml_snapshot import (
    DatasetSnapshotMetadata,
    DatasetSnapshotStatistics,
    DomainDatasetSnapshot,
)
from threatfusion.ml_snapshot_io import read_domain_snapshot, write_domain_snapshot


def make_snapshot(
    samples: list[DomainSample] | None = None,
) -> DomainDatasetSnapshot:
    snapshot_samples = samples or [
        DomainSample("evil.example", 1, "ThreatFox"),
        DomainSample("safe.example", 0, "Tranco"),
    ]
    return DomainDatasetSnapshot(
        samples=snapshot_samples,
        metadata=DatasetSnapshotMetadata(
            benign_source="Tranco",
            benign_snapshot_id="L5PV4",
            benign_snapshot_date="2026-09-23",
        ),
        statistics=DatasetSnapshotStatistics(
            malicious_input_count=2,
            benign_input_count=2,
            malicious_unique_count=1,
            benign_unique_count=1,
            final_malicious_count=1,
            final_benign_count=1,
            final_total_count=2,
            overlap_removed_from_benign=0,
            malicious_by_source={"ThreatFox": 1},
        ),
    )


def test_write_creates_nested_snapshot_files_and_csv_header(tmp_path: Path) -> None:
    output_dir = tmp_path / "data" / "snapshots" / "experiment-1"

    dataset_path, metadata_path = write_domain_snapshot(
        make_snapshot(),
        output_dir,
        experiment_metadata={"threatfox_days": 7, "sgb_pages": 10},
    )

    assert dataset_path == output_dir / "dataset.csv"
    assert metadata_path == output_dir / "metadata.json"
    assert dataset_path.exists()
    assert metadata_path.exists()
    with dataset_path.open("r", encoding="utf-8", newline="") as dataset_file:
        rows = list(csv.reader(dataset_file))

    assert rows == [
        ["domain", "label", "source"],
        ["evil.example", "1", "ThreatFox"],
        ["safe.example", "0", "Tranco"],
    ]


def test_metadata_and_statistics_are_preserved(tmp_path: Path) -> None:
    snapshot = make_snapshot()
    _, metadata_path = write_domain_snapshot(
        snapshot,
        tmp_path,
        experiment_metadata={
            "threatfox_days": 7,
            "sgb_pages": 10,
            "tranco_limit": 50000,
        },
    )

    payload = json.loads(metadata_path.read_text(encoding="utf-8"))

    assert payload["metadata"] == {
        "benign_source": "Tranco",
        "benign_snapshot_id": "L5PV4",
        "benign_snapshot_date": "2026-09-23",
    }
    assert payload["statistics"] == {
        "malicious_input_count": 2,
        "benign_input_count": 2,
        "malicious_unique_count": 1,
        "benign_unique_count": 1,
        "final_malicious_count": 1,
        "final_benign_count": 1,
        "final_total_count": 2,
        "overlap_removed_from_benign": 0,
        "malicious_by_source": {"ThreatFox": 1},
    }
    assert payload["experiment_metadata"] == {
        "threatfox_days": 7,
        "sgb_pages": 10,
        "tranco_limit": 50000,
    }


def test_round_trip_recreates_snapshot_and_labels_are_integers(tmp_path: Path) -> None:
    snapshot = make_snapshot()

    write_domain_snapshot(snapshot, tmp_path)
    loaded = read_domain_snapshot(tmp_path)

    assert loaded == snapshot
    assert all(isinstance(sample.label, int) for sample in loaded.samples)


def test_existing_snapshot_files_are_overwritten_deterministically(tmp_path: Path) -> None:
    first = make_snapshot()
    second = make_snapshot(
        [
            DomainSample("new-evil.example", 1, "SGB"),
            DomainSample("new-safe.example", 0, "Tranco"),
        ]
    )
    second = DomainDatasetSnapshot(
        samples=second.samples,
        metadata=second.metadata,
        statistics=DatasetSnapshotStatistics(
            malicious_input_count=1,
            benign_input_count=1,
            malicious_unique_count=1,
            benign_unique_count=1,
            final_malicious_count=1,
            final_benign_count=1,
            final_total_count=2,
            overlap_removed_from_benign=0,
            malicious_by_source={"SGB": 1},
        ),
    )

    write_domain_snapshot(first, tmp_path)
    write_domain_snapshot(second, tmp_path)

    assert read_domain_snapshot(tmp_path) == second


def test_missing_required_csv_columns_raise_value_error(tmp_path: Path) -> None:
    write_domain_snapshot(make_snapshot(), tmp_path)
    (tmp_path / "dataset.csv").write_text(
        "domain,label\nevil.example,1\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="required columns"):
        read_domain_snapshot(tmp_path)


def test_invalid_label_raises_value_error(tmp_path: Path) -> None:
    write_domain_snapshot(make_snapshot(), tmp_path)
    (tmp_path / "dataset.csv").write_text(
        "domain,label,source\nevil.example,2,ThreatFox\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="labels must be integers 0 or 1"):
        read_domain_snapshot(tmp_path)


def test_malformed_metadata_json_raises_value_error(tmp_path: Path) -> None:
    write_domain_snapshot(make_snapshot(), tmp_path)
    (tmp_path / "metadata.json").write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError, match="valid JSON"):
        read_domain_snapshot(tmp_path)


def test_count_mismatch_raises_value_error(tmp_path: Path) -> None:
    write_domain_snapshot(make_snapshot(), tmp_path)
    metadata_path = tmp_path / "metadata.json"
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    payload["statistics"]["final_total_count"] = 99
    metadata_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="final_total_count"):
        read_domain_snapshot(tmp_path)


def test_secret_experiment_fields_are_rejected_and_not_written(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="secret fields"):
        write_domain_snapshot(
            make_snapshot(),
            tmp_path,
            experiment_metadata={"THREATFOX_AUTH_KEY": "do-not-write"},
        )

    assert not (tmp_path / "dataset.csv").exists()
    assert not (tmp_path / "metadata.json").exists()


def test_snapshot_io_does_not_use_networking(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("snapshot persistence must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    write_domain_snapshot(make_snapshot(), tmp_path)
    assert read_domain_snapshot(tmp_path) == make_snapshot()
