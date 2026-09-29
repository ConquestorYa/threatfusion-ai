"""The final run must bind the frozen artifact and both exact snapshots."""

import json
from types import SimpleNamespace

import pytest
from scripts import evaluate_ml_final_holdout

from threatfusion.ml_final_provenance import (
    read_and_validate_final_provenance,
    write_final_provenance,
)


MODEL = "lr_char_2_6_plus_lexical_c4"
SHA = "82f07f99820cea4ec2b8c2c07ab3d6a9387c87b17fafe1994d7730cc39386d14"
CUTOFF = "2026-09-28T21:38:37.5577083Z"


def _snapshots(tmp_path):
    development = tmp_path / "development"
    holdout = tmp_path / "holdout"
    development.mkdir()
    holdout.mkdir()
    (development / "dataset.csv").write_text("domain,label\nold.example,0\n")
    (development / "metadata.json").write_text("{}\n")
    (holdout / "dataset.csv").write_text("domain,label\nnew.example,1\n")
    (holdout / "metadata.json").write_text(
        json.dumps(
            {
                "experiment_metadata": {
                    "collection_purpose": "final_holdout",
                    "frozen_model_name": MODEL,
                    "frozen_artifact_sha256": SHA,
                    "malicious_first_seen_after": "2026-09-28T21:38:37.557708+00:00",
                }
            }
        )
    )
    return development, holdout


def test_final_manifest_binds_exact_artifact_snapshots_and_cutoff(tmp_path):
    development, holdout = _snapshots(tmp_path)
    path = write_final_provenance(
        development,
        holdout,
        model_name=MODEL,
        artifact_sha256=SHA,
        cutoff=CUTOFF,
    )

    manifest = read_and_validate_final_provenance(
        path,
        development,
        holdout,
        model_name=MODEL,
        artifact_sha256=SHA,
        cutoff=CUTOFF,
    )

    assert manifest.schema_version == 1
    assert manifest.artifact_sha256 == SHA
    assert manifest.cutoff == CUTOFF
    assert len(manifest.development_snapshot_sha256) == 64
    assert len(manifest.holdout_snapshot_sha256) == 64

    (holdout / "dataset.csv").write_text("domain,label\nchanged.example,1\n")
    with pytest.raises(ValueError, match="holdout snapshot hash"):
        read_and_validate_final_provenance(
            path,
            development,
            holdout,
            model_name=MODEL,
            artifact_sha256=SHA,
            cutoff=CUTOFF,
        )


@pytest.mark.parametrize(
    "override,pattern",
    [
        ({"model_name": "wrong"}, "model name"),
        ({"artifact_sha256": "0" * 64}, "artifact SHA-256"),
        ({"cutoff": "2026-09-28T21:38:37.5577080Z"}, "cutoff"),
    ],
)
def test_final_manifest_rejects_wrong_run_identity(tmp_path, override, pattern):
    development, holdout = _snapshots(tmp_path)
    path = write_final_provenance(
        development,
        holdout,
        model_name=MODEL,
        artifact_sha256=SHA,
        cutoff=CUTOFF,
    )
    identity = {"model_name": MODEL, "artifact_sha256": SHA, "cutoff": CUTOFF}
    identity.update(override)

    with pytest.raises(ValueError, match=pattern):
        read_and_validate_final_provenance(
            path, development, holdout, **identity
        )


def test_temporal_evaluator_requires_manifest_before_scoring(
    tmp_path, monkeypatch
) -> None:
    development, holdout = _snapshots(tmp_path)
    monkeypatch.setattr(
        evaluate_ml_final_holdout,
        "load_trusted_ml_artifact",
        lambda *args, **kwargs: SimpleNamespace(
            metadata=SimpleNamespace(model_name=MODEL)
        ),
    )
    monkeypatch.setattr(
        evaluate_ml_final_holdout,
        "read_domain_snapshot",
        lambda path: SimpleNamespace(
            metadata=SimpleNamespace(
                benign_snapshot_date=(
                    "2026-09-27" if path == development else "2026-09-29"
                )
            ),
            samples=[],
        ),
    )
    monkeypatch.setattr(
        evaluate_ml_final_holdout,
        "evaluate_frozen_artifact_on_holdout",
        lambda *args, **kwargs: pytest.fail("scoring before provenance validation"),
    )
    monkeypatch.setattr(
        evaluate_ml_final_holdout,
        "compute_ml_artifact_checksum",
        lambda path: SHA,
    )

    with pytest.raises(SystemExit, match="provenance.json"):
        evaluate_ml_final_holdout.main(
            [
                "--artifact-dir", str(tmp_path / "model"),
                "--development-snapshot-dir", str(development),
                "--holdout-snapshot-dir", str(holdout),
                "--malicious-first-seen-after", CUTOFF,
            ]
        )
