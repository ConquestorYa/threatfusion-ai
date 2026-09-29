"""External identity manifest for a frozen final evaluation run."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .ml_artifact import LEXICAL_C4_DEVELOPMENT_CANDIDATE

LEXICAL_C4_ARTIFACT_SHA256 = (
    "82f07f99820cea4ec2b8c2c07ab3d6a9387c87b17fafe1994d7730cc39386d14"
)
LEXICAL_C4_FREEZE_CUTOFF = "2026-09-28T21:38:37.5577083Z"
FINAL_PROVENANCE_FILENAME = "provenance.json"
_PROTOCOL = "post_freeze_temporal_malicious_plus_confirmed_benign_dns"
_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FinalProvenance:
    schema_version: int
    protocol: str
    model_name: str
    artifact_sha256: str
    development_snapshot_sha256: str
    holdout_snapshot_sha256: str
    cutoff: str


def _parsed_cutoff(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("final cutoff must be an ISO timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("final cutoff must include a timezone offset")
    return parsed


def validate_frozen_lexical_identity(
    model_name: str, artifact_sha256: str, cutoff: str
) -> None:
    """Protect the published lexical freeze without changing its artifact."""
    _parsed_cutoff(cutoff)
    if model_name != LEXICAL_C4_DEVELOPMENT_CANDIDATE:
        return
    if artifact_sha256 != LEXICAL_C4_ARTIFACT_SHA256:
        raise ValueError("frozen lexical artifact SHA-256 does not match")
    if cutoff != LEXICAL_C4_FREEZE_CUTOFF:
        raise ValueError("frozen lexical cutoff does not match")


def snapshot_sha256(snapshot_dir: Path) -> str:
    """Hash the exact dataset and metadata files, including their names."""
    digest = hashlib.sha256()
    for name in ("dataset.csv", "metadata.json"):
        digest.update(name.encode("ascii") + b"\0")
        with (Path(snapshot_dir) / name).open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def write_final_provenance(
    development_snapshot_dir: Path,
    holdout_snapshot_dir: Path,
    *,
    model_name: str,
    artifact_sha256: str,
    cutoff: str,
) -> Path:
    validate_frozen_lexical_identity(model_name, artifact_sha256, cutoff)
    manifest = FinalProvenance(
        schema_version=_SCHEMA_VERSION,
        protocol=_PROTOCOL,
        model_name=model_name,
        artifact_sha256=artifact_sha256,
        development_snapshot_sha256=snapshot_sha256(development_snapshot_dir),
        holdout_snapshot_sha256=snapshot_sha256(holdout_snapshot_dir),
        cutoff=cutoff,
    )
    path = Path(holdout_snapshot_dir) / FINAL_PROVENANCE_FILENAME
    with path.open("x", encoding="utf-8") as handle:
        json.dump(asdict(manifest), handle, sort_keys=True, indent=2)
        handle.write("\n")
    return path


def read_and_validate_final_provenance(
    path: Path,
    development_snapshot_dir: Path,
    holdout_snapshot_dir: Path,
    *,
    model_name: str,
    artifact_sha256: str,
    cutoff: str,
) -> FinalProvenance:
    """Reject a final run whose artifact, snapshots or cutoff differ."""
    validate_frozen_lexical_identity(model_name, artifact_sha256, cutoff)
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("final provenance manifest is invalid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("final provenance manifest must be an object")
    try:
        manifest = FinalProvenance(**payload)
    except TypeError as error:
        raise ValueError("final provenance manifest schema is invalid") from error
    if manifest.schema_version != _SCHEMA_VERSION or manifest.protocol != _PROTOCOL:
        raise ValueError("final provenance protocol/schema version is unsupported")
    if manifest.model_name != model_name:
        raise ValueError("final provenance model name does not match")
    if manifest.artifact_sha256 != artifact_sha256:
        raise ValueError("final provenance artifact SHA-256 does not match")
    if manifest.cutoff != cutoff:
        raise ValueError("final provenance cutoff does not match")
    if manifest.development_snapshot_sha256 != snapshot_sha256(
        development_snapshot_dir
    ):
        raise ValueError("final provenance development snapshot hash does not match")
    if manifest.holdout_snapshot_sha256 != snapshot_sha256(holdout_snapshot_dir):
        raise ValueError("final provenance holdout snapshot hash does not match")

    metadata_path = Path(holdout_snapshot_dir) / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    experiment = metadata.get("experiment_metadata", {})
    if not isinstance(experiment, dict) or (
        experiment.get("collection_purpose") != "final_holdout"
        or experiment.get("frozen_model_name") != model_name
        or experiment.get("frozen_artifact_sha256") != artifact_sha256
    ):
        raise ValueError("final provenance disagrees with holdout metadata")
    embedded_cutoff = experiment.get("malicious_first_seen_after")
    if not isinstance(embedded_cutoff, str) or _parsed_cutoff(
        embedded_cutoff
    ) != _parsed_cutoff(cutoff):
        raise ValueError("final provenance cutoff disagrees with holdout metadata")
    return manifest
