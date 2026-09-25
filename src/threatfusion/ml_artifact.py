from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import sklearn
from sklearn.pipeline import Pipeline

from .hybrid_assessment import MLThresholds
from .ml_dataset import DomainSample, normalize_domain_candidate
from .ml_fpr_comparison import (
    build_candidate_pipelines,
    evaluate_candidate,
)
from .ml_high_recall import split_train_validation_test

_ARTIFACT_SCHEMA_VERSION = 1
_MODEL_FILENAME = "model.joblib"
_METADATA_FILENAME = "metadata.json"
SELECTED_DEVELOPMENT_MODEL = "lr_char_2_6_sublinear_balanced"


@dataclass(frozen=True)
class MLArtifactMetadata:
    schema_version: int
    model_name: str
    random_state: int
    train_count: int
    validation_count: int
    development_test_count: int
    high_fpr_budget: float
    medium_fpr_budget: float
    low_fpr_budget: float
    high_threshold: float
    medium_threshold: float
    low_threshold: float
    sklearn_version: str
    selection_split: str = "validation"
    evaluation_status: str = "development_only"


@dataclass(frozen=True)
class TrainedMLArtifact:
    model: Pipeline
    metadata: MLArtifactMetadata
    thresholds: MLThresholds


def _validate_fpr_budgets(
    high_fpr_budget: float,
    medium_fpr_budget: float,
    low_fpr_budget: float,
) -> None:
    if not (
        0.0
        <= high_fpr_budget
        <= medium_fpr_budget
        <= low_fpr_budget
        <= 1.0
    ):
        raise ValueError(
            "FPR budgets must satisfy "
            "0 <= high <= medium <= low <= 1"
        )


def train_selected_model_artifact(
    samples: Sequence[DomainSample],
    *,
    high_fpr_budget: float = 0.01,
    medium_fpr_budget: float = 0.05,
    low_fpr_budget: float = 0.10,
    test_size: float = 0.20,
    validation_size: float = 0.20,
    random_state: int = 42,
) -> TrainedMLArtifact:
    """Train the selected development model and choose thresholds on validation."""
    _validate_fpr_budgets(
        high_fpr_budget,
        medium_fpr_budget,
        low_fpr_budget,
    )

    split = split_train_validation_test(
        samples,
        test_size=test_size,
        validation_size=validation_size,
        random_state=random_state,
    )
    model = build_candidate_pipelines(random_state=random_state)[
        SELECTED_DEVELOPMENT_MODEL
    ]
    evaluation = evaluate_candidate(
        SELECTED_DEVELOPMENT_MODEL,
        model,
        split,
        fpr_budgets=(
            high_fpr_budget,
            medium_fpr_budget,
            low_fpr_budget,
        ),
    )

    high_threshold = evaluation.budget_evaluations[0].validation.threshold
    medium_threshold = evaluation.budget_evaluations[1].validation.threshold
    low_threshold = evaluation.budget_evaluations[2].validation.threshold

    thresholds = MLThresholds(
        high_confidence=high_threshold,
        medium_confidence=medium_threshold,
        low_confidence=low_threshold,
    )

    metadata = MLArtifactMetadata(
        schema_version=_ARTIFACT_SCHEMA_VERSION,
        model_name=SELECTED_DEVELOPMENT_MODEL,
        random_state=random_state,
        train_count=len(split.train),
        validation_count=len(split.validation),
        development_test_count=len(split.test),
        high_fpr_budget=float(high_fpr_budget),
        medium_fpr_budget=float(medium_fpr_budget),
        low_fpr_budget=float(low_fpr_budget),
        high_threshold=float(high_threshold),
        medium_threshold=float(medium_threshold),
        low_threshold=float(low_threshold),
        sklearn_version=sklearn.__version__,
    )

    return TrainedMLArtifact(
        model=evaluation.model,
        metadata=metadata,
        thresholds=thresholds,
    )


def write_ml_artifact(
    artifact: TrainedMLArtifact,
    output_dir: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Persist a locally trained model plus JSON metadata."""
    output_path = Path(output_dir)
    model_path = output_path / _MODEL_FILENAME
    metadata_path = output_path / _METADATA_FILENAME

    if not overwrite and (model_path.exists() or metadata_path.exists()):
        raise FileExistsError(
            "ML artifact already exists; pass overwrite=True to replace it"
        )

    output_path.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact.model, model_path)
    metadata_path.write_text(
        json.dumps(asdict(artifact.metadata), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return model_path, metadata_path


def compute_ml_artifact_checksum(input_dir: Path) -> str:
    """Return a stable SHA-256 identity for the persisted model artifact files."""
    input_path = Path(input_dir)
    digest = hashlib.sha256()

    for filename in (_MODEL_FILENAME, _METADATA_FILENAME):
        path = input_path / filename
        with path.open("rb") as handle:
            digest.update(filename.encode("utf-8"))
            digest.update(b"\0")
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)

    return digest.hexdigest()


def _read_metadata(metadata_path: Path) -> MLArtifactMetadata:
    try:
        raw = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("ML artifact metadata is invalid JSON") from error

    if not isinstance(raw, dict):
        raise TypeError("ML artifact metadata must be a JSON object")

    try:
        metadata = MLArtifactMetadata(**raw)
    except TypeError as error:
        raise ValueError("ML artifact metadata schema is invalid") from error

    if metadata.schema_version != _ARTIFACT_SCHEMA_VERSION:
        raise ValueError("unsupported ML artifact schema version")
    if metadata.model_name != SELECTED_DEVELOPMENT_MODEL:
        raise ValueError("unexpected ML artifact model name")

    MLThresholds(
        high_confidence=metadata.high_threshold,
        medium_confidence=metadata.medium_threshold,
        low_confidence=metadata.low_threshold,
    )
    _validate_fpr_budgets(
        metadata.high_fpr_budget,
        metadata.medium_fpr_budget,
        metadata.low_fpr_budget,
    )
    return metadata


def load_trusted_ml_artifact(input_dir: Path) -> TrainedMLArtifact:
    """Load a trusted local artifact.

    joblib/pickle loading can execute code. Only load artifacts generated by
    this project in a trusted local environment; never load untrusted files.
    """
    input_path = Path(input_dir)
    model_path = input_path / _MODEL_FILENAME
    metadata_path = input_path / _METADATA_FILENAME

    metadata = _read_metadata(metadata_path)
    model = joblib.load(model_path)

    if not isinstance(model, Pipeline):
        raise TypeError("ML artifact model must be an sklearn Pipeline")
    if not hasattr(model, "predict_proba"):
        raise ValueError("ML artifact model must support predict_proba")

    thresholds = MLThresholds(
        high_confidence=metadata.high_threshold,
        medium_confidence=metadata.medium_threshold,
        low_confidence=metadata.low_threshold,
    )
    return TrainedMLArtifact(
        model=model,
        metadata=metadata,
        thresholds=thresholds,
    )


def predict_domain_probabilities(
    artifact: TrainedMLArtifact,
    domains: Iterable[str],
) -> dict[str, float]:
    """Predict malicious-domain probabilities for valid normalized domains."""
    normalized_domains: list[str] = []
    seen: set[str] = set()

    for value in domains:
        normalized = normalize_domain_candidate(value)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        normalized_domains.append(normalized)

    if not normalized_domains:
        return {}

    probabilities = artifact.model.predict_proba(normalized_domains)
    classes = list(artifact.model.classes_)
    positive_index = classes.index(1)

    return {
        domain: float(row[positive_index])
        for domain, row in zip(normalized_domains, probabilities, strict=True)
    }
