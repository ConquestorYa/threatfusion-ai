from __future__ import annotations

import json
import socket

import pytest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from threatfusion.ml_artifact import (
    C4_DEVELOPMENT_CANDIDATE,
    SELECTED_DEVELOPMENT_MODEL,
    compute_ml_artifact_checksum,
    SUPPORTED_DEVELOPMENT_MODELS,
    load_trusted_ml_artifact,
    predict_domain_probabilities,
    predict_domain_scores,
    train_selected_model_artifact,
    verify_ml_artifact_checksum,
    write_ml_artifact,
)
from threatfusion.ml_dataset import DomainSample


def make_samples(count_per_label: int = 50) -> list[DomainSample]:
    return [
        *[
            DomainSample(f"malware-{index:03d}.bad-example.test", 1, "ThreatFox")
            for index in range(count_per_label)
        ],
        *[
            DomainSample(f"popular-{index:03d}.good-example.test", 0, "Tranco")
            for index in range(count_per_label)
        ],
    ]


def test_legacy_probability_predictor_alias_matches_score_api() -> None:
    artifact = train_selected_model_artifact(make_samples())
    domains = ["popular-001.good-example.test", "malware-001.bad-example.test"]

    assert predict_domain_probabilities(artifact, domains) == predict_domain_scores(
        artifact,
        domains,
    )


def test_selected_artifact_uses_wider_logistic_candidate() -> None:
    artifact = train_selected_model_artifact(make_samples())

    assert artifact.metadata.model_name == SELECTED_DEVELOPMENT_MODEL
    vectorizer = artifact.model.named_steps["tfidf"]
    classifier = artifact.model.named_steps["classifier"]

    assert isinstance(vectorizer, TfidfVectorizer)
    assert vectorizer.ngram_range == (2, 6)
    assert vectorizer.sublinear_tf is True
    assert isinstance(classifier, LogisticRegression)
    assert classifier.class_weight == "balanced"


def test_c4_candidate_can_be_frozen_without_changing_default() -> None:
    default_artifact = train_selected_model_artifact(make_samples())
    c4_artifact = train_selected_model_artifact(
        make_samples(),
        model_name=C4_DEVELOPMENT_CANDIDATE,
    )

    assert default_artifact.metadata.model_name == SELECTED_DEVELOPMENT_MODEL
    assert c4_artifact.metadata.model_name == C4_DEVELOPMENT_CANDIDATE
    assert SUPPORTED_DEVELOPMENT_MODELS == (
        SELECTED_DEVELOPMENT_MODEL,
        C4_DEVELOPMENT_CANDIDATE,
    )

    classifier = c4_artifact.model.named_steps["classifier"]
    vectorizer = c4_artifact.model.named_steps["tfidf"]
    assert isinstance(classifier, LogisticRegression)
    assert classifier.C == pytest.approx(4.0)
    assert classifier.class_weight == "balanced"
    assert isinstance(vectorizer, TfidfVectorizer)
    assert vectorizer.ngram_range == (2, 6)
    assert vectorizer.sublinear_tf is True


def test_c4_artifact_roundtrip_is_trusted(tmp_path) -> None:
    artifact = train_selected_model_artifact(
        make_samples(),
        model_name=C4_DEVELOPMENT_CANDIDATE,
        high_fpr_budget=0.001,
        medium_fpr_budget=0.005,
        low_fpr_budget=0.01,
    )
    write_ml_artifact(artifact, tmp_path / "c4")

    loaded = load_trusted_ml_artifact(tmp_path / "c4")

    assert loaded.metadata.model_name == C4_DEVELOPMENT_CANDIDATE
    assert loaded.metadata.high_fpr_budget == pytest.approx(0.001)
    assert loaded.metadata.medium_fpr_budget == pytest.approx(0.005)
    assert loaded.metadata.low_fpr_budget == pytest.approx(0.01)


def test_unsupported_model_name_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported development model"):
        train_selected_model_artifact(
            make_samples(),
            model_name="unsupported-model",
        )


def test_thresholds_are_validation_selected_and_ordered() -> None:
    artifact = train_selected_model_artifact(make_samples())

    assert artifact.metadata.selection_split == "validation"
    assert artifact.metadata.evaluation_status == "development_only"
    assert (
        artifact.thresholds.high_confidence
        >= artifact.thresholds.medium_confidence
        >= artifact.thresholds.low_confidence
    )
    assert artifact.metadata.high_fpr_budget == pytest.approx(0.01)
    assert artifact.metadata.medium_fpr_budget == pytest.approx(0.05)
    assert artifact.metadata.low_fpr_budget == pytest.approx(0.10)


def test_selected_artifact_accepts_lower_operational_fpr_budgets() -> None:
    artifact = train_selected_model_artifact(
        make_samples(),
        high_fpr_budget=0.001,
        medium_fpr_budget=0.005,
        low_fpr_budget=0.01,
    )

    assert artifact.metadata.high_fpr_budget == pytest.approx(0.001)
    assert artifact.metadata.medium_fpr_budget == pytest.approx(0.005)
    assert artifact.metadata.low_fpr_budget == pytest.approx(0.01)
    assert (
        artifact.thresholds.high_confidence
        >= artifact.thresholds.medium_confidence
        >= artifact.thresholds.low_confidence
    )


def test_artifact_split_counts_are_recorded() -> None:
    artifact = train_selected_model_artifact(make_samples())

    assert artifact.metadata.train_count == 60
    assert artifact.metadata.validation_count == 20
    assert artifact.metadata.development_test_count == 20


def test_artifact_roundtrip_preserves_predictions(tmp_path) -> None:
    artifact = train_selected_model_artifact(make_samples())
    before = predict_domain_scores(
        artifact,
        ["malware-001.bad-example.test", "popular-001.good-example.test"],
    )

    model_path, metadata_path = write_ml_artifact(
        artifact,
        tmp_path / "model",
    )
    loaded = load_trusted_ml_artifact(tmp_path / "model")
    after = predict_domain_scores(
        loaded,
        ["malware-001.bad-example.test", "popular-001.good-example.test"],
    )

    assert model_path.exists()
    assert metadata_path.exists()
    assert loaded.metadata == artifact.metadata
    assert loaded.thresholds == artifact.thresholds
    assert after == pytest.approx(before)


def test_pinned_checksum_is_verified_before_artifact_load(tmp_path) -> None:
    artifact = train_selected_model_artifact(make_samples())
    artifact_dir = tmp_path / "model"
    write_ml_artifact(artifact, artifact_dir)
    checksum = compute_ml_artifact_checksum(artifact_dir)

    assert verify_ml_artifact_checksum(artifact_dir, checksum.upper()) == checksum
    loaded = load_trusted_ml_artifact(
        artifact_dir,
        expected_checksum=checksum,
    )

    assert loaded.metadata == artifact.metadata


def test_checksum_mismatch_blocks_deserialization(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = train_selected_model_artifact(make_samples())
    artifact_dir = tmp_path / "model"
    model_path, _ = write_ml_artifact(artifact, artifact_dir)
    trusted_checksum = compute_ml_artifact_checksum(artifact_dir)
    model_path.write_bytes(model_path.read_bytes() + b"tampered")

    def forbidden_load(*args, **kwargs):
        raise AssertionError("joblib.load must not run before checksum verification")

    monkeypatch.setattr("threatfusion.ml_artifact.joblib.load", forbidden_load)

    with pytest.raises(ValueError, match="checksum does not match"):
        load_trusted_ml_artifact(
            artifact_dir,
            expected_checksum=trusted_checksum,
        )


def test_invalid_expected_checksum_is_rejected(tmp_path) -> None:
    artifact = train_selected_model_artifact(make_samples())
    artifact_dir = tmp_path / "model"
    write_ml_artifact(artifact, artifact_dir)

    with pytest.raises(ValueError, match="SHA-256"):
        load_trusted_ml_artifact(
            artifact_dir,
            expected_checksum="not-a-sha256",
        )


def test_metadata_contains_no_training_domains(tmp_path) -> None:
    marker = "private-marker.bad-example.test"
    samples = [
        DomainSample(marker, 1, "ThreatFox"),
        *make_samples(),
    ]
    artifact = train_selected_model_artifact(samples)

    _, metadata_path = write_ml_artifact(artifact, tmp_path / "model")
    metadata_text = metadata_path.read_text(encoding="utf-8")

    assert marker not in metadata_text
    parsed = json.loads(metadata_text)
    assert "model_name" in parsed
    assert "high_threshold" in parsed


def test_write_refuses_overwrite_by_default(tmp_path) -> None:
    artifact = train_selected_model_artifact(make_samples())
    output_dir = tmp_path / "model"
    write_ml_artifact(artifact, output_dir)

    with pytest.raises(FileExistsError, match="already exists"):
        write_ml_artifact(artifact, output_dir)


def test_prediction_normalizes_and_deduplicates_domains() -> None:
    artifact = train_selected_model_artifact(make_samples())

    result = predict_domain_scores(
        artifact,
        [
            "Popular-001.Good-Example.Test.",
            "popular-001.good-example.test",
            "not a valid domain",
            "203.0.113.5",
        ],
    )

    assert list(result) == ["popular-001.good-example.test"]
    assert 0.0 <= result["popular-001.good-example.test"] <= 1.0


def test_invalid_fpr_budget_order_is_rejected() -> None:
    with pytest.raises(ValueError, match="FPR budgets"):
        train_selected_model_artifact(
            make_samples(),
            high_fpr_budget=0.10,
            medium_fpr_budget=0.05,
            low_fpr_budget=0.01,
        )


def test_artifact_training_and_inference_do_not_use_networking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("ML artifact workflow must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    artifact = train_selected_model_artifact(make_samples())
    result = predict_domain_scores(
        artifact,
        ["unknown-example.test"],
    )

    assert result
