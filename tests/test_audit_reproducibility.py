from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from threatfusion.audit import (
    AnalysisAuditMetadata,
    CTISourceAudit,
    capture_analysis_audit_metadata,
)
from threatfusion.cti_cache import CTICacheStatus
from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import DomainBehavior
from threatfusion.hybrid_assessment import (
    HybridAssessment,
    HybridVerdict,
    MLThresholds,
)
from threatfusion.ml_artifact import (
    MLArtifactMetadata,
    TrainedMLArtifact,
    compute_ml_artifact_checksum,
)
from threatfusion.persistence import (
    get_analysis_run,
    initialize_database,
    save_runtime_analysis,
)
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def _result() -> RuntimeAnalysisResult:
    event = DNSEvent(query_name="example.com")
    behavior = DomainBehavior(
        domain="example.com",
        event_count=1,
        unique_client_count=0,
        unique_response_ip_count=0,
        query_types=(),
        first_seen=None,
        last_seen=None,
        observed_span_seconds=None,
    )
    assessment = HybridAssessment(
        domain="example.com",
        verdict=HybridVerdict.LOW,
        known_ioc_sources=(),
        known_match_types=(),
        ml_score=0.1,
        ml_tier=None,
        behavior=behavior,
        behavior_signals=(),
        reasons=(),
    )
    return RuntimeAnalysisResult(
        events=(event,),
        matches=(),
        ml_scores={"example.com": 0.1},
        assessments=(assessment,),
    )


def _artifact() -> TrainedMLArtifact:
    metadata = MLArtifactMetadata(
        schema_version=1,
        model_name="lr_char_2_6_sublinear_balanced",
        random_state=42,
        train_count=10,
        validation_count=2,
        development_test_count=2,
        high_fpr_budget=0.01,
        medium_fpr_budget=0.05,
        low_fpr_budget=0.10,
        high_threshold=0.9,
        medium_threshold=0.7,
        low_threshold=0.5,
        sklearn_version="test",
    )
    return TrainedMLArtifact(
        model=None,  # type: ignore[arg-type]
        metadata=metadata,
        thresholds=MLThresholds(
            high_confidence=0.9,
            medium_confidence=0.7,
            low_confidence=0.5,
        ),
    )


def test_artifact_checksum_is_stable_and_content_sensitive(tmp_path) -> None:
    model_dir = tmp_path / "artifact"
    model_dir.mkdir()
    (model_dir / "model.joblib").write_bytes(b"model-v1")
    (model_dir / "metadata.json").write_text(
        '{"schema_version":1}\n',
        encoding="utf-8",
    )

    first = compute_ml_artifact_checksum(model_dir)
    second = compute_ml_artifact_checksum(model_dir)

    assert first == second
    assert len(first) == 64

    (model_dir / "metadata.json").write_text(
        '{"schema_version":2}\n',
        encoding="utf-8",
    )
    assert compute_ml_artifact_checksum(model_dir) != first


def test_capture_audit_metadata_records_thresholds_and_cti_freshness(
    tmp_path,
) -> None:
    model_dir = tmp_path / "artifact"
    model_dir.mkdir()
    (model_dir / "model.joblib").write_bytes(b"model")
    (model_dir / "metadata.json").write_text("{}", encoding="utf-8")
    captured_at = datetime(2026, 9, 25, 20, 0, tzinfo=timezone.utc)

    audit = capture_analysis_audit_metadata(
        model_dir,
        _artifact(),
        [
            CTICacheStatus(
                source="FreshSource",
                refreshed_at="2026-09-25T19:30:00+00:00",
                record_count=12,
            ),
            CTICacheStatus(
                source="StaleSource",
                refreshed_at="2026-09-24T18:00:00+00:00",
                record_count=4,
            ),
        ],
        captured_at=captured_at,
    )

    assert audit.captured_at == captured_at.isoformat()
    assert audit.model_name == "lr_char_2_6_sublinear_balanced"
    assert audit.high_threshold == pytest.approx(0.9)
    assert audit.medium_threshold == pytest.approx(0.7)
    assert audit.low_threshold == pytest.approx(0.5)
    assert [item.freshness for item in audit.cti_sources] == [
        "fresh",
        "stale",
    ]


def test_saved_run_roundtrips_reproducibility_metadata(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    audit = AnalysisAuditMetadata(
        captured_at="2026-09-25T20:00:00+00:00",
        model_name="lr_char_2_6_sublinear_balanced",
        artifact_checksum="a" * 64,
        artifact_schema_version=1,
        high_threshold=0.9,
        medium_threshold=0.7,
        low_threshold=0.5,
        cti_sources=(
            CTISourceAudit(
                source="ThreatFox",
                refreshed_at="2026-09-25T19:00:00+00:00",
                record_count=100,
                freshness="fresh",
            ),
        ),
    )

    run_id = save_runtime_analysis(
        db_path,
        _result(),
        audit_metadata=audit,
    )
    saved = get_analysis_run(db_path, run_id)

    assert saved is not None
    assert saved.model_name == audit.model_name
    assert saved.audit_captured_at == audit.captured_at
    assert saved.artifact_checksum == audit.artifact_checksum
    assert saved.artifact_schema_version == 1
    assert saved.high_threshold == pytest.approx(0.9)
    assert saved.medium_threshold == pytest.approx(0.7)
    assert saved.low_threshold == pytest.approx(0.5)
    assert saved.cti_sources == audit.cti_sources
    assert saved.audit_schema_version == audit.audit_schema_version


def test_history_schema_migrates_legacy_analysis_runs_without_data_loss(
    tmp_path,
) -> None:
    db_path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                match_count INTEGER NOT NULL,
                assessment_count INTEGER NOT NULL,
                known_threat_count INTEGER NOT NULL,
                high_risk_count INTEGER NOT NULL,
                review_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                model_name TEXT
            )
            """
        )
        connection.execute(
            """
            INSERT INTO analysis_runs (
                created_at,
                event_count,
                match_count,
                assessment_count,
                known_threat_count,
                high_risk_count,
                review_count,
                low_count,
                model_name
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-09-24T18:00:00+00:00",
                2,
                1,
                2,
                1,
                0,
                1,
                0,
                "legacy-model",
            ),
        )

    initialize_database(db_path)
    saved = get_analysis_run(db_path, 1)

    assert saved is not None
    assert saved.model_name == "legacy-model"
    assert saved.event_count == 2
    assert saved.audit_captured_at is None
    assert saved.artifact_checksum is None
    assert saved.cti_sources == ()

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(analysis_runs)")
        }

    assert {
        "audit_captured_at",
        "artifact_checksum",
        "artifact_schema_version",
        "high_threshold",
        "medium_threshold",
        "low_threshold",
        "cti_context_json",
        "audit_schema_version",
    } <= columns

def test_capture_audit_metadata_supports_source_specific_freshness(
    tmp_path,
) -> None:
    model_dir = tmp_path / "artifact"
    model_dir.mkdir()
    (model_dir / "model.joblib").write_bytes(b"model")
    (model_dir / "metadata.json").write_text("{}", encoding="utf-8")
    captured_at = datetime(2026, 9, 25, 20, 0, tzinfo=timezone.utc)

    audit = capture_analysis_audit_metadata(
        model_dir,
        _artifact(),
        [
            CTICacheStatus(
                source="ThreatFox",
                refreshed_at="2026-09-25T10:00:00+00:00",
                record_count=12,
            ),
            CTICacheStatus(
                source="SGB",
                refreshed_at="2026-09-25T10:00:00+00:00",
                record_count=4,
            ),
        ],
        captured_at=captured_at,
        stale_after_by_source={
            "ThreatFox": timedelta(hours=6),
            "SGB": timedelta(hours=12),
        },
    )

    assert [item.freshness for item in audit.cti_sources] == [
        "fresh",
        "stale",
    ]

