from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .runtime_analysis import RuntimeAnalysisResult


@dataclass(frozen=True)
class AnalysisRunSummary:
    id: int
    created_at: str
    event_count: int
    match_count: int
    assessment_count: int
    known_threat_count: int
    high_risk_count: int
    review_count: int
    low_count: int
    model_name: str | None


@dataclass(frozen=True)
class PersistedDomainAssessment:
    domain: str
    verdict: str
    ml_probability: float | None
    ml_tier: str | None
    event_count: int
    unique_client_count: int
    unique_response_ip_count: int
    query_types: tuple[str, ...]
    first_seen: str | None
    last_seen: str | None
    observed_span_seconds: float | None
    known_ioc_sources: tuple[str, ...]
    known_match_types: tuple[str, ...]
    behavior_signals: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class AnalystFeedback:
    analysis_run_id: int
    domain: str
    label: str
    note: str | None
    updated_at: str


_FEEDBACK_LABELS = {
    "confirmed_threat",
    "benign",
    "uncertain",
}
_MAX_FEEDBACK_NOTE_LENGTH = 500


_SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_runs (
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
);

CREATE TABLE IF NOT EXISTS analysis_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_run_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    verdict TEXT NOT NULL,
    ml_probability REAL,
    ml_tier TEXT,
    event_count INTEGER NOT NULL,
    unique_client_count INTEGER NOT NULL,
    unique_response_ip_count INTEGER NOT NULL,
    query_types_json TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    observed_span_seconds REAL,
    known_ioc_sources_json TEXT NOT NULL,
    known_match_types_json TEXT NOT NULL,
    behavior_signals_json TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    FOREIGN KEY (analysis_run_id)
        REFERENCES analysis_runs(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_assessments_run_id
    ON analysis_assessments(analysis_run_id);

CREATE INDEX IF NOT EXISTS idx_assessments_verdict
    ON analysis_assessments(verdict);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    analysis_run_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    label TEXT NOT NULL,
    note TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (analysis_run_id, domain),
    FOREIGN KEY (analysis_run_id)
        REFERENCES analysis_runs(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_run_id
    ON analyst_feedback(analysis_run_id);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(Path(db_path))
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path: Path) -> None:
    """Create the local analysis-history schema if it does not exist."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with _connect(path) as connection:
        connection.executescript(_SCHEMA)


def _created_at_text(created_at: datetime | None) -> str:
    value = created_at or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("created_at must be timezone-aware")
    return value.isoformat()


def _optional_datetime_text(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_tuple(values: Sequence[str]) -> str:
    return json.dumps(list(values), ensure_ascii=True, separators=(",", ":"))


def save_runtime_analysis(
    db_path: Path,
    result: RuntimeAnalysisResult,
    *,
    model_name: str | None = None,
    created_at: datetime | None = None,
) -> int:
    """Persist summary and per-domain assessment data for one analysis run.

    Raw DNS rows and client IP values are intentionally not persisted.
    """
    initialize_database(db_path)

    verdict_counts = {
        "known_threat": 0,
        "high_risk": 0,
        "review": 0,
        "low": 0,
    }
    for assessment in result.assessments:
        verdict_counts[assessment.verdict.value] += 1

    with _connect(Path(db_path)) as connection:
        cursor = connection.execute(
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
                _created_at_text(created_at),
                len(result.events),
                len(result.matches),
                len(result.assessments),
                verdict_counts["known_threat"],
                verdict_counts["high_risk"],
                verdict_counts["review"],
                verdict_counts["low"],
                model_name,
            ),
        )
        run_id = int(cursor.lastrowid)

        rows = []
        for assessment in result.assessments:
            behavior = assessment.behavior
            rows.append(
                (
                    run_id,
                    assessment.domain,
                    assessment.verdict.value,
                    assessment.ml_probability,
                    assessment.ml_tier,
                    behavior.event_count,
                    behavior.unique_client_count,
                    behavior.unique_response_ip_count,
                    _json_tuple(behavior.query_types),
                    _optional_datetime_text(behavior.first_seen),
                    _optional_datetime_text(behavior.last_seen),
                    behavior.observed_span_seconds,
                    _json_tuple(assessment.known_ioc_sources),
                    _json_tuple(assessment.known_match_types),
                    _json_tuple(assessment.behavior_signals),
                    _json_tuple(assessment.reasons),
                )
            )

        connection.executemany(
            """
            INSERT INTO analysis_assessments (
                analysis_run_id,
                domain,
                verdict,
                ml_probability,
                ml_tier,
                event_count,
                unique_client_count,
                unique_response_ip_count,
                query_types_json,
                first_seen,
                last_seen,
                observed_span_seconds,
                known_ioc_sources_json,
                known_match_types_json,
                behavior_signals_json,
                reasons_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    return run_id


def _summary_from_row(row: sqlite3.Row) -> AnalysisRunSummary:
    return AnalysisRunSummary(
        id=int(row["id"]),
        created_at=str(row["created_at"]),
        event_count=int(row["event_count"]),
        match_count=int(row["match_count"]),
        assessment_count=int(row["assessment_count"]),
        known_threat_count=int(row["known_threat_count"]),
        high_risk_count=int(row["high_risk_count"]),
        review_count=int(row["review_count"]),
        low_count=int(row["low_count"]),
        model_name=row["model_name"],
    )


def list_analysis_runs(db_path: Path) -> list[AnalysisRunSummary]:
    """List persisted runs from newest to oldest."""
    initialize_database(db_path)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT *
            FROM analysis_runs
            ORDER BY id DESC
            """
        ).fetchall()

    return [_summary_from_row(row) for row in rows]


def get_analysis_run(
    db_path: Path,
    run_id: int,
) -> AnalysisRunSummary | None:
    """Load one persisted analysis-run summary."""
    initialize_database(db_path)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM analysis_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()

    return _summary_from_row(row) if row is not None else None


def _decode_string_tuple(value: str) -> tuple[str, ...]:
    decoded = json.loads(value)
    if not isinstance(decoded, list) or not all(
        isinstance(item, str) for item in decoded
    ):
        raise ValueError("persisted JSON string-list field is invalid")
    return tuple(decoded)


def get_analysis_assessments(
    db_path: Path,
    run_id: int,
) -> list[PersistedDomainAssessment]:
    """Load per-domain results for one run in stable domain order."""
    initialize_database(db_path)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT *
            FROM analysis_assessments
            WHERE analysis_run_id = ?
            ORDER BY domain ASC, id ASC
            """,
            (run_id,),
        ).fetchall()

    return [
        PersistedDomainAssessment(
            domain=str(row["domain"]),
            verdict=str(row["verdict"]),
            ml_probability=(
                float(row["ml_probability"])
                if row["ml_probability"] is not None
                else None
            ),
            ml_tier=row["ml_tier"],
            event_count=int(row["event_count"]),
            unique_client_count=int(row["unique_client_count"]),
            unique_response_ip_count=int(row["unique_response_ip_count"]),
            query_types=_decode_string_tuple(row["query_types_json"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            observed_span_seconds=(
                float(row["observed_span_seconds"])
                if row["observed_span_seconds"] is not None
                else None
            ),
            known_ioc_sources=_decode_string_tuple(
                row["known_ioc_sources_json"]
            ),
            known_match_types=_decode_string_tuple(
                row["known_match_types_json"]
            ),
            behavior_signals=_decode_string_tuple(
                row["behavior_signals_json"]
            ),
            reasons=_decode_string_tuple(row["reasons_json"]),
        )
        for row in rows
    ]


def _feedback_time_text(updated_at: datetime | None) -> str:
    value = updated_at or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("updated_at must be timezone-aware")
    return value.isoformat()


def save_analyst_feedback(
    db_path: Path,
    run_id: int,
    domain: str,
    label: str,
    *,
    note: str | None = None,
    updated_at: datetime | None = None,
) -> AnalystFeedback:
    """Save one current analyst label for a persisted run/domain finding."""
    if label not in _FEEDBACK_LABELS:
        raise ValueError("unsupported analyst feedback label")
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("feedback domain must be a non-empty string")

    normalized_domain = domain.strip()
    normalized_note = note.strip() if isinstance(note, str) else None
    if normalized_note == "":
        normalized_note = None
    if (
        normalized_note is not None
        and len(normalized_note) > _MAX_FEEDBACK_NOTE_LENGTH
    ):
        raise ValueError("analyst feedback note is too long")

    initialize_database(db_path)
    timestamp = _feedback_time_text(updated_at)

    with _connect(Path(db_path)) as connection:
        exists = connection.execute(
            """
            SELECT 1
            FROM analysis_assessments
            WHERE analysis_run_id = ? AND domain = ?
            LIMIT 1
            """,
            (run_id, normalized_domain),
        ).fetchone()
        if exists is None:
            raise ValueError("feedback domain is not part of the analysis run")

        connection.execute(
            """
            INSERT INTO analyst_feedback (
                analysis_run_id,
                domain,
                label,
                note,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(analysis_run_id, domain) DO UPDATE SET
                label = excluded.label,
                note = excluded.note,
                updated_at = excluded.updated_at
            """,
            (
                run_id,
                normalized_domain,
                label,
                normalized_note,
                timestamp,
            ),
        )

    return AnalystFeedback(
        analysis_run_id=run_id,
        domain=normalized_domain,
        label=label,
        note=normalized_note,
        updated_at=timestamp,
    )


def get_analyst_feedback(
    db_path: Path,
    run_id: int,
) -> list[AnalystFeedback]:
    """Load analyst feedback for one saved run in deterministic domain order."""
    initialize_database(db_path)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT analysis_run_id, domain, label, note, updated_at
            FROM analyst_feedback
            WHERE analysis_run_id = ?
            ORDER BY domain ASC
            """,
            (run_id,),
        ).fetchall()

    return [
        AnalystFeedback(
            analysis_run_id=int(row["analysis_run_id"]),
            domain=str(row["domain"]),
            label=str(row["label"]),
            note=row["note"],
            updated_at=str(row["updated_at"]),
        )
        for row in rows
    ]
