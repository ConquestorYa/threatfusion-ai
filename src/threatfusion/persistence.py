from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .audit import AnalysisAuditMetadata, CTISourceAudit
from .runtime_analysis import RuntimeAnalysisResult
from .target_privacy import safe_target_labels


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
    audit_captured_at: str | None = None
    artifact_checksum: str | None = None
    artifact_schema_version: int | None = None
    high_threshold: float | None = None
    medium_threshold: float | None = None
    low_threshold: float | None = None
    cti_sources: tuple[CTISourceAudit, ...] = ()
    audit_schema_version: int | None = None


@dataclass(frozen=True)
class PersistedDomainAssessment:
    domain: str
    verdict: str
    ml_score: float | None
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
    target_type: str = "domain"

    @property
    def ml_probability(self) -> float | None:
        """Backward-compatible alias for the legacy persisted field name."""
        return self.ml_score


@dataclass(frozen=True)
class AnalystFeedback:
    analysis_run_id: int
    domain: str
    label: str
    note: str | None
    updated_at: str


@dataclass(frozen=True)
class AnalystSuppression:
    domain: str
    reason: str
    expires_at: str | None
    updated_at: str


@dataclass(frozen=True)
class RunVerdictChange:
    domain: str
    previous_verdict: str
    current_verdict: str


@dataclass(frozen=True)
class RunComparison:
    current_run_id: int
    previous_run_id: int | None
    new_domains: tuple[str, ...]
    removed_domains: tuple[str, ...]
    verdict_changes: tuple[RunVerdictChange, ...]


_FEEDBACK_LABELS = {
    "confirmed_threat",
    "benign",
    "uncertain",
}
_MAX_FEEDBACK_NOTE_LENGTH = 500
_MAX_SUPPRESSION_REASON_LENGTH = 300


# Storage compatibility: analysis_assessments.ml_probability intentionally keeps
# its legacy SQLite column name. New Python APIs expose the value as ml_score.
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
    model_name TEXT,
    audit_captured_at TEXT,
    artifact_checksum TEXT,
    artifact_schema_version INTEGER,
    high_threshold REAL,
    medium_threshold REAL,
    low_threshold REAL,
    cti_context_json TEXT,
    audit_schema_version INTEGER
);

CREATE TABLE IF NOT EXISTS analysis_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_run_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'domain',
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

CREATE INDEX IF NOT EXISTS idx_analyst_feedback_domain
    ON analyst_feedback(domain);

CREATE TABLE IF NOT EXISTS analyst_suppressions (
    domain TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    expires_at TEXT,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyst_suppressions_expires_at
    ON analyst_suppressions(expires_at);
"""

_ANALYSIS_RUN_MIGRATIONS = {
    "audit_captured_at": "TEXT",
    "artifact_checksum": "TEXT",
    "artifact_schema_version": "INTEGER",
    "high_threshold": "REAL",
    "medium_threshold": "REAL",
    "low_threshold": "REAL",
    "cti_context_json": "TEXT",
    "audit_schema_version": "INTEGER",
}


def _migrate_analysis_runs(connection: sqlite3.Connection) -> None:
    existing = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(analysis_runs)")
    }
    for column, declaration in _ANALYSIS_RUN_MIGRATIONS.items():
        if column in existing:
            continue
        connection.execute(
            f"ALTER TABLE analysis_runs ADD COLUMN {column} {declaration}"
        )


def _migrate_assessment_target_type(connection: sqlite3.Connection) -> None:
    existing = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(analysis_assessments)")
    }
    if "target_type" in existing:
        return
    connection.execute(
        "ALTER TABLE analysis_assessments "
        "ADD COLUMN target_type TEXT NOT NULL DEFAULT 'domain'"
    )
    legacy_rows = connection.execute(
        "SELECT id, analysis_run_id, domain FROM analysis_assessments"
    ).fetchall()
    by_run: dict[int, list[tuple[int, str]]] = {}
    for row_id, run_id, domain in legacy_rows:
        by_run.setdefault(int(run_id), []).append((int(row_id), str(domain)))
    for run_id, rows in by_run.items():
        labels = safe_target_labels(domain for _, domain in rows)
        for row_id, domain in rows:
            target = labels[domain]
            if target.target_type != "ip":
                continue
            connection.execute(
                "UPDATE analysis_assessments "
                "SET domain = ?, target_type = 'ip' WHERE id = ?",
                (target.label, row_id),
            )
            connection.execute(
                "UPDATE analyst_feedback SET domain = ? "
                "WHERE analysis_run_id = ? AND domain = ?",
                (target.label, run_id, domain),
            )



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
        _migrate_analysis_runs(connection)
        _migrate_assessment_target_type(connection)


def _created_at_text(created_at: datetime | None) -> str:
    value = created_at or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("created_at must be timezone-aware")
    return value.isoformat()


def _optional_datetime_text(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_tuple(values: Sequence[str]) -> str:
    return json.dumps(list(values), ensure_ascii=True, separators=(",", ":"))


def _cti_context_json(values: Sequence[CTISourceAudit]) -> str:
    payload = [
        {
            "source": item.source,
            "refreshed_at": item.refreshed_at,
            "record_count": item.record_count,
            "freshness": item.freshness,
        }
        for item in values
    ]
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def save_runtime_analysis(
    db_path: Path,
    result: RuntimeAnalysisResult,
    *,
    model_name: str | None = None,
    audit_metadata: AnalysisAuditMetadata | None = None,
    created_at: datetime | None = None,
) -> int:
    """Persist summary and per-domain assessment data for one analysis run.

    Raw DNS rows, client IPs, and IP targets are intentionally not persisted.
    """
    initialize_database(db_path)

    if (
        audit_metadata is not None
        and model_name is not None
        and model_name != audit_metadata.model_name
    ):
        raise ValueError("model_name does not match audit metadata")
    persisted_model_name = (
        audit_metadata.model_name
        if audit_metadata is not None
        else model_name
    )

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
                model_name,
                audit_captured_at,
                artifact_checksum,
                artifact_schema_version,
                high_threshold,
                medium_threshold,
                low_threshold,
                cti_context_json,
                audit_schema_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                persisted_model_name,
                (
                    audit_metadata.captured_at
                    if audit_metadata is not None
                    else None
                ),
                (
                    audit_metadata.artifact_checksum
                    if audit_metadata is not None
                    else None
                ),
                (
                    audit_metadata.artifact_schema_version
                    if audit_metadata is not None
                    else None
                ),
                (
                    audit_metadata.high_threshold
                    if audit_metadata is not None
                    else None
                ),
                (
                    audit_metadata.medium_threshold
                    if audit_metadata is not None
                    else None
                ),
                (
                    audit_metadata.low_threshold
                    if audit_metadata is not None
                    else None
                ),
                (
                    _cti_context_json(audit_metadata.cti_sources)
                    if audit_metadata is not None
                    else None
                ),
                (
                    audit_metadata.audit_schema_version
                    if audit_metadata is not None
                    else None
                ),
            ),
        )
        run_id = int(cursor.lastrowid)

        rows = []
        targets = safe_target_labels(item.domain for item in result.assessments)
        for assessment in result.assessments:
            behavior = assessment.behavior
            target = targets[assessment.domain]
            rows.append(
                (
                    run_id,
                    target.label,
                    target.target_type,
                    assessment.verdict.value,
                    assessment.ml_score,
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
                target_type,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    return run_id


def _decode_cti_context(value: str | None) -> tuple[CTISourceAudit, ...]:
    if value is None:
        return ()
    decoded = json.loads(value)
    if not isinstance(decoded, list):
        raise TypeError("persisted CTI audit context must be a list")
    rows: list[CTISourceAudit] = []
    for item in decoded:
        if not isinstance(item, dict):
            raise TypeError("persisted CTI audit context items must be objects")
        try:
            rows.append(
                CTISourceAudit(
                    source=str(item["source"]),
                    refreshed_at=str(item["refreshed_at"]),
                    record_count=int(item["record_count"]),
                    freshness=str(item["freshness"]),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("persisted CTI audit context is invalid") from error
    return tuple(rows)


def _optional_float(value: object) -> float | None:
    return float(value) if value is not None else None


def _optional_int(value: object) -> int | None:
    return int(value) if value is not None else None


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
        audit_captured_at=row["audit_captured_at"],
        artifact_checksum=row["artifact_checksum"],
        artifact_schema_version=_optional_int(row["artifact_schema_version"]),
        high_threshold=_optional_float(row["high_threshold"]),
        medium_threshold=_optional_float(row["medium_threshold"]),
        low_threshold=_optional_float(row["low_threshold"]),
        cti_sources=_decode_cti_context(row["cti_context_json"]),
        audit_schema_version=_optional_int(row["audit_schema_version"]),
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
            target_type=str(row["target_type"]),
            verdict=str(row["verdict"]),
            ml_score=(
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
    if not isinstance(label, str):
        raise TypeError("analyst feedback label must be a string")
    if label not in _FEEDBACK_LABELS:
        raise ValueError("unsupported analyst feedback label")
    if not isinstance(domain, str):
        raise TypeError("feedback domain must be a string")
    if not domain.strip():
        raise ValueError("feedback domain must be a non-empty string")
    if note is not None and not isinstance(note, str):
        raise TypeError("analyst feedback note must be a string")

    normalized_domain = domain.strip()
    normalized_note = note.strip() if note is not None else None
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


def save_bulk_analyst_feedback(
    db_path: Path,
    run_id: int,
    domains: Sequence[str],
    label: str,
    *,
    note: str | None = None,
    updated_at: datetime | None = None,
) -> list[AnalystFeedback]:
    """Apply one analyst label to an explicit set of findings in one run."""
    if not isinstance(label, str):
        raise TypeError("analyst feedback label must be a string")
    if label not in _FEEDBACK_LABELS:
        raise ValueError("unsupported analyst feedback label")
    if note is not None and not isinstance(note, str):
        raise TypeError("analyst feedback note must be a string")

    normalized_domains = tuple(
        sorted(
            {
                domain.strip()
                for domain in domains
                if isinstance(domain, str) and domain.strip()
            }
        )
    )
    if not normalized_domains:
        raise ValueError("at least one feedback domain must be selected")

    normalized_note = note.strip() if note is not None else None
    if normalized_note == "":
        normalized_note = None
    if (
        normalized_note is not None
        and len(normalized_note) > _MAX_FEEDBACK_NOTE_LENGTH
    ):
        raise ValueError("analyst feedback note is too long")

    initialize_database(db_path)
    timestamp = _feedback_time_text(updated_at)
    placeholders = ",".join("?" for _ in normalized_domains)

    with _connect(Path(db_path)) as connection:
        existing = {
            str(row[0])
            for row in connection.execute(
                f"""
                SELECT domain
                FROM analysis_assessments
                WHERE analysis_run_id = ?
                  AND domain IN ({placeholders})
                """,
                (run_id, *normalized_domains),
            )
        }
        missing = sorted(set(normalized_domains) - existing)
        if missing:
            raise ValueError(
                "feedback domains are not part of the analysis run: "
                + ", ".join(missing)
            )

        connection.executemany(
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
            [
                (run_id, domain, label, normalized_note, timestamp)
                for domain in normalized_domains
            ],
        )

    return [
        AnalystFeedback(
            analysis_run_id=run_id,
            domain=domain,
            label=label,
            note=normalized_note,
            updated_at=timestamp,
        )
        for domain in normalized_domains
    ]


def delete_analysis_run(db_path: Path, run_id: int) -> bool:
    """Delete exactly one saved analysis run and its cascading local context."""
    if not isinstance(run_id, int) or isinstance(run_id, bool):
        raise TypeError("run_id must be an integer")
    initialize_database(db_path)
    with _connect(Path(db_path)) as connection:
        cursor = connection.execute(
            "DELETE FROM analysis_runs WHERE id = ?",
            (run_id,),
        )
    return cursor.rowcount > 0


def apply_history_retention(
    db_path: Path,
    *,
    keep_latest: int,
) -> tuple[int, ...]:
    """Delete older saved runs while always retaining at least one run."""
    if not isinstance(keep_latest, int) or isinstance(keep_latest, bool):
        raise TypeError("keep_latest must be an integer")
    if keep_latest < 1:
        raise ValueError("keep_latest must be at least 1")

    initialize_database(db_path)
    with _connect(Path(db_path)) as connection:
        run_ids = [
            int(row[0])
            for row in connection.execute(
                "SELECT id FROM analysis_runs ORDER BY id DESC"
            )
        ]
        delete_ids = run_ids[keep_latest:]
        if delete_ids:
            placeholders = ",".join("?" for _ in delete_ids)
            connection.execute(
                f"DELETE FROM analysis_runs WHERE id IN ({placeholders})",
                tuple(delete_ids),
            )

    return tuple(delete_ids)


def compare_analysis_runs(
    db_path: Path,
    current_run_id: int,
    *,
    previous_run_id: int | None = None,
) -> RunComparison:
    """Compare domain assessments across runs; IP target labels are run-local."""
    initialize_database(db_path)

    with _connect(Path(db_path)) as connection:
        current_exists = connection.execute(
            "SELECT 1 FROM analysis_runs WHERE id = ?",
            (current_run_id,),
        ).fetchone()
        if current_exists is None:
            raise ValueError("current analysis run does not exist")

        resolved_previous = previous_run_id
        if resolved_previous is None:
            row = connection.execute(
                """
                SELECT id
                FROM analysis_runs
                WHERE id < ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (current_run_id,),
            ).fetchone()
            resolved_previous = int(row[0]) if row is not None else None
        elif resolved_previous == current_run_id:
            raise ValueError("previous run must differ from current run")
        else:
            previous_exists = connection.execute(
                "SELECT 1 FROM analysis_runs WHERE id = ?",
                (resolved_previous,),
            ).fetchone()
            if previous_exists is None:
                raise ValueError("previous analysis run does not exist")

        current_rows = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                """
                SELECT domain, verdict
                FROM analysis_assessments
                WHERE analysis_run_id = ? AND target_type = 'domain'
                """,
                (current_run_id,),
            )
        }
        previous_rows: dict[str, str] = {}
        if resolved_previous is not None:
            previous_rows = {
                str(row[0]): str(row[1])
                for row in connection.execute(
                    """
                    SELECT domain, verdict
                    FROM analysis_assessments
                    WHERE analysis_run_id = ? AND target_type = 'domain'
                    """,
                    (resolved_previous,),
                )
            }

    new_domains = tuple(sorted(set(current_rows) - set(previous_rows)))
    removed_domains = tuple(sorted(set(previous_rows) - set(current_rows)))
    verdict_changes = tuple(
        RunVerdictChange(
            domain=domain,
            previous_verdict=previous_rows[domain],
            current_verdict=current_rows[domain],
        )
        for domain in sorted(set(current_rows) & set(previous_rows))
        if current_rows[domain] != previous_rows[domain]
    )
    return RunComparison(
        current_run_id=current_run_id,
        previous_run_id=resolved_previous,
        new_domains=new_domains,
        removed_domains=removed_domains,
        verdict_changes=verdict_changes,
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

def get_latest_analyst_feedback_for_domains(
    db_path: Path,
    domains: Sequence[str],
) -> dict[str, AnalystFeedback]:
    """Return the latest saved analyst review for each requested domain."""
    normalized_domains = sorted(
        {
            domain.strip().casefold().removesuffix(".")
            for domain in domains
            if isinstance(domain, str) and domain.strip()
        }
    )
    if not normalized_domains:
        return {}

    initialize_database(db_path)
    placeholders = ", ".join("?" for _ in normalized_domains)

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT
                analysis_run_id,
                domain,
                label,
                note,
                updated_at
            FROM analyst_feedback AS feedback
            WHERE domain IN ({placeholders})
                AND EXISTS (
                    SELECT 1
                    FROM analysis_assessments AS assessment
                    WHERE assessment.analysis_run_id = feedback.analysis_run_id
                        AND assessment.domain = feedback.domain
                        AND assessment.target_type = 'domain'
                )
            ORDER BY
                domain ASC,
                julianday(updated_at) DESC,
                analysis_run_id DESC
            """,
            tuple(normalized_domains),
        ).fetchall()

    latest: dict[str, AnalystFeedback] = {}
    for row in rows:
        domain = str(row["domain"])
        if domain in latest:
            continue
        latest[domain] = AnalystFeedback(
            analysis_run_id=int(row["analysis_run_id"]),
            domain=domain,
            label=str(row["label"]),
            note=row["note"],
            updated_at=str(row["updated_at"]),
        )

    return latest


def _suppression_time_text(value: datetime | None) -> str:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("suppression timestamps must be timezone-aware")
    return timestamp.isoformat()


def save_analyst_suppression(
    db_path: Path,
    domain: str,
    reason: str,
    *,
    expires_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> AnalystSuppression:
    """Create or replace one local domain suppression policy."""
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("suppression domain must be a non-empty string")
    if not isinstance(reason, str):
        raise TypeError("suppression reason must be a string")

    normalized_domain = domain.strip().casefold().removesuffix(".")
    normalized_reason = reason.strip()
    if not normalized_reason:
        raise ValueError("suppression reason must be non-empty")
    if len(normalized_reason) > _MAX_SUPPRESSION_REASON_LENGTH:
        raise ValueError("suppression reason is too long")

    expiry_text = (
        _suppression_time_text(expires_at)
        if expires_at is not None
        else None
    )
    updated_text = _suppression_time_text(updated_at)

    initialize_database(db_path)
    with _connect(Path(db_path)) as connection:
        connection.execute(
            """
            INSERT INTO analyst_suppressions (
                domain,
                reason,
                expires_at,
                updated_at
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                reason = excluded.reason,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at
            """,
            (
                normalized_domain,
                normalized_reason,
                expiry_text,
                updated_text,
            ),
        )

    return AnalystSuppression(
        domain=normalized_domain,
        reason=normalized_reason,
        expires_at=expiry_text,
        updated_at=updated_text,
    )


def remove_analyst_suppression(db_path: Path, domain: str) -> bool:
    """Remove one local suppression policy if it exists."""
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("suppression domain must be a non-empty string")

    normalized_domain = domain.strip().casefold().removesuffix(".")
    initialize_database(db_path)
    with _connect(Path(db_path)) as connection:
        cursor = connection.execute(
            "DELETE FROM analyst_suppressions WHERE domain = ?",
            (normalized_domain,),
        )
    return cursor.rowcount > 0


def get_active_analyst_suppressions(
    db_path: Path,
    domains: Sequence[str] | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, AnalystSuppression]:
    """Return active local suppressions, optionally limited to domains."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    normalized_domains = None
    if domains is not None:
        normalized_domains = sorted(
            {
                domain.strip().casefold().removesuffix(".")
                for domain in domains
                if isinstance(domain, str) and domain.strip()
            }
        )
        if not normalized_domains:
            return {}

    initialize_database(db_path)
    parameters: tuple[object, ...]
    where = ""
    if normalized_domains is None:
        parameters = (current.isoformat(),)
    else:
        placeholders = ", ".join("?" for _ in normalized_domains)
        where = f"AND domain IN ({placeholders})"
        parameters = (
            current.isoformat(),
            *normalized_domains,
        )

    with _connect(Path(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            f"""
            SELECT domain, reason, expires_at, updated_at
            FROM analyst_suppressions
            WHERE
                (expires_at IS NULL OR julianday(expires_at) > julianday(?))
                {where}
            ORDER BY domain ASC
            """,
            parameters,
        ).fetchall()

    return {
        str(row["domain"]): AnalystSuppression(
            domain=str(row["domain"]),
            reason=str(row["reason"]),
            expires_at=row["expires_at"],
            updated_at=str(row["updated_at"]),
        )
        for row in rows
    }

