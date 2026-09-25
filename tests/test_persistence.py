from __future__ import annotations

import socket
import sqlite3
from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import DomainBehavior
from threatfusion.hybrid_assessment import HybridAssessment, HybridVerdict
from threatfusion.matching import DNSIOCMatch
from threatfusion.models import IOCRecord, IOCType
from threatfusion.persistence import (
    get_active_analyst_suppressions,
    get_analysis_assessments,
    get_analysis_run,
    get_analyst_feedback,
    get_latest_analyst_feedback_for_domains,
    initialize_database,
    list_analysis_runs,
    remove_analyst_suppression,
    save_analyst_feedback,
    save_analyst_suppression,
    save_runtime_analysis,
)
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def make_result() -> RuntimeAnalysisResult:
    first_event = DNSEvent(
        query_name="known.bad",
        timestamp=datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc),
        client_ip="10.0.0.77",
        query_type="A",
        response_ip="203.0.113.7",
    )
    second_event = DNSEvent(
        query_name="review.example",
        timestamp=datetime(2026, 9, 24, 10, 1, tzinfo=timezone.utc),
        client_ip="10.0.0.88",
        query_type="AAAA",
        response_ip="2001:db8::1",
    )
    indicator = IOCRecord("known.bad", IOCType.DOMAIN, "ThreatFox")
    match = DNSIOCMatch(
        event=first_event,
        indicator=indicator,
        match_type="query_domain",
    )

    known_behavior = DomainBehavior(
        domain="known.bad",
        event_count=1,
        unique_client_count=1,
        unique_response_ip_count=1,
        query_types=("A",),
        first_seen=first_event.timestamp,
        last_seen=first_event.timestamp,
        observed_span_seconds=0.0,
    )
    review_behavior = DomainBehavior(
        domain="review.example",
        event_count=1,
        unique_client_count=1,
        unique_response_ip_count=1,
        query_types=("AAAA",),
        first_seen=second_event.timestamp,
        last_seen=second_event.timestamp,
        observed_span_seconds=0.0,
    )

    assessments = (
        HybridAssessment(
            domain="known.bad",
            verdict=HybridVerdict.KNOWN_THREAT,
            known_ioc_sources=("ThreatFox",),
            known_match_types=("query_domain",),
            ml_score=0.20,
            ml_tier=None,
            behavior=known_behavior,
            behavior_signals=(),
            reasons=("known_ioc_match",),
        ),
        HybridAssessment(
            domain="review.example",
            verdict=HybridVerdict.REVIEW,
            known_ioc_sources=(),
            known_match_types=(),
            ml_score=0.55,
            ml_tier="low",
            behavior=review_behavior,
            behavior_signals=(),
            reasons=("ml_low_confidence",),
        ),
    )

    return RuntimeAnalysisResult(
        events=(first_event, second_event),
        matches=(match,),
        ml_scores={
            "known.bad": 0.20,
            "review.example": 0.55,
        },
        assessments=assessments,
    )


def test_initialize_database_creates_expected_tables(tmp_path) -> None:
    db_path = tmp_path / "nested" / "history.sqlite"

    initialize_database(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

    assert "analysis_runs" in tables
    assert "analysis_assessments" in tables
    assert "analyst_feedback" in tables
    assert "analyst_suppressions" in tables


def test_save_runtime_analysis_persists_summary_counts(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    created_at = datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc)

    run_id = save_runtime_analysis(
        db_path,
        make_result(),
        model_name="lr_char_2_6_sublinear_balanced",
        created_at=created_at,
    )
    summary = get_analysis_run(db_path, run_id)

    assert summary is not None
    assert summary.created_at == created_at.isoformat()
    assert summary.event_count == 2
    assert summary.match_count == 1
    assert summary.assessment_count == 2
    assert summary.known_threat_count == 1
    assert summary.high_risk_count == 0
    assert summary.review_count == 1
    assert summary.low_count == 0
    assert summary.model_name == "lr_char_2_6_sublinear_balanced"


def test_assessment_roundtrip_preserves_aggregate_evidence(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())

    rows = get_analysis_assessments(db_path, run_id)

    assert [row.domain for row in rows] == ["known.bad", "review.example"]

    known = rows[0]
    assert known.verdict == "known_threat"
    assert known.ml_score == pytest.approx(0.20)
    assert known.ml_probability == known.ml_score
    assert known.query_types == ("A",)
    assert known.known_ioc_sources == ("ThreatFox",)
    assert known.known_match_types == ("query_domain",)
    assert known.reasons == ("known_ioc_match",)

    review = rows[1]
    assert review.verdict == "review"
    assert review.ml_tier == "low"
    assert review.reasons == ("ml_low_confidence",)


def test_legacy_ml_probability_storage_column_is_preserved(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    save_runtime_analysis(db_path, make_result())

    with sqlite3.connect(db_path) as connection:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(analysis_assessments)")
        }
        stored_score = connection.execute(
            "SELECT ml_probability FROM analysis_assessments "
            "WHERE domain = ?",
            ("known.bad",),
        ).fetchone()[0]

    assert "ml_probability" in columns
    assert "ml_score" not in columns
    assert stored_score == pytest.approx(0.20)


def test_raw_dns_rows_and_client_ips_are_not_persisted(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    save_runtime_analysis(db_path, make_result())

    with sqlite3.connect(db_path) as connection:
        dump = "\n".join(connection.iterdump())

    assert "10.0.0.77" not in dump
    assert "10.0.0.88" not in dump
    assert "DNSEvent" not in dump


def test_list_analysis_runs_is_newest_first(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    first_id = save_runtime_analysis(
        db_path,
        make_result(),
        created_at=datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc),
    )
    second_id = save_runtime_analysis(
        db_path,
        make_result(),
        created_at=datetime(2026, 9, 24, 18, 1, tzinfo=timezone.utc),
    )

    rows = list_analysis_runs(db_path)

    assert [row.id for row in rows] == [second_id, first_id]


def test_missing_run_returns_none_and_no_assessments(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"

    assert get_analysis_run(db_path, 999) is None
    assert get_analysis_assessments(db_path, 999) == []


def test_naive_created_at_is_rejected(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"

    with pytest.raises(ValueError, match="timezone-aware"):
        save_runtime_analysis(
            db_path,
            make_result(),
            created_at=datetime(2026, 9, 24, 18, 0, tzinfo=timezone.utc).replace(
                tzinfo=None
            ),
        )


def test_persistence_does_not_perform_networking(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise AssertionError("persistence must not use networking")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    monkeypatch.setattr(socket, "create_connection", fail)

    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    save_analyst_feedback(
        db_path,
        run_id,
        "review.example",
        "uncertain",
        note="Local review only",
    )

    assert get_analysis_run(db_path, run_id) is not None
    feedback = get_analyst_feedback(db_path, run_id)
    assert len(feedback) == 1
    assert feedback[0].domain == "review.example"
    latest = get_latest_analyst_feedback_for_domains(
        db_path,
        ["review.example"],
    )
    assert latest["review.example"].label == "uncertain"

    save_analyst_suppression(
        db_path,
        "review.example",
        "Local expected traffic",
    )
    assert "review.example" in get_active_analyst_suppressions(db_path)


def test_latest_feedback_is_returned_across_saved_runs(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    first_run = save_runtime_analysis(db_path, make_result())
    second_run = save_runtime_analysis(db_path, make_result())
    first_time = datetime(2026, 9, 24, 19, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 24, 20, 0, tzinfo=timezone.utc)

    save_analyst_feedback(
        db_path,
        second_run,
        "review.example",
        "uncertain",
        note="Initial review",
        updated_at=first_time,
    )
    latest = save_analyst_feedback(
        db_path,
        first_run,
        "review.example",
        "benign",
        note="Known internal service",
        updated_at=second_time,
    )

    rows = get_latest_analyst_feedback_for_domains(
        db_path,
        ["review.example", "missing.example"],
    )

    assert rows == {"review.example": latest}


def test_local_suppression_roundtrip_expiry_and_remove(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    now = datetime(2026, 9, 24, 20, 0, tzinfo=timezone.utc)
    expires = datetime(2026, 9, 25, 20, 0, tzinfo=timezone.utc)

    saved = save_analyst_suppression(
        db_path,
        "Expected.Example.",
        "Expected vendor telemetry",
        expires_at=expires,
        updated_at=now,
    )

    active = get_active_analyst_suppressions(
        db_path,
        ["expected.example"],
        now=now,
    )
    assert active == {"expected.example": saved}

    assert get_active_analyst_suppressions(
        db_path,
        ["expected.example"],
        now=expires,
    ) == {}

    updated = save_analyst_suppression(
        db_path,
        "expected.example",
        "Approved service",
        updated_at=now,
    )
    assert updated.expires_at is None
    assert get_active_analyst_suppressions(
        db_path,
        ["expected.example"],
        now=expires,
    ) == {"expected.example": updated}

    assert remove_analyst_suppression(db_path, "expected.example")
    assert not remove_analyst_suppression(db_path, "expected.example")
    assert get_active_analyst_suppressions(db_path) == {}


def test_suppression_validation_is_bounded(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"

    with pytest.raises(ValueError, match="reason"):
        save_analyst_suppression(db_path, "example.com", "   ")

    with pytest.raises(ValueError, match="too long"):
        save_analyst_suppression(
            db_path,
            "example.com",
            "x" * 301,
        )

    with pytest.raises(ValueError, match="timezone-aware"):
        save_analyst_suppression(
            db_path,
            "example.com",
            "Temporary exception",
            expires_at=datetime(
                2026,
                9,
                25,
                20,
                0,
                tzinfo=timezone.utc,
            ).replace(tzinfo=None),
        )


def test_analyst_feedback_roundtrip_and_update(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    first_time = datetime(2026, 9, 24, 19, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 24, 19, 5, tzinfo=timezone.utc)

    first = save_analyst_feedback(
        db_path,
        run_id,
        "review.example",
        "uncertain",
        note="Needs manual review",
        updated_at=first_time,
    )
    updated = save_analyst_feedback(
        db_path,
        run_id,
        "review.example",
        "benign",
        note="Expected internal service",
        updated_at=second_time,
    )
    rows = get_analyst_feedback(db_path, run_id)

    assert first.label == "uncertain"
    assert updated.label == "benign"
    assert len(rows) == 1
    assert rows[0].domain == "review.example"
    assert rows[0].label == "benign"
    assert rows[0].note == "Expected internal service"
    assert rows[0].updated_at == second_time.isoformat()


def test_analyst_feedback_is_isolated_by_run_and_domain(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    first_run = save_runtime_analysis(db_path, make_result())
    second_run = save_runtime_analysis(db_path, make_result())
    known_feedback = save_analyst_feedback(
        db_path, first_run, "known.bad", "confirmed_threat"
    )
    save_analyst_feedback(
        db_path, first_run, "review.example", "uncertain"
    )
    second_feedback = save_analyst_feedback(
        db_path,
        second_run,
        "review.example",
        "uncertain",
        note="Separate investigation",
    )

    updated = save_analyst_feedback(
        db_path, first_run, "review.example", "benign"
    )

    assert get_analyst_feedback(db_path, first_run) == [known_feedback, updated]
    assert get_analyst_feedback(db_path, second_run) == [second_feedback]


def test_analyst_feedback_upgrades_existing_history_without_data_loss(
    tmp_path,
) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    original_summary = get_analysis_run(db_path, run_id)
    original_assessments = get_analysis_assessments(db_path, run_id)
    # Earlier history databases contain the run tables but no feedback table.
    with sqlite3.connect(db_path) as connection:
        connection.execute("DROP TABLE analyst_feedback")

    saved = save_analyst_feedback(
        db_path, run_id, "review.example", "uncertain"
    )
    initialize_database(db_path)

    assert list_analysis_runs(db_path) == [original_summary]
    assert get_analysis_assessments(db_path, run_id) == original_assessments
    assert get_analyst_feedback(db_path, run_id) == [saved]


def test_analyst_feedback_rejects_unknown_domain_and_label(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())

    with pytest.raises(ValueError, match="label"):
        save_analyst_feedback(
            db_path,
            run_id,
            "review.example",
            "maybe",
        )

    with pytest.raises(ValueError, match="not part"):
        save_analyst_feedback(
            db_path,
            run_id,
            "missing.example",
            "uncertain",
        )


def test_analyst_feedback_note_is_bounded(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    saved = save_analyst_feedback(
        db_path,
        run_id,
        "review.example",
        "uncertain",
        note="x" * 500,
    )

    assert get_analyst_feedback(db_path, run_id) == [saved]
    assert saved.note == "x" * 500

    with pytest.raises(ValueError, match="too long"):
        save_analyst_feedback(
            db_path,
            run_id,
            "review.example",
            "benign",
            note="x" * 501,
        )

    assert get_analyst_feedback(db_path, run_id) == [saved]


def test_whitespace_note_clears_previous_analyst_note(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    save_analyst_feedback(
        db_path,
        run_id,
        "review.example",
        "uncertain",
        note="Needs investigation",
    )

    cleared = save_analyst_feedback(
        db_path,
        run_id,
        "review.example",
        "benign",
        note=" \n\t ",
    )

    assert cleared.note is None
    assert get_analyst_feedback(db_path, run_id) == [cleared]


def test_analyst_note_is_stored_as_literal_data(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    original_summary = get_analysis_run(db_path, run_id)
    original_assessments = get_analysis_assessments(db_path, run_id)
    note = "Analyst's note'); DROP TABLE analysis_runs; --"

    save_analyst_feedback(
        db_path, run_id, "review.example", "uncertain", note=note
    )

    assert get_analyst_feedback(db_path, run_id)[0].note == note
    assert get_analysis_run(db_path, run_id) == original_summary
    assert get_analysis_assessments(db_path, run_id) == original_assessments


def test_feedback_does_not_change_original_analysis(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(db_path, make_result())
    original_summary = get_analysis_run(db_path, run_id)
    original_assessments = get_analysis_assessments(db_path, run_id)

    save_analyst_feedback(
        db_path,
        run_id,
        "known.bad",
        "benign",
    )

    assert get_analysis_run(db_path, run_id) == original_summary
    assert get_analysis_assessments(db_path, run_id) == original_assessments

    save_analyst_feedback(
        db_path,
        run_id,
        "known.bad",
        "confirmed_threat",
        note="Reviewed again",
    )

    assert get_analysis_run(db_path, run_id) == original_summary
    assert get_analysis_assessments(db_path, run_id) == original_assessments
