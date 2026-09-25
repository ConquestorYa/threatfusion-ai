from __future__ import annotations

from datetime import datetime, timezone

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.dns_behavior import DomainBehavior
from threatfusion.hybrid_assessment import HybridAssessment, HybridVerdict
from threatfusion.persistence import (
    apply_history_retention,
    compare_analysis_runs,
    delete_analysis_run,
    get_analysis_assessments,
    get_analysis_run,
    get_analyst_feedback,
    list_analysis_runs,
    save_analyst_feedback,
    save_bulk_analyst_feedback,
    save_runtime_analysis,
)
from threatfusion.runtime_analysis import RuntimeAnalysisResult


def _result(rows: list[tuple[str, HybridVerdict]]) -> RuntimeAnalysisResult:
    events = tuple(DNSEvent(query_name=domain) for domain, _ in rows)
    assessments = tuple(
        HybridAssessment(
            domain=domain,
            verdict=verdict,
            known_ioc_sources=(),
            known_match_types=(),
            ml_probability=None,
            ml_tier=None,
            behavior=DomainBehavior(
                domain=domain,
                event_count=1,
                unique_client_count=0,
                unique_response_ip_count=0,
                query_types=(),
                first_seen=None,
                last_seen=None,
                observed_span_seconds=None,
            ),
            behavior_signals=(),
            reasons=(),
        )
        for domain, verdict in rows
    )
    return RuntimeAnalysisResult(
        events=events,
        matches=(),
        ml_probabilities={},
        assessments=assessments,
    )


def test_bulk_feedback_updates_only_explicit_selected_findings(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(
        db_path,
        _result(
            [
                ("a.example", HybridVerdict.REVIEW),
                ("b.example", HybridVerdict.LOW),
                ("c.example", HybridVerdict.LOW),
            ]
        ),
    )
    original = get_analysis_assessments(db_path, run_id)
    timestamp = datetime(2026, 9, 25, 20, 0, tzinfo=timezone.utc)

    saved = save_bulk_analyst_feedback(
        db_path,
        run_id,
        ["b.example", "a.example", "a.example"],
        "benign",
        note="Reviewed together",
        updated_at=timestamp,
    )

    assert [item.domain for item in saved] == ["a.example", "b.example"]
    assert [item.domain for item in get_analyst_feedback(db_path, run_id)] == [
        "a.example",
        "b.example",
    ]
    assert all(item.label == "benign" for item in saved)
    assert get_analysis_assessments(db_path, run_id) == original


def test_bulk_feedback_rejects_unknown_domain_without_partial_write(
    tmp_path,
) -> None:
    db_path = tmp_path / "history.sqlite"
    run_id = save_runtime_analysis(
        db_path,
        _result([("a.example", HybridVerdict.REVIEW)]),
    )

    with pytest.raises(ValueError, match="not part"):
        save_bulk_analyst_feedback(
            db_path,
            run_id,
            ["a.example", "missing.example"],
            "uncertain",
        )

    assert get_analyst_feedback(db_path, run_id) == []


def test_delete_analysis_run_is_exact_and_cascades_feedback(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    first = save_runtime_analysis(
        db_path,
        _result([("a.example", HybridVerdict.REVIEW)]),
    )
    second = save_runtime_analysis(
        db_path,
        _result([("b.example", HybridVerdict.LOW)]),
    )
    save_analyst_feedback(db_path, first, "a.example", "uncertain")

    assert delete_analysis_run(db_path, first)
    assert not delete_analysis_run(db_path, first)
    assert get_analysis_run(db_path, first) is None
    assert get_analysis_assessments(db_path, first) == []
    assert get_analyst_feedback(db_path, first) == []
    assert get_analysis_run(db_path, second) is not None


def test_retention_keeps_latest_runs_and_never_allows_zero(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    run_ids = [
        save_runtime_analysis(
            db_path,
            _result([(f"{index}.example", HybridVerdict.LOW)]),
        )
        for index in range(4)
    ]

    deleted = apply_history_retention(db_path, keep_latest=2)

    assert deleted == (run_ids[1], run_ids[0])
    assert [item.id for item in list_analysis_runs(db_path)] == [
        run_ids[3],
        run_ids[2],
    ]
    with pytest.raises(ValueError, match="at least 1"):
        apply_history_retention(db_path, keep_latest=0)


def test_run_comparison_surfaces_new_removed_and_verdict_changes(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    previous = save_runtime_analysis(
        db_path,
        _result(
            [
                ("a.example", HybridVerdict.REVIEW),
                ("b.example", HybridVerdict.LOW),
            ]
        ),
    )
    current = save_runtime_analysis(
        db_path,
        _result(
            [
                ("a.example", HybridVerdict.HIGH_RISK),
                ("c.example", HybridVerdict.LOW),
            ]
        ),
    )

    comparison = compare_analysis_runs(db_path, current)

    assert comparison.previous_run_id == previous
    assert comparison.new_domains == ("c.example",)
    assert comparison.removed_domains == ("b.example",)
    assert len(comparison.verdict_changes) == 1
    change = comparison.verdict_changes[0]
    assert change.domain == "a.example"
    assert change.previous_verdict == "review"
    assert change.current_verdict == "high_risk"


def test_first_saved_run_compares_against_empty_history(tmp_path) -> None:
    db_path = tmp_path / "history.sqlite"
    current = save_runtime_analysis(
        db_path,
        _result([("a.example", HybridVerdict.LOW)]),
    )

    comparison = compare_analysis_runs(db_path, current)

    assert comparison.previous_run_id is None
    assert comparison.new_domains == ("a.example",)
    assert comparison.removed_domains == ()
    assert comparison.verdict_changes == ()
