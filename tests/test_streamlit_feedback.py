from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import MLThresholds, assess_dns_domains
from threatfusion.persistence import (
    get_analysis_assessments,
    get_analyst_feedback,
    save_analyst_feedback,
    save_analyst_suppression,
    save_runtime_analysis,
)
from threatfusion.runtime_analysis import RuntimeAnalysisResult


@pytest.fixture
def feedback_app(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    app_module = importlib.import_module("streamlit_app")
    db_path = tmp_path / "history.sqlite"
    monkeypatch.setenv("THREATFUSION_DB_PATH", str(db_path))
    monkeypatch.setenv("THREATFUSION_MODEL_DIR", str(tmp_path / "model"))
    monkeypatch.setenv(
        "THREATFUSION_EVALUATION_REPORT", str(tmp_path / "holdout.json")
    )
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "0")
    artifact = SimpleNamespace(metadata=SimpleNamespace(model_name="test-model"))
    monkeypatch.setattr(app_module, "_load_artifact", lambda path: artifact)
    monkeypatch.setattr(app_module, "list_cti_cache_status", lambda path: [])
    monkeypatch.setattr(app_module, "load_ioc_records", lambda path: [])

    events = (DNSEvent(query_name="a.example"), DNSEvent(query_name="b.example"))
    scores = {"a.example": 0.9, "b.example": 0.55}
    result = RuntimeAnalysisResult(
        events=events,
        matches=(),
        ml_scores=scores,
        assessments=tuple(
            assess_dns_domains(
                events,
                (),
                ml_scores=scores,
                ml_thresholds=MLThresholds(0.8, 0.6, 0.5),
            )
        ),
    )
    run_id = save_runtime_analysis(db_path, result)
    return app_module, db_path, result, run_id


def test_public_mode_never_reads_or_writes_history_or_feedback(
    feedback_app, monkeypatch
) -> None:
    app_module, db_path, result, run_id = feedback_app
    save_analyst_feedback(
        db_path, run_id, "a.example", "benign", note="PRIVATE-ANALYST-NOTE"
    )
    original_database = db_path.read_bytes()
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "1")

    def forbidden(*args, **kwargs):
        raise AssertionError("Public mode must not access analysis history")

    for name in (
        "list_analysis_runs",
        "get_analysis_assessments",
        "get_analyst_feedback",
        "get_latest_analyst_feedback_for_domains",
        "get_active_analyst_suppressions",
        "save_runtime_analysis",
        "save_analyst_feedback",
        "save_bulk_analyst_feedback",
        "delete_analysis_run",
        "apply_history_retention",
        "compare_analysis_runs",
        "save_analyst_suppression",
        "remove_analyst_suppression",
    ):
        monkeypatch.setattr(app_module, name, forbidden)

    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["analysis_result"] = result
    app.run(timeout=15)

    assert not app.exception
    assert "Analysis overview" in [item.value for item in app.subheader]
    assert "Analysis history" not in [tab.label for tab in app.tabs]
    assert "Save aggregate analysis history" not in [b.label for b in app.button]
    assert "Save analyst feedback" not in [b.label for b in app.button]
    assert not app.text_area
    assert all(
        "Analyst note" not in frame.value.columns for frame in app.dataframe
    )
    assert db_path.read_bytes() == original_database




def test_live_analysis_surfaces_previous_review_and_local_suppression(
    feedback_app,
) -> None:
    _, db_path, result, run_id = feedback_app
    save_analyst_feedback(
        db_path,
        run_id,
        "a.example",
        "benign",
        note="Expected vendor domain",
    )
    save_analyst_suppression(
        db_path,
        "a.example",
        "Approved vendor traffic",
    )

    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["analysis_result"] = result
    app.run(timeout=15)

    assert not app.exception
    info_values = [item.value for item in app.info]
    warning_values = [item.value for item in app.warning]
    assert any("Previous analyst review: Benign" in value for value in info_values)
    assert any(
        "Locally suppressed from the priority queue" in value
        for value in warning_values
    )

def test_local_feedback_form_upserts_and_isolates_run_and_domain(feedback_app):
    _, db_path, result, first_run_id = feedback_app
    second_run_id = save_runtime_analysis(db_path, result)
    originals = get_analysis_assessments(db_path, second_run_id)
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.run(timeout=15)
    assert not app.exception

    domain_key = f"feedback_domain_{second_run_id}"
    assert app.selectbox(key=domain_key).value == "a.example"
    label = next(item for item in app.selectbox if item.label == "Analyst label")
    label.select("Benign")
    next(
        item for item in app.text_area if item.label == "Optional analyst note"
    ).input("Expected service")
    next(b for b in app.button if b.label == "Save analyst feedback").click()
    app.run(timeout=15)
    assert not app.exception

    saved = get_analyst_feedback(db_path, second_run_id)
    assert [(item.domain, item.label, item.note) for item in saved] == [
        ("a.example", "benign", "Expected service")
    ]
    findings = next(
        frame.value for frame in app.dataframe if "Analyst feedback" in frame.value
    ).set_index("Domain")
    assert findings.loc["a.example", "Analyst feedback"] == "Benign"
    assert findings.loc["a.example", "Verdict"] == "High Risk"

    label = next(item for item in app.selectbox if item.label == "Analyst label")
    label.select("Confirmed Threat")
    next(
        item for item in app.text_area if item.label == "Optional analyst note"
    ).input("Rechecked")
    next(b for b in app.button if b.label == "Save analyst feedback").click()
    app.run(timeout=15)
    assert not app.exception
    updated = get_analyst_feedback(db_path, second_run_id)
    assert len(updated) == 1
    assert updated[0].label == "confirmed_threat"
    assert updated[0].note == "Rechecked"
    assert get_analysis_assessments(db_path, second_run_id) == originals

    app.selectbox(key=domain_key).select("b.example").run(timeout=15)
    assert not app.exception
    assert next(
        item for item in app.text_area if item.label == "Optional analyst note"
    ).value == ""
    label = next(item for item in app.selectbox if item.label == "Analyst label")
    assert label.value == "Uncertain"

    run_selector = next(
        item for item in app.selectbox if item.label == "Inspect saved run"
    )
    run_selector.select(first_run_id).run(timeout=15)
    assert not app.exception
    assert next(
        item for item in app.text_area if item.label == "Optional analyst note"
    ).value == ""
    assert get_analyst_feedback(db_path, first_run_id) == []
