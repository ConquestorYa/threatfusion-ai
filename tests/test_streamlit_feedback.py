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
    monkeypatch.setenv("THREATFUSION_EVALUATION_REPORT", str(tmp_path / "holdout.json"))
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "0")
    monkeypatch.setenv("THREATFUSION_MODEL_SHA256", "a" * 64)
    artifact = SimpleNamespace(metadata=SimpleNamespace(model_name="test-model"))
    monkeypatch.setattr(
        app_module,
        "_load_artifact",
        lambda path, expected_checksum=None: artifact,
    )
    monkeypatch.setattr(app_module, "list_cti_cache_status", lambda path: [])
    monkeypatch.setattr(app_module, "load_ioc_records", lambda path: [])
    monkeypatch.setattr(
        app_module,
        "run_startup_refresh_if_enabled",
        lambda *args, **kwargs: (),
    )
    monkeypatch.setattr(
        app_module,
        "start_background_refresh_if_enabled",
        lambda path: False,
    )

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
        owners = [
            app_module,
            importlib.import_module("threatfusion.ui_history"),
            importlib.import_module("threatfusion.ui_investigation"),
        ]
        patched = False
        for owner in owners:
            if hasattr(owner, name):
                monkeypatch.setattr(owner, name, forbidden)
                patched = True
        assert patched, f"Privacy guard is missing its call site: {name}"

    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["analysis_result"] = result
    app.run(timeout=15)

    assert not app.exception
    assert "Priority findings" in [item.value for item in app.subheader]
    assert not any(button.key == "nav_analysis_history" for button in app.button)
    assert "Save aggregate analysis history" not in [b.label for b in app.button]
    assert "Save analyst feedback" not in [b.label for b in app.button]
    assert not app.text_area
    assert all("Analyst note" not in frame.value.columns for frame in app.dataframe)
    assert db_path.read_bytes() == original_database


def test_synthetic_demo_artifact_is_clearly_labeled(feedback_app, monkeypatch):
    app_module, _, _, _ = feedback_app
    artifact = SimpleNamespace(
        metadata=SimpleNamespace(
            model_name="demo-model",
            evaluation_status="demo_only_synthetic",
        )
    )
    monkeypatch.setattr(
        app_module,
        "_load_artifact",
        lambda path, expected_checksum=None: artifact,
    )

    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.run(timeout=15)

    assert not app.exception
    assert any(
        "Demo ML artifact active" in item.value
        and "must not be interpreted as measured model performance" in item.value
        for item in app.warning
    )


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
    app.session_state["workspace_nav"] = "Analysis history"
    app.run(timeout=15)
    assert not app.exception

    domain_key = f"feedback_domain_{second_run_id}"
    assert app.selectbox(key=domain_key).value == "a.example"
    label = next(item for item in app.selectbox if item.label == "Analyst label")
    label.select("Benign")
    next(item for item in app.text_area if item.label == "Optional analyst note").input(
        "Expected service"
    )
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
    assert findings.loc["a.example", "Verdict"] == "Review"

    label = next(item for item in app.selectbox if item.label == "Analyst label")
    label.select("Confirmed Threat")
    next(item for item in app.text_area if item.label == "Optional analyst note").input(
        "Rechecked"
    )
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
    assert (
        next(
            item for item in app.text_area if item.label == "Optional analyst note"
        ).value
        == ""
    )
    label = next(item for item in app.selectbox if item.label == "Analyst label")
    assert label.value == "Uncertain"

    run_selector = next(
        item for item in app.selectbox if item.label == "Inspect saved run"
    )
    run_selector.select(first_run_id).run(timeout=15)
    assert not app.exception
    assert (
        next(
            item for item in app.text_area if item.label == "Optional analyst note"
        ).value
        == ""
    )
    assert get_analyst_feedback(db_path, first_run_id) == []


def test_legacy_theme_state_is_migrated_to_product_theme_name(feedback_app):
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["visual_theme"] = "White"
    app.run(timeout=15)

    assert not app.exception
    assert app.session_state["visual_theme"] == "Midnight"


def test_quick_lookup_is_default_primary_workspace_without_network_activity(
    feedback_app,
):
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.run(timeout=15)

    assert not app.exception
    assert app.button(key="open_quick_lookup_workspace").label == "Open quick lookup"
    assert any(item.label == "URL, domain or IP" for item in app.text_input)
    assert app.button(key="quick_lookup_analyze").label == "Check"
    assert not app.button(key="quick_lookup_analyze").disabled
    assert any(
        "Passive by design" in item.value
        for item in app.caption
    )
    assert any("ThreatFusion AI" in item.value for item in app.markdown)


def test_turkish_mode_localizes_quick_lookup_placeholder(feedback_app):
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)

    assert not app.exception
    lookup = app.text_input(key="quick_lookup_input")
    assert lookup.label == "URL, domain veya IP"
    assert lookup.proto.placeholder == (
        "example.com, 143.20.185.213 veya https://example.com/yol"
    )


def test_quick_lookup_check_uses_current_input_value(feedback_app, monkeypatch):
    app_module, _, _, _ = feedback_app
    calls = []
    result = object()

    def analyze(value, db_path, artifact):
        calls.append(value)
        return result

    monkeypatch.setattr(app_module, "analyze_quick_lookup_from_cache", analyze)
    monkeypatch.setattr(app_module, "render_quick_lookup_result", lambda value: None)

    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.run(timeout=15)
    app.text_input(key="quick_lookup_input").input("example.com").run(timeout=15)
    app.button(key="quick_lookup_analyze").click().run(timeout=15)

    assert not app.exception
    assert calls == ["example.com"]


def test_navigation_preserves_current_analysis_and_format(feedback_app):
    _, _, result, _ = feedback_app
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["analysis_result"] = result
    app.session_state["upload_fingerprint"] = "previous-upload"
    app.session_state["telemetry_format"] = "Zeek dns.log"
    app.run(timeout=15)
    app.button(key="nav_analysis_history").click().run(timeout=15)
    assert not app.exception
    app.button(key="open_telemetry_workspace").click().run(timeout=15)
    assert not app.exception
    assert app.session_state["analysis_result"] == result
    assert app.selectbox(key="telemetry_format").value == "Zeek dns.log"
    assert "Priority findings" in [item.value for item in app.subheader]


def test_changing_source_clears_stale_analysis(feedback_app):
    _, _, result, _ = feedback_app
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["analysis_result"] = result
    app.session_state["upload_fingerprint"] = "old"
    app.session_state["analysis_audit_metadata"] = "old-audit"
    app.run(timeout=15)
    app.selectbox(key="telemetry_format").select("Zeek dns.log").run(timeout=15)
    assert not app.exception
    assert "analysis_result" not in app.session_state
    assert "analysis_audit_metadata" not in app.session_state
    assert app.button(key="analyze_empty").disabled


def test_history_and_evaluation_work_without_model(feedback_app, monkeypatch):
    app_module, _, _, _ = feedback_app

    def unavailable(path, expected_checksum=None):
        raise OSError("Missing artifact")

    monkeypatch.setattr(app_module, "_load_artifact", unavailable)
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["workspace_nav"] = "Model evaluation"
    app.run(timeout=15)
    assert not app.exception
    assert not app.error
    assert any("Final holdout not evaluated" in item.value for item in app.markdown)
    app.button(key="nav_analysis_history").click().run(timeout=15)
    assert not app.exception
    assert app.selectbox(key="feedback_domain_1").value == "a.example"


def test_sidebar_status_is_not_a_dataframe(feedback_app, monkeypatch):
    from datetime import datetime, timezone
    from threatfusion.cti_cache import CTICacheStatus

    app_module, _, _, _ = feedback_app
    monkeypatch.setattr(
        app_module,
        "list_cti_cache_status",
        lambda path: [
            CTICacheStatus(
                source="ThreatFox",
                record_count=8590,
                refreshed_at=datetime.now(timezone.utc).isoformat(),
                inactive_record_count=42,
            ),
        ],
    )
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.run(timeout=15)
    assert not app.exception
    assert not app.sidebar.dataframe
    sidebar_html = " ".join(item.value for item in app.sidebar.markdown)
    assert "8,590 active indicators" in sidebar_html
    assert "Fresh" in sidebar_html
    assert "Not cached" in sidebar_html
    assert any(item.label == "ThreatFox details" for item in app.sidebar.expander)


def test_public_mode_rejects_stale_history_navigation(feedback_app, monkeypatch):
    _, _, result, _ = feedback_app
    monkeypatch.setenv("THREATFUSION_PUBLIC_MODE", "1")
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["workspace_nav"] = "Analysis history"
    app.session_state["analysis_result"] = result
    app.run(timeout=15)
    assert not app.exception
    assert app.session_state["workspace_nav"] == "Analyze telemetry"
    assert not any(button.key == "nav_analysis_history" for button in app.button)
    assert not app.text_area


def test_result_filters_do_not_change_underlying_report(feedback_app):
    from threatfusion.reporting import build_analysis_report

    _, _, result, _ = feedback_app
    from datetime import datetime, timezone

    generated_at = datetime(2026, 9, 26, tzinfo=timezone.utc)
    before = build_analysis_report(
        result, model_name="test-model", generated_at=generated_at
    )
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["analysis_result"] = result
    app.run(timeout=15)
    app.text_input(key="live_findings_search").input("a.example").run(timeout=15)
    assert not app.exception
    frame = next(
        frame.value
        for frame in app.dataframe
        if list(frame.value.columns)
        == ["Domain", "Verdict", "ML tier", "DNS events", "Known CTI sources"]
    )
    assert frame["Domain"].tolist() == ["a.example"]
    assert (
        build_analysis_report(
            app.session_state["analysis_result"],
            model_name="test-model",
            generated_at=generated_at,
        )
        == before
    )


def test_auto_detect_is_default_and_uses_raw_upload_bytes(
    feedback_app,
    monkeypatch,
) -> None:
    import io
    from threatfusion.dns import DNSParseDiagnostics
    from threatfusion.dns_ingest import DNSInputDetection

    app_module, _, result, _ = feedback_app
    raw = b"Query Domain,Record Class\\nexample.com,A\\n"
    upload = io.BytesIO(raw)
    upload.name = "dns_logs.csv"
    calls = []
    diagnostics = DNSParseDiagnostics(
        total_rows=1,
        accepted_rows=1,
        skipped_missing_query_name=0,
        invalid_timestamps=0,
        invalid_response_ips=0,
    )
    detection = DNSInputDetection(
        format_name="Delimited DNS table",
        detail="delimiter and DNS columns detected automatically",
        encoding="utf-8-sig",
    )

    def analyze(value, filename, indicators, artifact):
        calls.append((value, filename))
        return result, diagnostics, detection

    monkeypatch.setattr(
        app_module.st,
        "file_uploader",
        lambda *a, **kw: upload,
    )
    monkeypatch.setattr(
        app_module,
        "analyze_dns_upload_with_diagnostics",
        analyze,
    )
    monkeypatch.setattr(
        app_module,
        "capture_analysis_audit_metadata",
        lambda *a, **kw: "audit",
    )

    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["workspace_nav"] = "Analyze telemetry"
    app.run(timeout=15)

    assert app.selectbox(key="telemetry_format").value == "Auto-detect"
    next(button for button in app.button if button.label == "Analyze").click()
    app.run(timeout=15)

    assert not app.exception
    assert calls == [(raw, "dns_logs.csv")]
    assert app.session_state["analysis_result"] == result
    assert app.session_state["dns_input_detection"] == detection


@pytest.mark.parametrize(
    ("telemetry_format", "analyzer_name", "content"),
    [
        ("Generic DNS CSV", "analyze_dns_csv_with_diagnostics", b"query_name\na.example\n"),
        ("Zeek dns.log", "analyze_zeek_dns_log_with_diagnostics", b"#fields\tquery\na.example\n"),
        ("Pi-hole FTL database", "analyze_pihole_query_db_with_diagnostics", b"SQLite test bytes"),
        ("AdGuard Home query log", "analyze_adguard_query_log_with_diagnostics", b'{"host":"a.example"}'),
    ],
)
def test_analyze_keeps_parser_dispatch_and_collapses_intake(
    feedback_app, monkeypatch, telemetry_format, analyzer_name, content
):
    import io
    from threatfusion.dns import DNSParseDiagnostics

    app_module, _, result, _ = feedback_app
    calls = []
    diagnostics = DNSParseDiagnostics(
        total_rows=2, accepted_rows=2, skipped_missing_query_name=0,
        invalid_timestamps=0, invalid_response_ips=0,
    )

    def analyze(value, indicators, artifact):
        calls.append(value)
        return result, diagnostics

    monkeypatch.setattr(app_module.st, "file_uploader", lambda *a, **kw: io.BytesIO(content))
    monkeypatch.setattr(app_module, analyzer_name, analyze)
    monkeypatch.setattr(app_module, "capture_analysis_audit_metadata", lambda *a, **kw: "audit")
    app = AppTest.from_string("import streamlit_app\nstreamlit_app.main()")
    app.session_state["workspace_nav"] = "Analyze telemetry"
    app.session_state["telemetry_format"] = telemetry_format
    app.run(timeout=15)
    next(button for button in app.button if button.label == "Analyze").click()
    app.run(timeout=15)
    assert not app.exception
    expected = content if telemetry_format == "Pi-hole FTL database" else content.decode("utf-8-sig")
    assert calls == [expected]
    assert app.session_state["analysis_result"] == result
    assert app.session_state["analysis_audit_metadata"] == "audit"
    intake = next(item for item in app.expander if item.label == "New analysis")
    assert not intake.proto.expanded
