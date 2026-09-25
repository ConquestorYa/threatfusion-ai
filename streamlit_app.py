from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.app_config import load_app_config
from threatfusion.campaign import find_related_activity
from threatfusion.cti_cache import (
    list_cti_cache_status,
    load_ioc_records,
)
from threatfusion.dashboard import (
    assessment_detail,
    assessment_rows,
    build_relationship_graph,
    cluster_rows,
    content_fingerprint,
    cti_status_rows,
    feedback_label,
    history_rows,
    match_rows,
    persisted_assessment_rows,
    relationship_rows,
    summarize_runtime_result,
)
from threatfusion.evaluation_dashboard import (
    operating_point_rows,
    source_recall_rows,
    summarize_holdout_report,
)
from threatfusion.ml_artifact import load_trusted_ml_artifact
from threatfusion.ml_evaluation_report import read_frozen_holdout_report
from threatfusion.persistence import (
    get_analysis_assessments,
    get_analyst_feedback,
    list_analysis_runs,
    save_analyst_feedback,
    save_runtime_analysis,
)
from threatfusion.reporting import build_analysis_report
from threatfusion.runtime_analysis import analyze_dns_csv_with_diagnostics

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


@st.cache_resource
def _load_artifact(path_text: str):
    return load_trusted_ml_artifact(Path(path_text))

def _verdict_chart(summary) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "verdict": [
                "Known Threat",
                "High Risk",
                "Review",
                "Low",
            ],
            "count": [
                summary.known_threat_count,
                summary.high_risk_count,
                summary.review_count,
                summary.low_count,
            ],
        }
    )


def _relationship_figure(report, result) -> go.Figure:
    graph = build_relationship_graph(report, result)
    figure = go.Figure()

    for edge in graph.edges:
        figure.add_trace(
            go.Scatter(
                x=[edge.x0, edge.x1],
                y=[edge.y0, edge.y1],
                mode="lines",
                line={"width": 2},
                hoverinfo="text",
                text=[edge.hover_text, edge.hover_text],
                showlegend=False,
            )
        )

    if graph.nodes:
        figure.add_trace(
            go.Scatter(
                x=[node.x for node in graph.nodes],
                y=[node.y for node in graph.nodes],
                mode="markers+text",
                marker={"size": 18},
                text=[node.domain for node in graph.nodes],
                textposition="top center",
                hoverinfo="text",
                hovertext=[
                    (
                        f"{node.domain}<br>"
                        f"Group: {node.cluster_id}<br>"
                        f"Verdict: {node.verdict}<br>"
                        f"ML tier: {node.ml_tier}<br>"
                        f"Known CTI sources: "
                        f"{', '.join(node.known_sources) or 'None'}"
                    )
                    for node in graph.nodes
                ],
                showlegend=False,
            )
        )

    figure.update_layout(
        title="Possible related-activity graph",
        xaxis={"visible": False},
        yaxis={"visible": False},
        hovermode="closest",
        margin={"l": 20, "r": 20, "t": 50, "b": 20},
    )
    return figure


def _show_system_status(
    db_path: Path,
    model_dir: Path,
    evaluation_report_path: Path,
) -> None:
    st.sidebar.header("System status")

    model_path = model_dir / "model.joblib"
    metadata_path = model_dir / "metadata.json"
    if model_path.exists() and metadata_path.exists():
        st.sidebar.success("ML model artifact available")
    else:
        st.sidebar.error("ML model artifact missing")

    statuses = list_cti_cache_status(db_path)
    if statuses:
        status_rows = cti_status_rows(statuses)
        if any(row["Status"] == "Stale" for row in status_rows):
            st.sidebar.warning(
                "CTI cache is available, but at least one source is stale."
            )
        else:
            st.sidebar.success("CTI cache available")
        st.sidebar.dataframe(
            pd.DataFrame(status_rows),
            hide_index=True,
            width="stretch",
        )
    else:
        st.sidebar.warning("CTI cache is empty")

    if evaluation_report_path.is_file():
        st.sidebar.success("Final holdout report available")
    else:
        st.sidebar.info("Final holdout report not collected yet")

def _show_domain_detail(result, domain: str) -> None:
    assessment = next(
        item for item in result.assessments if item.domain == domain
    )
    detail = assessment_detail(assessment)

    st.markdown(f"#### Domain detail: {detail['domain']}")

    columns = st.columns(4)
    columns[0].metric("Verdict", detail["verdict"])
    ml_score = detail["ml_score"]
    columns[1].metric(
        "ML score",
        f"{ml_score:.4f}" if ml_score is not None else "N/A",
    )
    columns[2].metric("ML tier", detail["ml_tier"])
    columns[3].metric("DNS events", detail["event_count"])

    behavior_columns = st.columns(3)
    behavior_columns[0].metric("Unique clients", detail["client_count"])
    behavior_columns[1].metric(
        "Unique response IPs",
        detail["response_ip_count"],
    )
    behavior_columns[2].metric(
        "Query types",
        ", ".join(detail["query_types"]) or "None",
    )

    sources = detail["known_sources"]
    if sources:
        st.write("**Known CTI sources:** " + ", ".join(sources))
    else:
        st.write("**Known CTI sources:** No cached IOC match")

    if detail["verdict"] == "Known Threat" and sources:
        st.caption(
            "Known CTI evidence determines the Known Threat verdict. "
            "ML and DNS-behavior signals are shown as additional context."
        )

    evidence = detail["evidence"]
    st.write("**Evidence observed**")
    if evidence:
        for item in evidence:
            st.markdown(f"- {item}")
    else:
        st.caption("No strong CTI, ML-tier, or DNS-behavior signal was recorded.")

def _show_analysis_result(
    result,
    artifact,
    db_path: Path,
    *,
    history_enabled: bool,
) -> None:
    summary = summarize_runtime_result(result)

    st.subheader("Analysis summary")
    columns = st.columns(6)
    columns[0].metric("DNS events", summary.event_count)
    columns[1].metric("Unique domains", summary.domain_count)
    columns[2].metric("Known threat", summary.known_threat_count)
    columns[3].metric("High risk", summary.high_risk_count)
    columns[4].metric("Review", summary.review_count)
    columns[5].metric("Low", summary.low_count)

    st.caption(
        "Verdicts are assigned per unique domain; DNS events count individual "
        "telemetry rows."
    )

    chart_data = _verdict_chart(summary)
    figure = px.bar(
        chart_data,
        x="verdict",
        y="count",
        title="Domain verdict distribution",
        text_auto=True,
        labels={"verdict": "Verdict", "count": "Domains"},
    )
    st.plotly_chart(figure, width="stretch")

    findings_tab, matches_tab, campaign_tab = st.tabs(
        ["Domain findings", "Known IOC evidence", "Related activity"]
    )

    with findings_tab:
        rows = assessment_rows(result)
        if rows:
            frame = pd.DataFrame(rows)
            frame["ML score"] = frame["ML score"].map(
                lambda value: (
                    f"{value:.4f}" if value is not None else ""
                )
            )
            st.dataframe(
                frame,
                hide_index=True,
                width="stretch",
                column_config={
                    "Domain": st.column_config.TextColumn(width="medium"),
                    "Known CTI sources": st.column_config.TextColumn(
                        width="medium"
                    ),
                    "Evidence": st.column_config.TextColumn(width="large"),
                },
            )

            selected_domain = st.selectbox(
                "Inspect a domain",
                [row["Domain"] for row in rows],
                key="live_domain_detail",
            )
            _show_domain_detail(result, selected_domain)
        else:
            st.info("No domain assessments were produced.")

        st.caption(
            "ML score is a model decision score, not a literal probability "
            "that a domain is malware. Known IOC matches take precedence "
            "over ML score tiers."
        )

    with matches_tab:
        rows = match_rows(result)
        if rows:
            st.dataframe(
                pd.DataFrame(rows),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info("No cached IOC matches were found.")

    with campaign_tab:
        try:
            related_report = find_related_activity(result)
        except ValueError as error:
            st.warning(
                "Related-activity visualization was skipped because the "
                f"candidate set was too large: {error}"
            )
            related_report = None

        if related_report is not None and related_report.clusters:
            st.info(
                "These groups show possible related suspicious activity based "
                "on shared local DNS evidence. They do not prove one malware "
                "campaign."
            )
            st.plotly_chart(
                _relationship_figure(related_report, result),
                width="stretch",
            )
            st.write("**Possible related-activity groups**")
            st.dataframe(
                pd.DataFrame(cluster_rows(related_report)),
                hide_index=True,
                width="stretch",
            )
            st.write("**Relationship evidence**")
            st.dataframe(
                pd.DataFrame(relationship_rows(related_report)),
                hide_index=True,
                width="stretch",
            )
            st.caption(
                "Raw client IP values are not shown. Relationship rows expose "
                "aggregate shared counts only."
            )
        elif related_report is not None:
            st.info(
                "No possible related-activity groups were found among Known "
                "Threat, High Risk, or Review domains."
            )

    report = build_analysis_report(
        result,
        model_name=artifact.metadata.model_name,
    )
    export_columns = st.columns(2)
    export_columns[0].download_button(
        "Download JSON report",
        data=report.json_text,
        file_name="threatfusion_analysis.json",
        mime="application/json",
        width="stretch",
    )
    export_columns[1].download_button(
        "Download CSV findings",
        data=report.csv_text,
        file_name="threatfusion_findings.csv",
        mime="text/csv",
        width="stretch",
    )
    st.caption(
        "Exports contain aggregate/per-domain findings only. Raw DNS rows, "
        "client IP values, and response IP values are not included."
    )

    if history_enabled and st.button("Save aggregate analysis history"):
        run_id = save_runtime_analysis(
            db_path,
            result,
            model_name=artifact.metadata.model_name,
        )
        st.success(
            f"Analysis #{run_id} saved. Raw DNS rows and client IPs were not stored."
        )

def _show_history(db_path: Path) -> None:
    st.subheader("Saved analysis history")
    summaries = list_analysis_runs(db_path)
    if not summaries:
        st.info("No saved analyses yet.")
        return

    st.dataframe(
        pd.DataFrame(history_rows(summaries)),
        hide_index=True,
        width="stretch",
        column_config={
            "Created at": st.column_config.TextColumn(width="medium"),
            "Model": st.column_config.TextColumn(width="large"),
        },
    )

    selected_id = st.selectbox(
        "Inspect saved run",
        [summary.id for summary in summaries],
    )
    run_id = int(selected_id)
    assessments = get_analysis_assessments(db_path, run_id)
    feedback = get_analyst_feedback(db_path, run_id)
    feedback_by_domain = {item.domain: item for item in feedback}

    rows = persisted_assessment_rows(assessments)
    if rows:
        frame = pd.DataFrame(rows)
        frame["ML score"] = frame["ML score"].map(
            lambda value: (
                f"{value:.4f}" if value is not None else ""
            )
        )
        frame["Analyst feedback"] = frame["Domain"].map(
            lambda domain: feedback_label(
                feedback_by_domain.get(domain).label
                if domain in feedback_by_domain
                else None
            )
        )
        frame["Analyst note"] = frame["Domain"].map(
            lambda domain: (
                feedback_by_domain[domain].note or ""
                if domain in feedback_by_domain
                else ""
            )
        )
        st.dataframe(
            frame,
            hide_index=True,
            width="stretch",
            column_config={
                "Domain": st.column_config.TextColumn(width="medium"),
                "Known CTI sources": st.column_config.TextColumn(
                    width="medium"
                ),
                "Evidence": st.column_config.TextColumn(width="large"),
                "Analyst feedback": st.column_config.TextColumn(
                    width="medium"
                ),
                "Analyst note": st.column_config.TextColumn(width="large"),
            },
        )

        st.write("**Analyst feedback**")
        st.caption(
            "Feedback is local analyst context only. It does not change the "
            "original verdict, retrain the model, or alter frozen evaluation."
        )

        feedback_domain = st.selectbox(
            "Finding to review",
            [assessment.domain for assessment in assessments],
            key=f"feedback_domain_{run_id}",
        )
        current = feedback_by_domain.get(feedback_domain)
        feedback_options = {
            "Confirmed Threat": "confirmed_threat",
            "Benign": "benign",
            "Uncertain": "uncertain",
        }
        option_labels = list(feedback_options)
        current_label = (
            feedback_label(current.label)
            if current is not None
            else "Uncertain"
        )
        current_index = (
            option_labels.index(current_label)
            if current_label in option_labels
            else option_labels.index("Uncertain")
        )

        with st.form(f"analyst_feedback_{run_id}_{feedback_domain}"):
            selected_feedback = st.selectbox(
                "Analyst label",
                option_labels,
                index=current_index,
            )
            note = st.text_area(
                "Optional analyst note",
                value=(
                    current.note
                    if current is not None and current.note
                    else ""
                ),
                max_chars=500,
            )
            submitted = st.form_submit_button("Save analyst feedback")

        if submitted:
            save_analyst_feedback(
                db_path,
                run_id,
                feedback_domain,
                feedback_options[selected_feedback],
                note=note,
            )
            st.success(
                "Analyst feedback saved. The original ThreatFusion verdict "
                "was not changed."
            )
            st.rerun()

def _show_model_evaluation(report_path: Path) -> None:
    st.subheader("Model evaluation")

    if not report_path.is_file():
        st.info(
            "No final holdout report is available yet. The model remains in "
            "development status until a separately collected disjoint holdout "
            "is evaluated with the frozen artifact and thresholds."
        )
        st.code(
            "python scripts\\evaluate_ml_final_holdout.py "
            "--artifact-dir data\\models\\development-001 "
            "--development-snapshot-dir data\\snapshots\\baseline-001 "
            "--holdout-snapshot-dir data\\snapshots\\holdout-001 "
            "--json-output data\\evaluation\\final_holdout.json",
            language="powershell",
        )
        return

    try:
        report = read_frozen_holdout_report(report_path)
    except (OSError, TypeError, ValueError) as error:
        st.error("The final holdout report could not be loaded.")
        st.caption(type(error).__name__)
        return

    summary = summarize_holdout_report(report)

    st.success(
        "Frozen-model holdout report loaded. No retraining or threshold "
        "tuning was performed on this holdout."
    )
    st.write(f"**Model:** {summary.model_name}")
    st.write(
        "**Snapshot dates:** "
        f"development {summary.development_snapshot_date} → "
        f"holdout {summary.holdout_snapshot_date}"
    )

    columns = st.columns(5)
    columns[0].metric("Input samples", summary.input_count)
    columns[1].metric("Overlap removed", summary.overlap_removed)
    columns[2].metric("Retained", summary.retained_count)
    columns[3].metric("Malicious", summary.malicious_count)
    columns[4].metric("Benign", summary.benign_count)

    rows = operating_point_rows(report)
    frame = pd.DataFrame(rows)
    display_frame = frame.copy()
    for column in (
        "Precision",
        "Recall",
        "F1",
        "False-positive rate",
    ):
        display_frame[column] = display_frame[column].map(
            lambda value: f"{value:.2%}"
        )
    display_frame["Threshold"] = display_frame["Threshold"].map(
        lambda value: f"{value:.6f}"
    )

    st.write("**Frozen operating points**")
    st.dataframe(
        display_frame,
        hide_index=True,
        width="stretch",
    )

    chart_frame = frame[
        ["Operating point", "Recall", "False-positive rate"]
    ].melt(
        id_vars="Operating point",
        var_name="Metric",
        value_name="Rate",
    )
    figure = px.bar(
        chart_frame,
        x="Operating point",
        y="Rate",
        color="Metric",
        barmode="group",
        title="Final holdout recall vs false-positive rate",
        labels={"Rate": "Rate"},
    )
    figure.update_yaxes(tickformat=".0%")
    st.plotly_chart(figure, width="stretch")

    source_rows = source_recall_rows(report)
    if source_rows:
        source_frame = pd.DataFrame(source_rows)
        for column in ("High recall", "Medium recall", "Low recall"):
            source_frame[column] = source_frame[column].map(
                lambda value: f"{value:.2%}"
            )
        st.write("**Malicious recall by retained source**")
        st.dataframe(
            source_frame,
            hide_index=True,
            width="stretch",
        )

    st.caption(
        "Protocol: fresh-collection disjoint holdout. Every domain seen in "
        "the development snapshot is removed before evaluation. This is not "
        "a strict IOC first-seen temporal split because DomainSample does not "
        "store malicious IOC first_seen timestamps."
    )


def main() -> None:
    st.set_page_config(
        page_title="ThreatFusion AI",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("ThreatFusion AI")
    st.write(
        "Multi-source cyber threat intelligence, malicious-domain ML, "
        "and DNS behavior analysis in one explainable workflow."
    )

    try:
        config = load_app_config()
    except ValueError as error:
        st.error(f"Application configuration is invalid: {error}")
        return

    db_path = config.db_path
    model_dir = config.model_dir
    _show_system_status(
        db_path,
        model_dir,
        config.evaluation_report_path,
    )

    if config.public_mode:
        st.info(
            "Public mode is enabled. Shared analysis history is disabled so "
            "one visitor cannot browse another visitor's saved findings."
        )
        analysis_tab, evaluation_tab = st.tabs(
            ["Analyze DNS telemetry", "Model evaluation"]
        )
        history_tab = None
    else:
        analysis_tab, evaluation_tab, history_tab = st.tabs(
            [
                "Analyze DNS telemetry",
                "Model evaluation",
                "Analysis history",
            ]
        )

    with analysis_tab:
        st.info(
            "Uploaded DNS data is processed in memory. Raw DNS rows and "
            "client IP values are not persisted by this application."
        )

        try:
            artifact = _load_artifact(str(model_dir))
        except (OSError, TypeError, ValueError) as error:
            st.error(
                "The trusted local ML artifact could not be loaded. "
                "Run scripts/train_ml_artifact.py first."
            )
            st.caption(type(error).__name__)
            return

        indicators = load_ioc_records(db_path)
        if not indicators:
            st.warning(
                "CTI cache is empty. Analysis can still use ML and DNS "
                "behavior, but known-threat matching will be unavailable. "
                "Run scripts/refresh_cti_cache.py to populate the cache."
            )

        uploaded = st.file_uploader(
            "Upload DNS CSV",
            type=["csv"],
            help=(
                "Expected columns: timestamp, client_ip, query_name, "
                "query_type, response_ip. Only query_name is required."
            ),
        )

        if uploaded is None:
            if st.session_state.pop("upload_fingerprint", None) is not None:
                st.session_state.pop("analysis_result", None)
                st.session_state.pop("dns_parse_diagnostics", None)
        else:
            content_bytes = uploaded.getvalue()
            fingerprint = content_fingerprint(content_bytes)
            if st.session_state.get("upload_fingerprint") != fingerprint:
                st.session_state["upload_fingerprint"] = fingerprint
                st.session_state.pop("analysis_result", None)
                st.session_state.pop("dns_parse_diagnostics", None)

            if len(content_bytes) > MAX_UPLOAD_BYTES:
                st.error("Uploaded CSV exceeds the 10 MB application limit.")
            else:
                try:
                    content = content_bytes.decode("utf-8-sig")
                except UnicodeDecodeError:
                    st.error("CSV must use UTF-8 encoding.")
                else:
                    if st.button("Analyze", type="primary"):
                        try:
                            result, diagnostics = (
                                analyze_dns_csv_with_diagnostics(
                                    content,
                                    indicators,
                                    artifact,
                                )
                            )
                        except ValueError as error:
                            st.error(f"DNS CSV could not be analyzed: {error}")
                        else:
                            st.session_state["analysis_result"] = result
                            st.session_state["dns_parse_diagnostics"] = diagnostics

        result = st.session_state.get("analysis_result")
        diagnostics = st.session_state.get("dns_parse_diagnostics")
        if result is not None and diagnostics is not None:
            st.caption(
                "Input quality: "
                f"{diagnostics.accepted_rows}/{diagnostics.total_rows} rows "
                "accepted; "
                f"{diagnostics.skipped_missing_query_name} missing query names; "
                f"{diagnostics.invalid_timestamps} invalid timestamps; "
                f"{diagnostics.invalid_response_ips} invalid response IPs."
            )
        if result is not None:
            _show_analysis_result(
                result,
                artifact,
                db_path,
                history_enabled=config.history_enabled,
            )

    with evaluation_tab:
        _show_model_evaluation(config.evaluation_report_path)

    if history_tab is not None:
        with history_tab:
            _show_history(db_path)


if __name__ == "__main__":
    main()
