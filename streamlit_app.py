from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.app_config import load_app_config
from threatfusion.audit import capture_analysis_audit_metadata
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
    domain_match_rows,
    feedback_label,
    format_timestamp,
    history_rows,
    ioc_corroboration_rows,
    match_rows,
    persisted_assessment_rows,
    priority_assessment_rows,
    relationship_rows,
    summarize_runtime_result,
)
from threatfusion.evaluation_dashboard import (
    operating_point_rows,
    source_metric_rows,
    summarize_holdout_report,
)
from threatfusion.ml_artifact import load_trusted_ml_artifact
from threatfusion.ml_evaluation_report import read_frozen_holdout_report
from threatfusion.persistence import (
    AnalystFeedback,
    AnalystSuppression,
    apply_history_retention,
    compare_analysis_runs,
    delete_analysis_run,
    get_active_analyst_suppressions,
    get_analysis_assessments,
    get_analyst_feedback,
    get_latest_analyst_feedback_for_domains,
    list_analysis_runs,
    remove_analyst_suppression,
    save_analyst_feedback,
    save_analyst_suppression,
    save_bulk_analyst_feedback,
    save_runtime_analysis,
)
from threatfusion.reporting import build_analysis_report
from threatfusion.runtime_analysis import (
    analyze_adguard_query_log_with_diagnostics,
    analyze_dns_csv_with_diagnostics,
    analyze_pihole_query_db_with_diagnostics,
    analyze_zeek_dns_log_with_diagnostics,
)
from threatfusion.ui_theme import (
    VERDICT_COLORS,
    active_theme,
    apply_plotly_theme,
    inject_theme_css,
    metric_card,
    palette,
    render_app_header,
    render_page_intro,
    render_pipeline_overview,
    render_priority_finding,
    render_privacy_note,
    render_sidebar_brand,
    safe_text,
    section_label,
    sidebar_label,
    source_status_card,
    status_card,
    verdict_badge,
)

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


def _verdict_distribution_figure(summary) -> go.Figure:
    frame = _verdict_chart(summary)
    colors = palette()
    figure = go.Figure(
        data=[
            go.Pie(
                labels=frame["verdict"],
                values=frame["count"],
                hole=0.70,
                sort=False,
                marker={
                    "colors": [
                        VERDICT_COLORS[label]
                        for label in frame["verdict"]
                    ],
                    "line": {
                        "color": colors["panel"],
                        "width": 2,
                    },
                },
                textinfo="label+value",
                textposition="outside",
                hovertemplate=(
                    "<b>%{label}</b><br>"
                    "Domains: %{value}<extra></extra>"
                ),
            )
        ]
    )
    figure.add_annotation(
        text=(
            f"<b>{summary.domain_count}</b>"
            "<br><span>domains</span>"
        ),
        x=0.5,
        y=0.5,
        showarrow=False,
        font={"size": 17, "color": colors["text"]},
        align="center",
    )
    figure.update_layout(showlegend=False)
    return apply_plotly_theme(figure, height=310)


def _relationship_figure(report, result) -> go.Figure:
    graph = build_relationship_graph(report, result)
    colors = palette()
    figure = go.Figure()

    for edge in graph.edges:
        figure.add_trace(
            go.Scatter(
                x=[edge.x0, edge.x1],
                y=[edge.y0, edge.y1],
                mode="lines",
                line={
                    "width": 1.0 + (edge.strength * 3.0),
                    "color": colors["muted"],
                },
                opacity=0.42,
                hoverinfo="text",
                text=[edge.hover_text, edge.hover_text],
                showlegend=False,
            )
        )

    if graph.nodes:
        node_colors = [
            VERDICT_COLORS.get(node.verdict, colors["cyan"])
            for node in graph.nodes
        ]
        figure.add_trace(
            go.Scatter(
                x=[node.x for node in graph.nodes],
                y=[node.y for node in graph.nodes],
                mode="markers+text",
                marker={
                    "size": 21,
                    "color": node_colors,
                    "line": {
                        "width": 2,
                        "color": colors["panel"],
                    },
                },
                text=[node.domain for node in graph.nodes],
                textposition="top center",
                textfont={"size": 11, "color": colors["text"]},
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
        title={
            "text": "Possible related-activity graph",
            "font": {"size": 15},
        },
        xaxis={"visible": False},
        yaxis={"visible": False},
        hovermode="closest",
    )
    return apply_plotly_theme(figure, height=440)


def _show_system_status(
    db_path: Path,
    model_dir: Path,
    evaluation_report_path: Path,
    *,
    cti_stale_after_by_source=None,
) -> None:
    sidebar_label("Workspace status")

    model_path = model_dir / "model.joblib"
    metadata_path = model_dir / "metadata.json"
    model_ready = model_path.exists() and metadata_path.exists()
    status_card(
        "ML artifact",
        "Ready" if model_ready else "Missing",
        "good" if model_ready else "bad",
    )

    statuses = list_cti_cache_status(db_path)
    status_rows = (
        cti_status_rows(
            statuses,
            stale_after_by_source=cti_stale_after_by_source,
        )
        if statuses
        else []
    )
    stale_sources = [
        row["Source"] for row in status_rows if row["Status"] == "Stale"
    ]

    if not statuses:
        cti_value = "Empty"
        cti_tone = "warn"
    elif stale_sources:
        cti_value = f"{len(stale_sources)} stale"
        cti_tone = "warn"
    else:
        cti_value = f"{len(statuses)} ready"
        cti_tone = "good"

    status_card("Threat intelligence", cti_value, cti_tone)

    holdout_ready = evaluation_report_path.is_file()
    status_card(
        "Final evaluation",
        "Available" if holdout_ready else "Pending",
        "good" if holdout_ready else "info",
    )

    if status_rows:
        with st.sidebar.expander(
            "Threat intelligence sources",
            expanded=False,
        ):
            for row in status_rows:
                source_status_card(row)
    else:
        st.sidebar.caption(
            "Known-IOC matching is unavailable until the CTI cache is "
            "populated."
        )

def _show_domain_detail(
    result,
    domain: str,
    *,
    prior_feedback: AnalystFeedback | None = None,
    suppression: AnalystSuppression | None = None,
    db_path: Path | None = None,
    analyst_policy_enabled: bool = False,
) -> None:
    assessment = next(
        item for item in result.assessments if item.domain == domain
    )
    detail = assessment_detail(assessment)
    evidence_rows = domain_match_rows(result, domain)

    with st.container(border=True):
        st.markdown(
            f"""
            <div class="tf-investigation-head">
                <div>
                    <div class="tf-eyebrow">Domain investigation</div>
                    <div class="tf-domain-name">{safe_text(detail["domain"])}</div>
                </div>
                <div>{verdict_badge(str(detail["verdict"]))}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if prior_feedback is not None:
            st.info(
                "Previous analyst review: "
                f"{feedback_label(prior_feedback.label)} · "
                f"{format_timestamp(prior_feedback.updated_at)}"
                + (
                    f" · {prior_feedback.note}"
                    if prior_feedback.note
                    else ""
                )
            )

        if suppression is not None:
            expiry_text = (
                format_timestamp(suppression.expires_at)
                if suppression.expires_at is not None
                else "No expiry"
            )
            st.warning(
                "Locally suppressed from the priority queue · "
                f"{suppression.reason} · {expiry_text}"
            )

        if evidence_rows:
            section_label("Primary CTI evidence")
            primary = evidence_rows[0]
            st.write(
                f"{primary['Evidence scope']} · {primary['Source']}"
                + (
                    f" · {primary['Threat type']}"
                    if primary["Threat type"]
                    else ""
                )
            )
            metadata_columns = st.columns(4)
            metric_card(
                metadata_columns[0],
                "First seen",
                primary["First seen"] or "Unknown",
                accent="cyan",
            )
            metric_card(
                metadata_columns[1],
                "Last seen",
                primary["Last seen"] or "Unknown",
                accent="blue",
            )
            metric_card(
                metadata_columns[2],
                "Confidence",
                (
                    f"{primary['Confidence']:.2f}"
                    if primary["Confidence"] is not None
                    else "Unknown"
                ),
                accent="green",
            )
            metric_card(
                metadata_columns[3],
                "Tags",
                primary["Tags"] or "None",
                accent="yellow",
            )

            if len(evidence_rows) > 1:
                with st.expander(
                    f"Show all IOC evidence ({len(evidence_rows)})",
                    expanded=False,
                ):
                    st.dataframe(
                        pd.DataFrame(evidence_rows),
                        hide_index=True,
                        width="stretch",
                    )
        else:
            st.caption("No cached IOC evidence is associated with this domain.")

        section_label("Detection context")
        context_columns = st.columns(5)
        ml_score = detail["ml_score"]
        metric_card(
            context_columns[0],
            "ML score",
            f"{ml_score:.4f}" if ml_score is not None else "Not scored",
            accent="cyan",
        )
        metric_card(
            context_columns[1],
            "ML tier",
            detail["ml_tier"],
            accent="blue",
        )
        metric_card(
            context_columns[2],
            "DNS events",
            detail["event_count"],
            accent="green",
        )
        metric_card(
            context_columns[3],
            "Unique clients",
            detail["client_count"],
            accent="yellow",
        )
        metric_card(
            context_columns[4],
            "Response IPs",
            detail["response_ip_count"],
            accent="orange",
        )
        st.caption(
            "Query types: "
            + (", ".join(detail["query_types"]) or "None")
        )
        response_codes = ", ".join(
            f"{code}:{count}" for code, count in detail["response_code_counts"]
        )
        st.caption(f"Response codes: {response_codes or 'None'}")
        st.caption(
            "NXDOMAIN ratio: "
            + (
                f"{detail['nxdomain_ratio']:.2f}"
                if detail["nxdomain_ratio"] is not None
                else "N/A"
            )
        )
        st.caption(
            "Label count / subdomain depth: "
            + f"{detail['label_count']} / {detail['subdomain_depth']}"
        )
        st.caption(
            "Numeric ratio / entropy: "
            + (
                f"{detail['numeric_character_ratio']:.2f}"
                if detail["numeric_character_ratio"] is not None
                else "N/A"
            )
            + " / "
            + (
                f"{detail['hostname_entropy']:.2f}"
                if detail["hostname_entropy"] is not None
                else "N/A"
            )
        )
        st.caption(
            "Response-IP churn rate: "
            + (
                f"{detail['response_ip_churn_rate']:.2f}"
                if detail["response_ip_churn_rate"] is not None
                else "N/A"
            )
        )
        periodicity = (
            f"{detail['periodicity_score']:.2f}"
            if detail["periodicity_score"] is not None
            else "N/A"
        )
        interval = (
            f"{detail['periodic_interval_seconds']:.1f}s"
            if detail["periodic_interval_seconds"] is not None
            else "N/A"
        )
        st.caption(
            "Periodicity score / interval: "
            + f"{periodicity} / {interval}"
        )

        evidence = detail["evidence"]
        section_label("Why this verdict?")
        if evidence:
            for item in evidence:
                st.markdown(f"- {item}")
        else:
            st.caption(
                "No strong CTI, ML-tier, or DNS-behavior signal was recorded."
            )

        if detail["verdict"] == "Known Threat":
            st.caption(
                "Known Threat is reserved for an exact known-domain IOC match. "
                "URL-hostname and response-IP matches are contextual CTI "
                "evidence and do not prove the queried domain is malicious."
            )

        if analyst_policy_enabled and db_path is not None:
            st.markdown("**Local analyst policy**")
            if suppression is not None:
                if st.button(
                    "Remove local suppression",
                    key=f"remove_suppression_{detail['domain']}",
                ):
                    remove_analyst_suppression(db_path, detail["domain"])
                    st.rerun()
            else:
                with st.expander(
                    "Suppress from priority triage",
                    expanded=False,
                ):
                    with st.form(f"suppress_{detail['domain']}"):
                        reason = st.text_input(
                            "Suppression reason",
                            max_chars=300,
                        )
                        expiry_days = st.number_input(
                            "Expiry in days (0 = no expiry)",
                            min_value=0,
                            max_value=3650,
                            value=0,
                            step=1,
                        )
                        submitted = st.form_submit_button(
                            "Save local suppression"
                        )
                    if submitted:
                        expires_at = (
                            datetime.now(timezone.utc)
                            + timedelta(days=int(expiry_days))
                            if expiry_days
                            else None
                        )
                        try:
                            save_analyst_suppression(
                                db_path,
                                detail["domain"],
                                reason,
                                expires_at=expires_at,
                            )
                        except (TypeError, ValueError) as error:
                            st.error(f"Suppression could not be saved: {error}")
                        else:
                            st.success(
                                "Local suppression saved. Detector output was "
                                "not changed."
                            )
                            st.rerun()


def _show_analysis_result(
    result,
    artifact,
    db_path: Path,
    *,
    history_enabled: bool,
) -> None:
    summary = summarize_runtime_result(result)

    render_page_intro(
        "Analysis results",
        "Review prioritized findings first, then drill into domain evidence "
        "and supporting telemetry when needed.",
        eyebrow="Current run",
    )
    columns = st.columns(6)
    metric_card(columns[0], "DNS events", summary.event_count, accent="cyan")
    metric_card(
        columns[1],
        "Unique domains",
        summary.domain_count,
        accent="blue",
    )
    metric_card(
        columns[2],
        "Known threat",
        summary.known_threat_count,
        accent="red",
    )
    metric_card(
        columns[3],
        "High risk",
        summary.high_risk_count,
        accent="orange",
    )
    metric_card(
        columns[4],
        "Review",
        summary.review_count,
        accent="yellow",
    )
    metric_card(columns[5], "Low", summary.low_count, accent="green")

    st.caption(
        "Verdicts are assigned per unique domain; DNS events count individual "
        "telemetry rows."
    )

    domains = [assessment.domain for assessment in result.assessments]
    if history_enabled:
        prior_feedback_by_domain = get_latest_analyst_feedback_for_domains(
            db_path,
            domains,
        )
        suppressions_by_domain = get_active_analyst_suppressions(
            db_path,
            domains,
        )
    else:
        prior_feedback_by_domain = {}
        suppressions_by_domain = {}

    priority_rows = priority_assessment_rows(result)
    suppressed_priority_count = sum(
        row["Domain"] in suppressions_by_domain for row in priority_rows
    )
    include_suppressed = False
    if suppressed_priority_count:
        include_suppressed = st.checkbox(
            f"Include {suppressed_priority_count} locally suppressed finding(s)",
            value=False,
            key="include_suppressed_live_findings",
        )
    visible_priority_rows = [
        row
        for row in priority_rows
        if include_suppressed or row["Domain"] not in suppressions_by_domain
    ]

    overview_left, overview_right = st.columns([2, 1])

    with overview_left:
        section_label("Priority findings")
        if visible_priority_rows:
            for row in visible_priority_rows[:8]:
                render_priority_finding(row)
            if len(visible_priority_rows) > 8:
                st.caption(
                    f"{len(visible_priority_rows) - 8} additional priority "
                    "finding(s) are available in Domain findings."
                )
        else:
            if priority_rows and suppressed_priority_count:
                st.info(
                    "All current priority findings are locally suppressed. "
                    "Enable the checkbox above to include them."
                )
            else:
                st.success("No Known Threat, High Risk, or Review findings.")

    with overview_right:
        section_label("Verdict distribution")
        st.plotly_chart(
            _verdict_distribution_figure(summary),
            width="stretch",
            config={"displayModeBar": False},
        )

    all_rows = assessment_rows(result)
    if all_rows:
        selected_domain = st.selectbox(
            "Inspect a domain",
            [row["Domain"] for row in all_rows],
            key="live_domain_detail",
        )
        _show_domain_detail(
            result,
            selected_domain,
            prior_feedback=prior_feedback_by_domain.get(selected_domain),
            suppression=suppressions_by_domain.get(selected_domain),
            db_path=db_path,
            analyst_policy_enabled=history_enabled,
        )

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

        else:
            st.info("No domain assessments were produced.")

        st.caption(
            "ML score is a model decision score, not a literal probability "
            "that a domain is malware. Known IOC matches take precedence "
            "over ML score tiers."
        )

    with matches_tab:
        corroboration = ioc_corroboration_rows(result)
        rows = match_rows(result)

        if corroboration:
            st.markdown("#### Source corroboration")
            st.caption(
                "Multiple cached CTI sources strengthen analyst context. "
                "Corroboration does not override evidence-scope rules."
            )
            st.dataframe(
                pd.DataFrame(corroboration),
                hide_index=True,
                width="stretch",
            )

        if rows:
            st.markdown("#### IOC evidence")
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
                "on weighted local DNS and CTI context. High-fan-out shared "
                "infrastructure is down-weighted or filtered. The groups do "
                "not prove one malware campaign."
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
                "Raw client IP values are not shown. Strength is a local "
                "evidence score, not an attribution probability. Relationship "
                "rows expose aggregate counts and explainable noise "
                "adjustments only."
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
        audit_metadata = st.session_state.get("analysis_audit_metadata")
        if audit_metadata is None:
            st.error(
                "Re-run the analysis before saving so model, threshold, "
                "and CTI audit metadata can be captured."
            )
        else:
            run_id = save_runtime_analysis(
                db_path,
                result,
                model_name=artifact.metadata.model_name,
                audit_metadata=audit_metadata,
            )
            st.success(
                f"Analysis #{run_id} saved with reproducibility metadata. "
                "Raw DNS rows and client IPs were not stored."
            )

def _show_history(db_path: Path) -> None:
    render_page_intro(
        "Analysis history",
        "Review saved aggregate runs, compare changes, and record analyst "
        "decisions without persisting raw DNS rows.",
        eyebrow="Local workspace",
    )
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
    selected_summary = next(
        summary for summary in summaries if summary.id == run_id
    )
    with st.expander("Reproducibility metadata", expanded=False):
        if selected_summary.audit_captured_at is None:
            st.caption(
                "This is a legacy saved run created before audit metadata "
                "was added."
            )
        else:
            st.write(
                "**Audit captured:** "
                + format_timestamp(selected_summary.audit_captured_at)
            )
            st.write(
                "**Artifact:** " + (selected_summary.model_name or "Unknown")
            )
            checksum = selected_summary.artifact_checksum or "Unknown"
            st.code(checksum, language="text")
            st.caption(
                "Artifact SHA-256 checksum · artifact schema "
                f"{selected_summary.artifact_schema_version or 'Unknown'} · "
                "audit schema "
                f"{selected_summary.audit_schema_version or 'Unknown'}"
            )
            if (
                selected_summary.high_threshold is not None
                and selected_summary.medium_threshold is not None
                and selected_summary.low_threshold is not None
            ):
                st.write(
                    "**Frozen thresholds:** "
                    f"high {selected_summary.high_threshold:.6f} · "
                    f"medium {selected_summary.medium_threshold:.6f} · "
                    f"low {selected_summary.low_threshold:.6f}"
                )
            if selected_summary.cti_sources:
                st.write("**CTI snapshot context**")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Source": item.source,
                                "Refreshed at": format_timestamp(
                                    item.refreshed_at
                                ),
                                "Records": item.record_count,
                                "Status": item.freshness.title(),
                            }
                            for item in selected_summary.cti_sources
                        ]
                    ),
                    hide_index=True,
                    width="stretch",
                )
            else:
                st.caption("No CTI source refresh metadata was captured.")

    comparison = compare_analysis_runs(db_path, run_id)
    with st.expander("Compare with previous analysis", expanded=False):
        if comparison.previous_run_id is None:
            st.caption(
                "No earlier saved analysis exists. Every domain in this run "
                "is new relative to saved history."
            )
        else:
            st.caption(
                f"Comparing run #{run_id} with previous run "
                f"#{comparison.previous_run_id}."
            )
        compare_columns = st.columns(3)
        compare_columns[0].metric("New domains", len(comparison.new_domains))
        compare_columns[1].metric(
            "No longer present",
            len(comparison.removed_domains),
        )
        compare_columns[2].metric(
            "Verdict changes",
            len(comparison.verdict_changes),
        )
        if comparison.new_domains:
            st.write("**New since previous analysis**")
            st.dataframe(
                pd.DataFrame({"Domain": comparison.new_domains}),
                hide_index=True,
                width="stretch",
            )
        if comparison.removed_domains:
            st.write("**No longer present**")
            st.dataframe(
                pd.DataFrame({"Domain": comparison.removed_domains}),
                hide_index=True,
                width="stretch",
            )
        if comparison.verdict_changes:
            st.write("**Verdict changes**")
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Domain": item.domain,
                            "Previous verdict": item.previous_verdict,
                            "Current verdict": item.current_verdict,
                        }
                        for item in comparison.verdict_changes
                    ]
                ),
                hide_index=True,
                width="stretch",
            )

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
        filter_columns = st.columns(3)
        verdict_filter = filter_columns[0].selectbox(
            "Verdict",
            ["All", *sorted(frame["Verdict"].unique())],
            key=f"history_verdict_filter_{run_id}",
        )
        review_filter = filter_columns[1].selectbox(
            "Review state",
            [
                "All",
                "Unreviewed",
                "Reviewed",
                "Confirmed Threat",
                "Benign",
                "Uncertain",
            ],
            key=f"history_review_filter_{run_id}",
        )
        source_values = sorted(
            {
                source.strip()
                for value in frame["Known CTI sources"]
                for source in value.split(",")
                if source.strip()
            }
        )
        source_filter = filter_columns[2].selectbox(
            "CTI source",
            ["All", *source_values],
            key=f"history_source_filter_{run_id}",
        )

        filtered_frame = frame.copy()
        if verdict_filter != "All":
            filtered_frame = filtered_frame[
                filtered_frame["Verdict"] == verdict_filter
            ]
        if review_filter == "Unreviewed":
            filtered_frame = filtered_frame[
                filtered_frame["Analyst feedback"] == "Not reviewed"
            ]
        elif review_filter == "Reviewed":
            filtered_frame = filtered_frame[
                filtered_frame["Analyst feedback"] != "Not reviewed"
            ]
        elif review_filter != "All":
            filtered_frame = filtered_frame[
                filtered_frame["Analyst feedback"] == review_filter
            ]
        if source_filter != "All":
            filtered_frame = filtered_frame[
                filtered_frame["Known CTI sources"].map(
                    lambda value: source_filter
                    in {item.strip() for item in value.split(",")}
                )
            ]

        compact_columns = [
            "Domain",
            "Verdict",
            "ML score",
            "ML tier",
            "DNS events",
            "Known CTI sources",
            "Analyst feedback",
        ]
        if filtered_frame.empty:
            st.info("No saved findings match the current triage filters.")
        else:
            st.dataframe(
                filtered_frame[compact_columns],
                hide_index=True,
                width="stretch",
                column_config={
                    "Domain": st.column_config.TextColumn(width="medium"),
                    "Verdict": st.column_config.TextColumn(width="small"),
                    "ML score": st.column_config.TextColumn(width="small"),
                    "ML tier": st.column_config.TextColumn(width="small"),
                    "DNS events": st.column_config.NumberColumn(width="small"),
                    "Known CTI sources": st.column_config.TextColumn(
                        width="medium"
                    ),
                    "Analyst feedback": st.column_config.TextColumn(
                        width="medium"
                    ),
                },
            )

        st.write("**Analyst review**")
        st.caption(
            "Feedback is local analyst context only. It does not change the "
            "original verdict, retrain the model, or alter frozen evaluation."
        )

        feedback_options = {
            "Confirmed Threat": "confirmed_threat",
            "Benign": "benign",
            "Uncertain": "uncertain",
        }
        option_labels = list(feedback_options)

        with st.expander("Bulk review selected findings", expanded=False):
            bulk_candidates = (
                filtered_frame["Domain"].tolist()
                if not filtered_frame.empty
                else [assessment.domain for assessment in assessments]
            )
            bulk_domains = st.multiselect(
                "Findings to review",
                bulk_candidates,
                key=f"bulk_feedback_domains_{run_id}",
            )
            bulk_label = st.selectbox(
                "Bulk analyst label",
                option_labels,
                key=f"bulk_feedback_label_{run_id}",
            )
            bulk_note = st.text_area(
                "Optional bulk analyst note",
                max_chars=500,
                key=f"bulk_feedback_note_{run_id}",
            )
            bulk_confirm = st.checkbox(
                "Apply this label only to the selected findings.",
                key=f"bulk_feedback_confirm_{run_id}",
            )
            if st.button(
                "Apply bulk review",
                key=f"bulk_feedback_submit_{run_id}",
                disabled=not bulk_domains or not bulk_confirm,
            ):
                save_bulk_analyst_feedback(
                    db_path,
                    run_id,
                    bulk_domains,
                    feedback_options[bulk_label],
                    note=bulk_note,
                )
                st.success(
                    f"Saved analyst feedback for {len(bulk_domains)} "
                    "selected findings. Detector verdicts were not changed."
                )
                st.rerun()

        review_domains = (
            filtered_frame["Domain"].tolist()
            if not filtered_frame.empty
            else [assessment.domain for assessment in assessments]
        )
        feedback_domain = st.selectbox(
            "Finding to review",
            review_domains,
            key=f"feedback_domain_{run_id}",
        )
        current = feedback_by_domain.get(feedback_domain)
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

    with st.expander("History retention and deletion", expanded=False):
        st.warning(
            "These controls permanently delete local saved history. "
            "Detector logic and the current in-memory analysis are unchanged."
        )
        delete_confirm = st.checkbox(
            f"I understand run #{run_id} will be permanently deleted.",
            key=f"delete_run_confirm_{run_id}",
        )
        if st.button(
            f"Delete saved run #{run_id}",
            key=f"delete_run_{run_id}",
            disabled=not delete_confirm,
        ):
            deleted = delete_analysis_run(db_path, run_id)
            if deleted:
                st.success(f"Saved run #{run_id} was deleted.")
                st.rerun()
            else:
                st.info("The selected saved run no longer exists.")

        keep_latest = int(
            st.number_input(
                "Retention: keep latest N saved runs",
                min_value=1,
                max_value=1000,
                value=min(max(len(summaries), 1), 25),
                step=1,
                key="history_keep_latest",
            )
        )
        retention_confirm = st.checkbox(
            "I understand older saved runs beyond this limit will be "
            "permanently deleted.",
            key="history_retention_confirm",
        )
        if st.button(
            "Apply retention cleanup",
            key="history_retention_apply",
            disabled=not retention_confirm,
        ):
            deleted_ids = apply_history_retention(
                db_path,
                keep_latest=keep_latest,
            )
            if deleted_ids:
                st.success(
                    "Deleted older saved runs: "
                    + ", ".join(f"#{item}" for item in deleted_ids)
                )
                st.rerun()
            else:
                st.info("No saved runs were old enough to delete.")

def _show_model_evaluation(report_path: Path) -> None:
    render_page_intro(
        "Model evaluation",
        "Inspect frozen operating points and holdout diagnostics separately "
        "from live analysis results.",
        eyebrow="Model assurance",
    )

    if not report_path.is_file():
        with st.container(border=True):
            st.markdown("### Final holdout not evaluated")
            st.write(
                "The frozen development model has not yet been measured on "
                "the separately collected fresh disjoint holdout."
            )
            st.caption(
                "Until that report exists, ThreatFusion intentionally keeps "
                "the model in development status."
            )
            with st.expander("Show final-evaluation command", expanded=False):
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
    metric_card(
        columns[0],
        "Input samples",
        summary.input_count,
        accent="cyan",
    )
    metric_card(
        columns[1],
        "Overlap removed",
        summary.overlap_removed,
        accent="yellow",
    )
    metric_card(
        columns[2],
        "Retained",
        summary.retained_count,
        accent="blue",
    )
    metric_card(
        columns[3],
        "Malicious",
        summary.malicious_count,
        accent="red",
    )
    metric_card(
        columns[4],
        "Benign",
        summary.benign_count,
        accent="green",
    )

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
    apply_plotly_theme(figure, height=390)
    st.plotly_chart(
        figure,
        width="stretch",
        config={"displayModeBar": False},
    )

    source_rows = source_metric_rows(report)
    if source_rows:
        source_frame = pd.DataFrame(source_rows)
        for column in (
            "High recall",
            "High FPR",
            "Medium recall",
            "Medium FPR",
            "Low recall",
            "Low FPR",
        ):
            source_frame[column] = source_frame[column].map(
                lambda value: (
                    "n/a" if pd.isna(value) else f"{value:.2%}"
                )
            )
        st.write("**Source-aware holdout diagnostics**")
        st.dataframe(
            source_frame,
            hide_index=True,
            width="stretch",
        )
        st.caption(
            "Recall is shown for malicious samples and false-positive rate "
            "for benign samples. A source with no samples for one class shows "
            "n/a for that class-specific rate."
        )

    st.info(
        "Dataset precision is not the same as operational positive predictive "
        "value (PPV). Real DNS traffic may contain a much lower malicious "
        "base rate, so even a small false-positive rate can produce many "
        "benign alerts."
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

    inject_theme_css(active_theme())
    render_sidebar_brand()
    render_app_header()

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
        cti_stale_after_by_source=config.cti_stale_after_by_source,
    )

    if config.public_mode:
        st.info(
            "Public mode is enabled. Shared analysis history is disabled so "
            "one visitor cannot browse another visitor's saved findings."
        )
        analysis_tab, evaluation_tab = st.tabs(
            ["Analysis", "Model evaluation"]
        )
        history_tab = None
    else:
        analysis_tab, evaluation_tab, history_tab = st.tabs(
            [
                "Analysis",
                "Model evaluation",
                "History",
            ]
        )

    with analysis_tab:
        render_page_intro(
            "Analyze telemetry",
            "Choose a DNS source, upload a sample, and let ThreatFusion "
            "correlate CTI, ML, and DNS-behavior evidence into explainable "
            "domain verdicts.",
            eyebrow="Start here",
        )
        render_privacy_note()

        format_caption = {
            "Generic DNS CSV": "Generic DNS CSV · UTF-8 · max 10 MB",
            "Zeek dns.log": "Zeek dns.log text export · max 10 MB",
            "Pi-hole FTL database": "Pi-hole FTL SQLite database · max 10 MB",
            "AdGuard Home query log": "AdGuard Home JSON query log · max 10 MB",
        }
        required_caption = {
            "Generic DNS CSV": "query_name; all other fields are optional",
            "Zeek dns.log": "Zeek #fields header with query",
            "Pi-hole FTL database": "queries view with standard Pi-hole fields",
            "AdGuard Home query log": (
                "query-log JSON with host and timestamp fields"
            ),
        }

        intake_column, pipeline_column = st.columns(
            [2.15, 1],
            gap="large",
        )
        with intake_column:
            telemetry_format = st.selectbox(
                "Telemetry source",
                [
                    "Generic DNS CSV",
                    "Zeek dns.log",
                    "Pi-hole FTL database",
                    "AdGuard Home query log",
                ],
                key="telemetry_format",
            )
            with st.expander("Input requirements", expanded=False):
                st.markdown(
                    f"**Format**  \n{format_caption[telemetry_format]}"
                )
                st.markdown(
                    f"**Required**  \n{required_caption[telemetry_format]}"
                )
                st.caption(
                    "The upload limit is 10 MB. Raw rows are analyzed in "
                    "memory and are not added to saved analysis history."
                )

        with pipeline_column:
            render_pipeline_overview()

        try:
            artifact = _load_artifact(str(model_dir))
        except (OSError, TypeError, ValueError) as error:
            st.error(
                "The trusted local ML artifact could not be loaded. "
                "Run scripts/train_ml_artifact.py first."
            )
            st.caption(type(error).__name__)
            return

        if (
            getattr(artifact.metadata, "evaluation_status", None)
            == "demo_only_synthetic"
        ):
            st.warning(
                "Demo ML artifact active. It uses synthetic training data "
                "only to exercise the interface and must not be interpreted "
                "as measured model performance."
            )

        indicators = load_ioc_records(db_path)
        if not indicators:
            st.warning(
                "CTI cache is empty. Analysis can still use ML and DNS "
                "behavior, but known-threat matching will be unavailable. "
                "Run scripts/refresh_cti_cache.py to populate the cache."
            )

        upload_label = {
            "Generic DNS CSV": "Upload DNS CSV",
            "Zeek dns.log": "Upload Zeek dns.log",
            "Pi-hole FTL database": "Upload Pi-hole FTL database",
            "AdGuard Home query log": "Upload AdGuard Home query log",
        }[telemetry_format]
        upload_types = {
            "Generic DNS CSV": ["csv"],
            "Zeek dns.log": ["log", "txt"],
            "Pi-hole FTL database": ["db", "sqlite", "sqlite3"],
            "AdGuard Home query log": ["json", "log", "txt"],
        }[telemetry_format]
        upload_help = {
            "Generic DNS CSV": (
                "Expected columns: timestamp, client_ip, query_name, "
                "query_type, response_ip. Only query_name is required."
            ),
            "Zeek dns.log": (
                "Expected Zeek dns.log text with a #fields header. "
                "query, ts, id.orig_h, qtype_name, and answers are "
                "used when available."
            ),
            "Pi-hole FTL database": (
                "Expected a Pi-hole FTL SQLite query database containing "
                "the standard queries view. The database is deserialized "
                "into memory; the upstream forward field is not treated "
                "as a DNS response IP."
            ),
            "AdGuard Home query log": (
                "Expected AdGuard Home query-log JSON. Both the on-disk "
                "querylog.json record shape and exported query-log API "
                "objects are accepted."
            ),
        }[telemetry_format]
        section_label("Upload telemetry")
        with st.container(border=True):
            uploaded = st.file_uploader(
                upload_label,
                type=upload_types,
                help=upload_help,
                key=f"telemetry_upload_{telemetry_format}",
            )

        if uploaded is None:
            if st.session_state.pop("upload_fingerprint", None) is not None:
                st.session_state.pop("analysis_result", None)
                st.session_state.pop("dns_parse_diagnostics", None)
                st.session_state.pop("analysis_audit_metadata", None)
        else:
            content_bytes = uploaded.getvalue()
            fingerprint = (
                f"{telemetry_format}:"
                + content_fingerprint(content_bytes)
            )
            if st.session_state.get("upload_fingerprint") != fingerprint:
                st.session_state["upload_fingerprint"] = fingerprint
                st.session_state.pop("analysis_result", None)
                st.session_state.pop("dns_parse_diagnostics", None)
                st.session_state.pop("analysis_audit_metadata", None)

            if len(content_bytes) > MAX_UPLOAD_BYTES:
                st.error("Uploaded telemetry exceeds the 10 MB application limit.")
            elif telemetry_format == "Pi-hole FTL database":
                if st.button("Analyze", type="primary"):
                    try:
                        result, diagnostics = (
                            analyze_pihole_query_db_with_diagnostics(
                                content_bytes,
                                indicators,
                                artifact,
                            )
                        )
                    except ValueError as error:
                        st.error(
                            "DNS telemetry could not be analyzed: "
                            f"{error}"
                        )
                    else:
                        st.session_state["analysis_result"] = result
                        st.session_state["dns_parse_diagnostics"] = diagnostics
                        try:
                            st.session_state["analysis_audit_metadata"] = (
                                capture_analysis_audit_metadata(
                                    model_dir,
                                    artifact,
                                    list_cti_cache_status(db_path),

                                    stale_after_by_source=(

                                        config.cti_stale_after_by_source

                                    ),
                                )
                            )
                        except OSError:
                            st.session_state.pop("analysis_audit_metadata", None)
                            st.warning(
                                "Analysis completed, but reproducibility "
                                "metadata could not be captured. Re-run the "
                                "analysis before saving history."
                            )
            else:
                try:
                    content = content_bytes.decode("utf-8-sig")
                except UnicodeDecodeError:
                    st.error("Telemetry input must use UTF-8 encoding.")
                else:
                    if st.button("Analyze", type="primary"):
                        try:
                            analyzers = {
                                "Generic DNS CSV": analyze_dns_csv_with_diagnostics,
                                "Zeek dns.log": analyze_zeek_dns_log_with_diagnostics,
                                "AdGuard Home query log": (
                                    analyze_adguard_query_log_with_diagnostics
                                ),
                            }
                            analyzer = analyzers[telemetry_format]
                            result, diagnostics = analyzer(
                                content,
                                indicators,
                                artifact,
                            )
                        except ValueError as error:
                            st.error(
                                "DNS telemetry could not be analyzed: "
                                f"{error}"
                            )
                        else:
                            st.session_state["analysis_result"] = result
                            st.session_state["dns_parse_diagnostics"] = diagnostics
                            try:
                                st.session_state["analysis_audit_metadata"] = (
                                    capture_analysis_audit_metadata(
                                        model_dir,
                                        artifact,
                                        list_cti_cache_status(db_path),

                                        stale_after_by_source=(

                                            config.cti_stale_after_by_source

                                        ),
                                    )
                                )
                            except OSError:
                                st.session_state.pop(
                                    "analysis_audit_metadata",
                                    None,
                                )
                                st.warning(
                                    "Analysis completed, but reproducibility "
                                    "metadata could not be captured. Re-run "
                                    "the analysis before saving history."
                                )

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
