from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

_PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.app_config import load_app_config
from threatfusion.audit import capture_analysis_audit_metadata
from threatfusion.campaign import find_related_activity
from threatfusion.cti_cache import list_cti_cache_status, load_ioc_records
from threatfusion.dashboard import (
    assessment_rows,
    cluster_rows,
    content_fingerprint,
    cti_status_rows,
    ioc_corroboration_rows,
    match_rows,
    priority_assessment_rows,
    relationship_rows,
    summarize_runtime_result,
)
from threatfusion.ml_artifact import load_trusted_ml_artifact
from threatfusion.persistence import (
    get_active_analyst_suppressions,
    get_latest_analyst_feedback_for_domains,
    save_runtime_analysis,
)
from threatfusion.quick_lookup import analyze_quick_lookup
from threatfusion.reporting import build_analysis_report
from threatfusion.runtime_analysis import (
    analyze_adguard_query_log_with_diagnostics,
    analyze_dns_csv_with_diagnostics,
    analyze_pihole_query_db_with_diagnostics,
    analyze_zeek_dns_log_with_diagnostics,
)
from threatfusion.ui_charts import _relationship_figure, _verdict_distribution_figure
from threatfusion.ui_components import (
    empty_state,
    intake_steps,
    render_findings_table,
    render_source_status,
)
from threatfusion.ui_evaluation import _show_model_evaluation
from threatfusion.ui_history import _show_history
from threatfusion.ui_investigation import _show_domain_detail
from threatfusion.ui_quick_lookup import render_quick_lookup_result
from threatfusion.ui_theme import (
    inject_theme_css,
    metric_card,
    render_app_header,
    render_priority_finding,
    render_sidebar_brand,
    section_label,
    status_card,
)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


@st.cache_resource
def _load_artifact(path_text: str):
    return load_trusted_ml_artifact(Path(path_text))


def _show_system_status(
    db_path: Path,
    model_dir: Path,
    evaluation_report_path: Path,
    *,
    cti_stale_after_by_source=None,
) -> None:
    st.sidebar.markdown("### Workspace health")

    model_path = model_dir / "model.joblib"
    metadata_path = model_dir / "metadata.json"
    model_ready = model_path.exists() and metadata_path.exists()
    status_card(
        "ML artifact",
        "Present" if model_ready else "Missing",
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
    stale_sources = [row["Source"] for row in status_rows if row["Status"] != "Fresh"]

    if not statuses:
        cti_value = "Empty"
        cti_tone = "warn"
    elif stale_sources:
        cti_value = f"{len(stale_sources)} need review"
        cti_tone = "warn"
    else:
        cti_value = f"{len(statuses)} cached"
        cti_tone = "good"

    status_card("CTI cache", cti_value, cti_tone)

    holdout_ready = evaluation_report_path.is_file()
    status_card(
        "Final evaluation",
        "Available" if holdout_ready else "Pending holdout",
        "good" if holdout_ready else "info",
    )

    st.sidebar.markdown("### CTI sources")
    cached = {str(row["Source"]): row for row in status_rows}
    source_names = list(dict.fromkeys(["ThreatFox", "URLhaus", "SGB", *cached]))
    for source in source_names:
        row = cached.get(
            source,
            {
                "Source": source,
                "Status": "Not cached",
                "Records": None,
                "Inactive history": 0,
                "Refreshed at": "Unavailable",
                "Age": "Unknown",
                "Stale after": f"{(cti_stale_after_by_source or {}).get(source, timedelta(hours=24)).total_seconds() / 3600:g} h",
            },
        )
        render_source_status(row)
    with st.sidebar.expander("Workspace details", expanded=False):
        st.caption(
            "Artifact status checks for local model and metadata files. The model is validated when analysis opens."
        )
        st.caption("Theme follows Settings → Theme in the app menu.")
        st.caption("CTI status describes the local cache, not a live feed connection.")


def _show_analysis_result(
    result,
    artifact,
    db_path: Path,
    *,
    history_enabled: bool,
) -> None:
    summary = summarize_runtime_result(result)

    st.subheader("Priority findings")
    st.caption(
        "Start with the highest-priority domains, then open Domain investigation for the evidence."
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
        if visible_priority_rows:
            for row in visible_priority_rows[:5]:
                render_priority_finding(row)
            if len(visible_priority_rows) > 5:
                st.caption(
                    f"{len(visible_priority_rows) - 5} additional priority "
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

    section_label("Analysis overview")
    columns = st.columns(6)
    metric_card(columns[0], "DNS events", summary.event_count, accent="neutral")
    metric_card(
        columns[1],
        "Unique domains",
        summary.domain_count,
        accent="neutral",
    )
    metric_card(
        columns[2],
        "Known Threat",
        summary.known_threat_count,
        accent="red",
    )
    metric_card(
        columns[3],
        "High Risk",
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

    findings_tab, investigation_tab, matches_tab, campaign_tab, export_tab = st.tabs(
        [
            "Domain findings",
            "Domain investigation",
            "IOC evidence",
            "Related activity",
            "Export & save",
        ]
    )
    with findings_tab:
        render_findings_table(assessment_rows(result), key="live_findings")

    with investigation_tab:
        all_rows = assessment_rows(result)
        if all_rows:
            domain_options = [row["Domain"] for row in all_rows]
            if st.session_state.get("live_domain_detail") not in domain_options:
                st.session_state.pop("live_domain_detail", None)
            selected_domain = st.selectbox(
                "Inspect a domain",
                domain_options,
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
        else:
            empty_state("No domains to investigate", "Upload telemetry to begin.")

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
            with st.expander(
                "Relationship evidence and noise adjustments", expanded=False
            ):
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

    with export_tab:
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


def _clear_analysis_state() -> None:
    """Discard stale UI results when the user changes or removes input."""
    for key in (
        "upload_fingerprint",
        "analysis_result",
        "dns_parse_diagnostics",
        "analysis_audit_metadata",
    ):
        st.session_state.pop(key, None)


def _on_upload_change(upload_key: str) -> None:
    if st.session_state.get(upload_key) is None:
        _clear_analysis_state()


def _clear_quick_lookup_state() -> None:
    st.session_state.pop("quick_lookup_result", None)


def main() -> None:
    st.set_page_config(
        page_title="ThreatFusion AI",
        page_icon=":material/shield:",
        layout="wide",
    )

    inject_theme_css()
    render_sidebar_brand()
    if "telemetry_format" in st.session_state:
        st.session_state["telemetry_format"] = st.session_state["telemetry_format"]

    try:
        config = load_app_config()
    except ValueError as error:
        st.error(f"Application configuration is invalid: {error}")
        return

    db_path = config.db_path
    model_dir = config.model_dir
    navigation = st.sidebar.container()
    _show_system_status(
        db_path,
        model_dir,
        config.evaluation_report_path,
        cti_stale_after_by_source=config.cti_stale_after_by_source,
    )

    pages = [
        "Analyze telemetry",
        "Quick lookup",
        "Analysis history",
        "Model evaluation",
    ]
    if config.public_mode:
        pages.remove("Analysis history")
    if st.session_state.get("workspace_nav") not in pages:
        st.session_state.pop("workspace_nav", None)
    # Navigation precedes health in the sidebar, using its reserved container.
    with navigation:
        page = st.radio(
            "Workspace", pages, key="workspace_nav", label_visibility="collapsed"
        )

    if page == "Quick lookup":
        render_app_header(
            "Quick lookup",
            "Check one URL or domain against local threat intelligence and the "
            "domain ML model without visiting the destination.",
        )

        try:
            artifact = _load_artifact(str(model_dir))
        except (OSError, TypeError, ValueError) as error:
            st.error(
                "The local ML artifact is not ready. Set up a trusted artifact "
                "to run quick lookup."
            )
            with st.expander("Setup details", expanded=False):
                st.code("python scripts/train_ml_artifact.py", language="shell")
                st.caption(type(error).__name__)
            return

        if (
            getattr(artifact.metadata, "evaluation_status", None)
            == "demo_only_synthetic"
        ):
            st.warning(
                "Demo ML artifact active. It uses synthetic training data only "
                "to exercise the interface and must not be interpreted as "
                "measured model performance."
            )

        indicators = load_ioc_records(db_path)
        if not indicators:
            st.warning(
                "CTI cache is empty. Quick lookup can still use the ML model, "
                "but known-indicator matching is unavailable."
            )

        st.caption(
            "Paste one address. ThreatFusion checks the local CTI cache and "
            "domain model without opening the destination."
        )
        lookup_input, lookup_action = st.columns([5, 1.15], vertical_alignment="bottom")
        with lookup_input:
            lookup_value = st.text_input(
                "URL or domain",
                placeholder="example.com or https://example.com/path",
                key="quick_lookup_input",
                on_change=_clear_quick_lookup_state,
            )
        with lookup_action:
            analyze_lookup = st.button(
                "Check",
                type="primary",
                width="stretch",
                disabled=not lookup_value.strip(),
                key="quick_lookup_analyze",
            )

        st.caption(
            "Passive by design · no page visit · no DNS resolution · no download"
        )

        if analyze_lookup:
            try:
                with st.spinner("Checking local threat signals…"):
                    st.session_state["quick_lookup_result"] = analyze_quick_lookup(
                        lookup_value,
                        indicators,
                        artifact,
                    )
            except (TypeError, ValueError) as error:
                st.session_state.pop("quick_lookup_result", None)
                st.error(f"Lookup input could not be analyzed: {error}")

        lookup_result = st.session_state.get("quick_lookup_result")
        if lookup_result is not None:
            render_quick_lookup_result(lookup_result)
        else:
            empty_state(
                "Enter one URL or domain",
                "ThreatFusion will normalize it, check the local CTI cache, "
                "score the domain, and explain the result.",
            )
        return

    if page == "Analysis history":
        render_app_header(
            "Analysis history",
            "Revisit saved runs, compare changes and record analyst decisions.",
        )
        _show_history(db_path)
        return
    if page == "Model evaluation":
        render_app_header(
            "Model evaluation",
            "Inspect the frozen model's measured performance and its limits.",
        )
        _show_model_evaluation(config.evaluation_report_path)
        return

    render_app_header()
    if config.public_mode:
        st.caption("Public workspace · Shared analysis history is disabled.")
    with st.expander(
        "New analysis"
        if st.session_state.get("analysis_result") is not None
        else "Telemetry intake",
        expanded=st.session_state.get("analysis_result") is None,
    ):
        intake_steps()
        telemetry_format = st.selectbox(
            "Telemetry format",
            [
                "Generic DNS CSV",
                "Zeek dns.log",
                "Pi-hole FTL database",
                "AdGuard Home query log",
            ],
            key="telemetry_format",
            on_change=_clear_analysis_state,
        )

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
            "AdGuard Home query log": "query-log JSON with host and timestamp fields",
        }
        st.caption(format_caption[telemetry_format])
        with st.expander("Input requirements", expanded=False):
            st.write(required_caption[telemetry_format])
            st.caption(
                "Optional fields enrich the evidence. Missing values are handled by the existing parser."
            )

        try:
            artifact = _load_artifact(str(model_dir))
        except (OSError, TypeError, ValueError) as error:
            st.error(
                "The local ML artifact is not ready. Set up a trusted artifact to analyze telemetry."
            )
            with st.expander("Setup details", expanded=False):
                st.code("python scripts/train_ml_artifact.py", language="shell")
                st.caption(type(error).__name__)
            return

        if (
            getattr(artifact.metadata, "evaluation_status", None)
            == "demo_only_synthetic"
        ):
            st.warning(
                "Demo ML artifact active. It uses synthetic training data only "
                "to exercise the interface and must not be interpreted as "
                "measured model performance."
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
        uploaded = st.file_uploader(
            upload_label,
            type=upload_types,
            help=upload_help,
            key=f"telemetry_upload_{telemetry_format}",
            on_change=_on_upload_change,
            args=(f"telemetry_upload_{telemetry_format}",),
        )

        st.markdown(
            '<p class="tf-privacy">Processed in memory. Raw DNS rows and client IPs are not saved. '
            "Reports and optional history contain aggregate findings only.</p>",
            unsafe_allow_html=True,
        )
        if uploaded is None:
            st.button("Analyze", type="primary", disabled=True, key="analyze_empty")
        else:
            content_bytes = uploaded.getvalue()
            fingerprint = f"{telemetry_format}:" + content_fingerprint(content_bytes)
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
                        result, diagnostics = analyze_pihole_query_db_with_diagnostics(
                            content_bytes,
                            indicators,
                            artifact,
                        )
                    except ValueError as error:
                        st.error(f"DNS telemetry could not be analyzed: {error}")
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
                            st.rerun()
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
                            with st.spinner("Analyzing telemetry…"):
                                result, diagnostics = analyzer(
                                    content,
                                    indicators,
                                    artifact,
                                )
                        except ValueError as error:
                            st.error(f"DNS telemetry could not be analyzed: {error}")
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
                            else:
                                st.rerun()

    result = st.session_state.get("analysis_result")
    diagnostics = st.session_state.get("dns_parse_diagnostics")
    if result is not None and diagnostics is not None:
        with st.expander("Input quality", expanded=False):
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

    else:
        empty_state(
            "Your findings will appear here",
            "Choose a source and upload a file to build your priority queue. Then select a domain to inspect the evidence.",
        )


if __name__ == "__main__":
    main()
