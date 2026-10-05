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
from threatfusion.i18n import tr, translate_dataframe
from threatfusion.ml_artifact import load_trusted_ml_artifact
from threatfusion.persistence import (
    get_active_analyst_suppressions,
    get_latest_analyst_feedback_for_domains,
    save_runtime_analysis,
)
from threatfusion.quick_lookup import (
    MAX_LOOKUP_INPUT_CHARS,
    analyze_quick_lookup_from_cache,
)
from threatfusion.reporting import build_analysis_report
from threatfusion.runtime_analysis import (
    analyze_adguard_query_log_with_diagnostics,
    analyze_dns_csv_with_diagnostics,
    analyze_dns_upload_with_diagnostics,
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
from threatfusion.ui_device_triage import render_device_triage
from threatfusion.ui_connections import render_connections
from threatfusion.ui_collector import render_collector
from threatfusion.ui_history import _show_history
from threatfusion.ui_investigation import _show_domain_detail
from threatfusion.ui_quick_lookup import (
    render_quick_lookup_empty_state,
    render_quick_lookup_result,
)
from threatfusion.ui_local_settings import resolve_managed_config, render_local_settings
from threatfusion.ui_theme import (
    THEME_OPTIONS,
    canonical_theme_name,
    inject_theme_css,
    metric_card,
    render_app_header,
    render_main_brand,
    render_priority_finding,
    render_sidebar_brand,
    section_label,
    status_card,
)

MAX_UPLOAD_BYTES = 100 * 1024 * 1024


@st.cache_resource
def _load_artifact(path_text: str, expected_checksum: str | None):
    return load_trusted_ml_artifact(
        Path(path_text),
        expected_checksum=expected_checksum,
    )


@st.fragment(run_every="10s")
def _show_system_status(
    db_path: Path,
    model_dir: Path,
    evaluation_report_path: Path,
    *,
    cti_stale_after_by_source=None,
    cti_only=False,
) -> None:
    st.sidebar.markdown(f"### {tr('Workspace health')}")

    model_path = model_dir / "model.joblib"
    metadata_path = model_dir / "metadata.json"
    model_ready = model_path.exists() and metadata_path.exists()
    status_card(
        tr("ML artifact"),
        tr("Disabled") if cti_only else tr("Present") if model_ready else tr("Missing"),
        "info" if cti_only else "good" if model_ready else "bad",
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
        cti_value = tr("Empty")
        cti_tone = "warn"
    elif stale_sources:
        cti_value = tr("{count} need review", count=len(stale_sources))
        cti_tone = "warn"
    else:
        cti_value = tr("{count} cached", count=len(statuses))
        cti_tone = "good"

    status_card(tr("CTI cache"), cti_value, cti_tone)

    holdout_ready = evaluation_report_path.is_file()
    status_card(
        tr("Final evaluation"),
        tr("Available") if holdout_ready else tr("Pending holdout"),
        "good" if holdout_ready else "info",
    )

    st.sidebar.markdown(f"### {tr('CTI sources')}")
    cached = {str(row["Source"]): row for row in status_rows}
    source_names = list(
        dict.fromkeys(["ThreatFox", "URLhaus", "PhishTank", "SGB", *cached])
    )
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
    with st.sidebar.expander(tr("Workspace details"), expanded=False):
        st.caption(
            tr(
                "Artifact status checks for local model and metadata files. The model is validated when analysis opens."
            )
        )
        st.caption(tr("Theme and language controls are available in the top bar."))
        st.caption(tr("CTI status describes the local cache, not a live feed connection."))


def _show_analysis_result(
    result,
    artifact,
    db_path: Path,
    *,
    history_enabled: bool,
    public_mode: bool = False,
) -> None:
    summary = summarize_runtime_result(result)

    st.subheader(tr("Priority findings"))
    st.caption(
        tr(
            "Start with the highest-priority domains, then open Domain investigation for the evidence."
        )
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
            tr(
                "Include {count} locally suppressed finding(s)",
                count=suppressed_priority_count,
            ),
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
                    tr(
                        "{count} additional priority finding(s) are available in Domain findings.",
                        count=len(visible_priority_rows) - 5,
                    )
                )
        else:
            if priority_rows and suppressed_priority_count:
                st.info(
                    tr(
                        "All current priority findings are locally suppressed. "
                        "Enable the checkbox above to include them."
                    )
                )
            else:
                st.success(tr("No Known Threat, High Risk, or Review findings."))

    with overview_right:
        section_label(tr("Verdict distribution"))
        st.plotly_chart(
            _verdict_distribution_figure(summary),
            width="stretch",
            config={"displayModeBar": False},
        )

    section_label(tr("Analysis overview"))
    columns = st.columns(6)
    metric_card(columns[0], tr("DNS events"), summary.event_count, accent="neutral")
    metric_card(
        columns[1],
        tr("Unique domains"),
        summary.domain_count,
        accent="neutral",
    )
    metric_card(
        columns[2],
        tr("Known Threat"),
        summary.known_threat_count,
        accent="red",
    )
    metric_card(
        columns[3],
        tr("High Risk"),
        summary.high_risk_count,
        accent="orange",
    )
    metric_card(
        columns[4],
        tr("Review"),
        summary.review_count,
        accent="yellow",
    )
    metric_card(columns[5], tr("Low"), summary.low_count, accent="green")

    st.caption(
        tr(
            "Verdicts are assigned per unique domain; DNS events count individual "
            "telemetry rows."
        )
    )

    findings_tab, device_tab, connection_tab, investigation_tab, matches_tab, campaign_tab, export_tab = st.tabs(
        [
            tr("Domain findings"),
            tr("Device triage"),
            tr("Connection activity"),
            tr("Domain investigation"),
            tr("IOC evidence"),
            tr("Related activity"),
            tr("Export & save"),
        ]
    )
    with findings_tab:
        render_findings_table(assessment_rows(result), key="live_findings")

    with device_tab:
        render_device_triage(result, public_mode=public_mode)

    with connection_tab:
        render_connections(result, public_mode=public_mode)

    with investigation_tab:
        all_rows = assessment_rows(result)
        if all_rows:
            domain_options = [row["Domain"] for row in all_rows]
            if st.session_state.get("live_domain_detail") not in domain_options:
                st.session_state.pop("live_domain_detail", None)
            selected_domain = st.selectbox(
                tr("Inspect a domain"),
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
            empty_state(tr("No domains to investigate"), tr("Upload telemetry to begin."))

    with matches_tab:
        corroboration = ioc_corroboration_rows(result)
        rows = match_rows(result)

        if corroboration:
            st.markdown(f"#### {tr('Source corroboration')}")
            st.caption(
                tr(
                    "Multiple cached CTI sources strengthen analyst context. "
                    "Corroboration does not override evidence-scope rules."
                )
            )
            st.dataframe(
                translate_dataframe(pd.DataFrame(corroboration)),
                hide_index=True,
                width="stretch",
            )

        if rows:
            st.markdown(f"#### {tr('IOC evidence')}")
            st.dataframe(
                translate_dataframe(pd.DataFrame(rows)),
                hide_index=True,
                width="stretch",
            )
        else:
            st.info(tr("No cached IOC matches were found."))

    with campaign_tab:
        try:
            related_report = find_related_activity(result)
        except ValueError as error:
            st.warning(
                tr(
                    "Related-activity visualization was skipped because the candidate set was too large: {error}",
                    error=error,
                )
            )
            related_report = None

        if related_report is not None and related_report.clusters:
            st.info(
                tr(
                    "These groups show possible related suspicious activity based "
                    "on weighted local DNS and CTI context. High-fan-out shared "
                    "infrastructure is down-weighted or filtered. The groups do "
                    "not prove one malware campaign."
                )
            )
            st.plotly_chart(
                _relationship_figure(related_report, result),
                width="stretch",
            )
            st.write(f"**{tr('Possible related-activity groups')}**")
            st.dataframe(
                translate_dataframe(pd.DataFrame(cluster_rows(related_report))),
                hide_index=True,
                width="stretch",
            )
            with st.expander(
                tr("Relationship evidence and noise adjustments"), expanded=False
            ):
                st.write(f"**{tr('Relationship evidence')}**")
                st.dataframe(
                    translate_dataframe(pd.DataFrame(relationship_rows(related_report))),
                    hide_index=True,
                    width="stretch",
                )
                st.caption(
                    tr(
                        "Raw client IP values are not shown. Strength is a local "
                        "evidence score, not an attribution probability. Relationship "
                        "rows expose aggregate counts and explainable noise "
                        "adjustments only."
                    )
                )
        elif related_report is not None:
            st.info(
                tr(
                    "No possible related-activity groups were found among Known "
                    "Threat, High Risk, or Review domains."
                )
            )

    with export_tab:
        report = build_analysis_report(
            result,
            model_name=artifact.metadata.model_name if artifact else "cti_only_ml_disabled",
        )
        export_columns = st.columns(2)
        export_columns[0].download_button(
            tr("Download JSON report"),
            data=report.json_text,
            file_name="threatfusion_analysis.json",
            mime="application/json",
            width="stretch",
        )
        export_columns[1].download_button(
            tr("Download CSV findings"),
            data=report.csv_text,
            file_name="threatfusion_findings.csv",
            mime="text/csv",
            width="stretch",
        )
        st.caption(
            tr(
                "Exports contain aggregate/per-domain findings only. Raw DNS rows, "
                "client IP values, and response IP values are not included."
            )
        )

        if history_enabled and st.button(tr("Save aggregate analysis history")):
            audit_metadata = st.session_state.get("analysis_audit_metadata")
            if audit_metadata is None:
                st.error(
                    tr(
                        "Re-run the analysis before saving so model, threshold, "
                        "and CTI audit metadata can be captured."
                    )
                )
            else:
                run_id = save_runtime_analysis(
                    db_path,
                    result,
                    model_name=artifact.metadata.model_name,
                    audit_metadata=audit_metadata,
                )
                st.success(
                    tr(
                        "Analysis #{run_id} saved with reproducibility metadata. Raw DNS rows and client IPs were not stored.",
                        run_id=run_id,
                    )
                )


def _clear_analysis_state() -> None:
    """Discard stale UI results when the user changes or removes input."""
    for key in (
        "upload_fingerprint",
        "analysis_result",
        "dns_parse_diagnostics",
        "dns_input_detection",
        "analysis_audit_metadata",
    ):
        st.session_state.pop(key, None)


def _on_upload_change(upload_key: str) -> None:
    if st.session_state.get(upload_key) is None:
        _clear_analysis_state()


def _clear_quick_lookup_state() -> None:
    st.session_state.pop("quick_lookup_result", None)


def _render_primary_workspace_launcher(current_page: str) -> None:
    """Keep the two core user workflows visually dominant in the main canvas."""
    with st.container(border=True, key="primary_workspace_launcher"):
        st.markdown(
            '<div class="tf-primary-workspace-head">'
            f'<div><div class="tf-primary-workspace-kicker">{tr("Primary workspace")}</div>'
            f'<div class="tf-primary-workspace-title">{tr("Choose how you want to investigate")}</div></div>'
            '<div class="tf-primary-workspace-hint">'
            f'{tr("Quick lookup is the default entry point; telemetry analysis is one click away for deeper batch investigation.")}'
            '</div></div>',
            unsafe_allow_html=True,
        )

        lookup_col, telemetry_col = st.columns(2)

        lookup_active = current_page == "Quick lookup"
        with lookup_col:
            lookup_state = (
                tr("Current workspace") if lookup_active else tr("Instant investigation")
            )
            lookup_class = " tf-primary-card--active" if lookup_active else ""
            st.markdown(
                f'<div class="tf-primary-card{lookup_class}">'
                '<div class="tf-primary-card-top">'
                f'<span class="tf-primary-card-number">01 · {tr("QUICK LOOKUP")}</span>'
                f'<span class="tf-primary-card-state">{lookup_state}</span>'
                '</div>'
                f'<div class="tf-primary-card-title">{tr("Check a URL, domain or IP")}</div>'
                '<div class="tf-primary-card-copy">'
                f'{tr("Paste one address for a fast passive CTI + ML check with a clear color-coded result and evidence path.")}'
                '</div>'
                '<div class="tf-primary-card-tags">'
                f'<span class="tf-primary-card-tag">{tr("Single target")}</span>'
                f'<span class="tf-primary-card-tag">{tr("Passive")}</span>'
                f'<span class="tf-primary-card-tag">{tr("Fast verdict")}</span>'
                '</div></div>',
                unsafe_allow_html=True,
            )
            if st.button(
                tr("Open quick lookup"),
                key="open_quick_lookup_workspace",
                type="primary" if lookup_active else "secondary",
                width="stretch",
            ):
                st.session_state["workspace_nav"] = "Quick lookup"
                st.rerun()

        telemetry_active = current_page == "Analyze telemetry"
        with telemetry_col:
            telemetry_state = (
                tr("Current workspace") if telemetry_active else tr("Batch investigation")
            )
            telemetry_class = " tf-primary-card--active" if telemetry_active else ""
            st.markdown(
                f'<div class="tf-primary-card{telemetry_class}">'
                '<div class="tf-primary-card-top">'
                f'<span class="tf-primary-card-number">02 · {tr("TELEMETRY")}</span>'
                f'<span class="tf-primary-card-state">{telemetry_state}</span>'
                '</div>'
                f'<div class="tf-primary-card-title">{tr("Analyze telemetry")}</div>'
                '<div class="tf-primary-card-copy">'
                f'{tr("Upload DNS CSV, Zeek, Pi-hole or AdGuard data and correlate CTI, ML and DNS behavior at scale.")}'
                '</div>'
                '<div class="tf-primary-card-tags">'
                f'<span class="tf-primary-card-tag">{tr("Multi-domain")}</span>'
                f'<span class="tf-primary-card-tag">{tr("Behavior signals")}</span>'
                f'<span class="tf-primary-card-tag">{tr("Investigation queue")}</span>'
                '</div></div>',
                unsafe_allow_html=True,
            )
            if st.button(
                tr("Open telemetry analysis"),
                key="open_telemetry_workspace",
                type="primary" if telemetry_active else "secondary",
                width="stretch",
            ):
                st.session_state["workspace_nav"] = "Analyze telemetry"
                st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="ThreatFusion AI",
        page_icon=":material/shield:",
        layout="wide",
    )

    try:
        config, local_root = resolve_managed_config(load_app_config())
    except (OSError, TypeError, ValueError):
        st.error(tr("Application configuration is invalid. Check runtime paths and private file permissions."))
        return

    db_path = config.db_path
    model_dir = config.model_dir

    selected_theme = st.session_state.get("visual_theme")
    if isinstance(selected_theme, str):
        selected_theme = canonical_theme_name(selected_theme)
    if selected_theme not in THEME_OPTIONS:
        selected_theme = "Midnight"
    st.session_state["visual_theme"] = selected_theme

    inject_theme_css(selected_theme)
    render_sidebar_brand()
    render_main_brand()
    if "telemetry_format" in st.session_state:
        st.session_state["telemetry_format"] = st.session_state["telemetry_format"]

    if local_root is not None:
        try:
            render_local_settings(local_root)
        except (OSError, ValueError, TypeError):
            st.sidebar.error(tr("Local settings could not be read. Check private file permissions."))

    navigation = st.sidebar.container()
    _show_system_status(
        db_path,
        model_dir,
        config.evaluation_report_path,
        cti_stale_after_by_source=config.cti_stale_after_by_source,
        cti_only=config.cti_only,
    )
    pages = [
        "Analyze telemetry",
        "Quick lookup",
        "Analysis history",
        "Model evaluation",
    ]
    collector_available = not config.public_mode or (local_root is not None and config.cti_only)
    if collector_available:
        pages.append("Collected connections")
    if not config.history_enabled:
        pages.remove("Analysis history")

    default_page = (
        "Analyze telemetry"
        if st.session_state.get("analysis_result") is not None
        else "Quick lookup"
    )
    page = st.session_state.get("workspace_nav", default_page)
    if page not in pages:
        page = default_page
    st.session_state["workspace_nav"] = page

    # Keep history/evaluation as secondary navigation. The two core workflows
    # live prominently in the main canvas instead of being tiny sidebar items.
    with navigation:
        st.markdown(f"### {tr('Secondary views')}")
        if config.history_enabled:
            if st.button(
                tr("Analysis history"),
                key="nav_analysis_history",
                type="primary" if page == "Analysis history" else "secondary",
                width="stretch",
            ):
                st.session_state["workspace_nav"] = "Analysis history"
                st.rerun()
        if st.button(
            tr("Model evaluation"),
            key="nav_model_evaluation",
            type="primary" if page == "Model evaluation" else "secondary",
            width="stretch",
        ):
            st.session_state["workspace_nav"] = "Model evaluation"
            st.rerun()
        st.caption(tr("Primary tools are available in the main workspace."))
        if collector_available:
            if st.button(tr("Collected connections"), key="nav_collector", width="stretch"):
                st.session_state["workspace_nav"] = "Collected connections"
                st.rerun()

    _render_primary_workspace_launcher(page)
    if config.cti_only:
        st.warning(tr(
            "CTI-only mode: ML is disabled. Results use the local CTI cache and "
            "available DNS behavior only. A missing match does not establish "
            "that a target is benign. Shared history is disabled in this mode."
        ))

    if page == "Collected connections":
        render_app_header("Collected connections", "Inspect automatically collected local Zeek connection activity.")
        render_collector(local_root / "collector" if local_root else config.collector_state_dir,
                         public_mode=not collector_available)
        return

    if page == "Quick lookup":
        render_app_header(
            "Quick lookup",
            "Check one URL or domain against local threat intelligence and the "
            "domain ML model without visiting the destination.",
        )

        try:
            artifact = None if config.cti_only else _load_artifact(str(model_dir), config.model_sha256)
        except (OSError, TypeError, ValueError) as error:
            st.error(
                tr(
                    "The local ML artifact is not ready. Set up a trusted artifact "
                    "to run quick lookup."
                )
            )
            with st.expander(tr("Setup details"), expanded=False):
                st.code("python scripts/train_ml_artifact.py", language="shell")
                st.caption(type(error).__name__)
            return

        if artifact is not None and (
            getattr(artifact.metadata, "evaluation_status", None)
            == "demo_only_synthetic"
        ):
            st.warning(
                tr(
                    "Demo ML artifact active. It uses synthetic training data only "
                    "to exercise the interface and must not be interpreted as "
                    "measured model performance."
                )
            )

        if not list_cti_cache_status(db_path):
            st.warning(
                tr(
                    "CTI cache is empty. CTI-only lookup has no known-indicator evidence."
                    if config.cti_only else
                    "CTI cache is empty. Quick lookup can still use the ML model, "
                    "but known-indicator matching is unavailable."
                )
            )

        st.caption(
            tr(
                "Paste one URL, domain or IP. ThreatFusion checks the local CTI "
                "cache and uses the domain model only when the host is a domain."
            )
        )
        lookup_input, lookup_action = st.columns([5, 1.15], vertical_alignment="bottom")
        with lookup_input:
            lookup_value = st.text_input(
                tr("URL, domain or IP"),
                placeholder=tr("example.com, 143.20.185.213, or https://example.com/path"),
                max_chars=MAX_LOOKUP_INPUT_CHARS,
                key="quick_lookup_input",
                on_change=_clear_quick_lookup_state,
            )
        with lookup_action:
            analyze_lookup = st.button(
                tr("Check"),
                type="primary",
                width="stretch",
                key="quick_lookup_analyze",
            )

        st.caption(
            tr("Passive by design · no page visit · no DNS resolution · no download")
        )

        if analyze_lookup:
            if not lookup_value.strip():
                st.warning(tr("Enter a URL, domain or IP before checking it."))
            else:
                try:
                    with st.spinner(tr("Checking local threat signals…")):
                        st.session_state["quick_lookup_result"] = (
                            analyze_quick_lookup_from_cache(
                                lookup_value,
                                db_path,
                                artifact,
                            )
                        )
                except (TypeError, ValueError) as error:
                    st.session_state.pop("quick_lookup_result", None)
                    st.error(tr("Lookup input could not be analyzed: {error}", error=error))

        lookup_result = st.session_state.get("quick_lookup_result")
        if lookup_result is not None:
            render_quick_lookup_result(lookup_result)
        else:
            render_quick_lookup_empty_state()
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
        st.caption(tr("Session-only workspace · Shared analysis history is disabled."))
    with st.expander(
        tr("New analysis")
        if st.session_state.get("analysis_result") is not None
        else tr("Telemetry intake"),
        expanded=st.session_state.get("analysis_result") is None,
    ):
        intake_steps()
        telemetry_format = st.selectbox(
            tr("Telemetry format"),
            [
                "Auto-detect",
                "Generic DNS CSV",
                "Zeek dns.log",
                "Pi-hole FTL database",
                "AdGuard Home query log",
            ],
            key="telemetry_format",
            on_change=_clear_analysis_state,
            format_func=tr,
        )

        format_caption = {
            "Auto-detect": (
                "Auto-detect · CSV/TSV/TXT/XLSX/XLS/PCAP/Zeek/Suricata/Pi-hole/AdGuard · max 100 MB"
            ),
            "Generic DNS CSV": "Generic DNS CSV · UTF-8 · max 100 MB",
            "Zeek dns.log": "Zeek dns.log text export · max 100 MB",
            "Pi-hole FTL database": "Pi-hole FTL SQLite database · max 100 MB",
            "AdGuard Home query log": "AdGuard Home JSON query log · max 100 MB",
        }
        required_caption = {
            "Auto-detect": (
                "No manual mapping required. ThreatFusion detects the file type, "
                "delimiter, text encoding, DNS columns, packet captures, Zeek "
                "logs and supported network telemetry automatically."
            ),
            "Generic DNS CSV": "query_name; all other fields are optional",
            "Zeek dns.log": "Zeek #fields header with query",
            "Pi-hole FTL database": "queries view with standard Pi-hole fields",
            "AdGuard Home query log": "query-log JSON with host and timestamp fields",
        }
        st.caption(tr(format_caption[telemetry_format]))
        with st.expander(tr("Input requirements"), expanded=False):
            st.write(tr(required_caption[telemetry_format]))
            st.caption(
                tr("Optional fields enrich the evidence. Missing values are handled by the existing parser.")
            )

        upload_label = {
            "Auto-detect": "Upload telemetry",
            "Generic DNS CSV": "Upload DNS CSV",
            "Zeek dns.log": "Upload Zeek dns.log",
            "Pi-hole FTL database": "Upload Pi-hole FTL database",
            "AdGuard Home query log": "Upload AdGuard Home query log",
        }[telemetry_format]
        upload_types = {
            "Auto-detect": [
                "csv",
                "tsv",
                "txt",
                "log",
                "json",
                "xlsx",
                "xls",
                "db",
                "sqlite",
                "sqlite3",
                "pcap",
                "pcapng",
                "cap",
                "capinfos",
                "dnstop",
            ],
            "Generic DNS CSV": ["csv"],
            "Zeek dns.log": ["log", "txt"],
            "Pi-hole FTL database": ["db", "sqlite", "sqlite3"],
            "AdGuard Home query log": ["json", "log", "txt"],
        }[telemetry_format]
        upload_help = {
            "Auto-detect": (
                "Upload a DNS telemetry file. ThreatFusion detects CSV/TSV "
                "delimiters, common text encodings, Excel worksheets, common "
                "DNS column names, Zeek dns.log/conn.log, PCAP/PCAPNG DNS, "
                "Pi-hole FTL SQLite, Suricata EVE, dnstop, and AdGuard Home "
                "query logs automatically."
            ),
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
            tr(upload_label),
            type=upload_types,
            help=tr(upload_help),
            key=f"telemetry_upload_{telemetry_format}",
            on_change=_on_upload_change,
            args=(f"telemetry_upload_{telemetry_format}",),
        )

        st.markdown(
            f'<p class="tf-privacy">{tr("Processed in memory. Raw DNS rows and client IPs are not saved. Reports and optional history contain aggregate findings only.")}</p>',
            unsafe_allow_html=True,
        )
        if uploaded is None:
            st.button(tr("Analyze"), type="primary", disabled=True, key="analyze_empty")
        else:
            content_bytes = uploaded.getvalue()
            fingerprint = f"{telemetry_format}:" + content_fingerprint(content_bytes)
            if st.session_state.get("upload_fingerprint") != fingerprint:
                st.session_state["upload_fingerprint"] = fingerprint
                st.session_state.pop("analysis_result", None)
                st.session_state.pop("dns_parse_diagnostics", None)
                st.session_state.pop("dns_input_detection", None)
                st.session_state.pop("analysis_audit_metadata", None)

            content = None
            input_ready = True
            if len(content_bytes) > MAX_UPLOAD_BYTES:
                st.error(tr("Uploaded telemetry exceeds the 100 MB application limit."))
                input_ready = False
            elif telemetry_format not in {"Auto-detect", "Pi-hole FTL database"}:
                try:
                    content = content_bytes.decode("utf-8-sig")
                except UnicodeDecodeError:
                    st.error(tr("Telemetry input must use UTF-8 encoding."))
                    input_ready = False

            if input_ready and st.button(
                tr("Analyze"),
                type="primary",
                key="analyze_telemetry",
            ):
                try:
                    with st.spinner(tr("Preparing local analysis engine…")):
                        artifact = None if config.cti_only else _load_artifact(
                            str(model_dir),
                            config.model_sha256,
                        )
                        indicators = load_ioc_records(db_path)
                except (OSError, TypeError, ValueError) as error:
                    st.error(
                        tr(
                            "The local ML artifact is not ready. Set up a trusted artifact to analyze telemetry."
                        )
                    )
                    with st.expander(tr("Setup details"), expanded=False):
                        st.code("python scripts/train_ml_artifact.py", language="shell")
                        st.caption(type(error).__name__)
                else:
                    if artifact is not None and (
                        getattr(artifact.metadata, "evaluation_status", None)
                        == "demo_only_synthetic"
                    ):
                        st.warning(
                            tr(
                                "Demo ML artifact active. It uses synthetic training data only "
                                "to exercise the interface and must not be interpreted as "
                                "measured model performance."
                            )
                        )

                    if not indicators:
                        st.warning(
                            tr(
                                "CTI cache is empty. Results can include DNS behavior only; "
                                "known-indicator matching and ML are unavailable."
                                if config.cti_only else
                                "CTI cache is empty. Analysis can still use ML and DNS "
                                "behavior, but known-threat matching will be unavailable. "
                                "Run scripts/refresh_cti_cache.py to populate the cache."
                            )
                        )

                    try:
                        with st.spinner(tr("Analyzing telemetry…")):
                            if telemetry_format == "Auto-detect":
                                result, diagnostics, detection = (
                                    analyze_dns_upload_with_diagnostics(
                                        content_bytes,
                                        getattr(uploaded, "name", None),
                                        indicators,
                                        artifact,
                                    )
                                )
                            elif telemetry_format == "Pi-hole FTL database":
                                result, diagnostics = (
                                    analyze_pihole_query_db_with_diagnostics(
                                        content_bytes,
                                        indicators,
                                        artifact,
                                    )
                                )
                                detection = None
                            else:
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
                                detection = None
                    except ValueError as error:
                        st.error(
                            tr(
                                "DNS telemetry could not be analyzed: {error}",
                                error=error,
                            )
                        )
                    else:
                        st.session_state["analysis_result"] = result
                        st.session_state["dns_parse_diagnostics"] = diagnostics
                        if detection is None:
                            st.session_state.pop("dns_input_detection", None)
                        else:
                            st.session_state["dns_input_detection"] = detection
                        if config.cti_only:
                            st.session_state.pop("analysis_audit_metadata", None)
                            st.rerun()
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
                                tr(
                                    "Analysis completed, but reproducibility metadata could not be captured. Re-run the analysis before saving history."
                                )
                            )
                        else:
                            st.rerun()


    result = st.session_state.get("analysis_result")
    diagnostics = st.session_state.get("dns_parse_diagnostics")
    detection = st.session_state.get("dns_input_detection")
    artifact = None
    if result is not None:
        try:
            artifact = None if config.cti_only else _load_artifact(str(model_dir), config.model_sha256)
        except (OSError, TypeError, ValueError) as error:
            st.error(
                tr(
                    "The local ML artifact is not ready. Set up a trusted artifact to analyze telemetry."
                )
            )
            with st.expander(tr("Setup details"), expanded=False):
                st.code("python scripts/train_ml_artifact.py", language="shell")
                st.caption(type(error).__name__)
            return
    if result is not None and diagnostics is not None:
        with st.expander(tr("Input quality"), expanded=False):
            if detection is not None:
                encoding = (
                    f" · {detection.encoding}"
                    if detection.encoding
                    else ""
                )
                detail = detection.detail
                if detail.startswith("worksheet: "):
                    detail = tr(
                        "worksheet: {sheet}",
                        sheet=detail.split(": ", 1)[1],
                    )
                else:
                    detail = tr(detail)
                st.caption(
                    tr(
                        "Detected input: {format} · {detail}{encoding}",
                        format=tr(detection.format_name),
                        detail=detail,
                        encoding=encoding,
                    )
                )
            st.caption(
                tr(
                    "Input quality: {accepted}/{total} rows accepted; {missing} missing query names; {timestamps} invalid timestamps; {ips} invalid response IPs.",
                    accepted=diagnostics.accepted_rows,
                    total=diagnostics.total_rows,
                    missing=diagnostics.skipped_missing_query_name,
                    timestamps=diagnostics.invalid_timestamps,
                    ips=diagnostics.invalid_response_ips,
                )
            )
    if result is not None:
        _show_analysis_result(
            result,
            artifact,
            db_path,
            history_enabled=config.history_enabled,
            public_mode=config.public_mode,
        )

    else:
        empty_state(
            tr("Your findings will appear here"),
            tr("Choose a source and upload a file to build your priority queue. Then select a domain to inspect the evidence."),
        )


if __name__ == "__main__":
    main()
