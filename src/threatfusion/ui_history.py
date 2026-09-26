"""Saved run browsing and the existing local analyst workflow."""

from __future__ import annotations

from pathlib import Path
import pandas as pd
import streamlit as st
from .dashboard import (
    feedback_label,
    format_timestamp,
    history_rows,
    persisted_assessment_rows,
)
from .i18n import tr, translate_dataframe
from .persistence import (
    apply_history_retention,
    compare_analysis_runs,
    delete_analysis_run,
    get_analysis_assessments,
    get_analyst_feedback,
    list_analysis_runs,
    save_analyst_feedback,
    save_bulk_analyst_feedback,
)
from .ui_components import empty_state


def _show_history(db_path: Path) -> None:
    summaries = list_analysis_runs(db_path)
    if not summaries:
        empty_state(
            tr("No saved analyses yet"),
            tr("Analyze telemetry, then choose Save aggregate analysis history under Export & save. Only aggregate findings are saved."),
        )
        return

    st.dataframe(
        translate_dataframe(
            pd.DataFrame(history_rows(summaries))[
                ["Run ID", "Created at", "Domains", "Known Threat", "High Risk", "Review"]
            ]
        ),
        hide_index=True,
        width="stretch",
        column_config={
            "Created at": st.column_config.TextColumn(width="medium"),
            "Model": st.column_config.TextColumn(width="large"),
        },
    )

    with st.expander(tr("All run statistics"), expanded=False):
        st.dataframe(
            translate_dataframe(pd.DataFrame(history_rows(summaries))), hide_index=True, width="stretch"
        )

    selected_id = st.selectbox(
        tr("Inspect saved run"),
        [summary.id for summary in summaries],
    )
    run_id = int(selected_id)
    selected_summary = next(summary for summary in summaries if summary.id == run_id)
    with st.expander(tr("Reproducibility metadata"), expanded=False):
        if selected_summary.audit_captured_at is None:
            st.caption(
                tr("This is a legacy saved run created before audit metadata was added.")
            )
        else:
            st.write(
                f"**{tr('Audit captured')}:** "
                + format_timestamp(selected_summary.audit_captured_at)
            )
            st.write(f"**{tr('Artifact')}:** " + (selected_summary.model_name or tr("Unknown")))
            checksum = selected_summary.artifact_checksum or tr("Unknown")
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
                    f"**{tr('Frozen thresholds')}:** "
                    f"high {selected_summary.high_threshold:.6f} · "
                    f"medium {selected_summary.medium_threshold:.6f} · "
                    f"low {selected_summary.low_threshold:.6f}"
                )
            if selected_summary.cti_sources:
                st.write(f"**{tr('CTI snapshot context')}**")
                st.dataframe(
                    translate_dataframe(
                        pd.DataFrame(
                            [
                                {
                                    "Source": item.source,
                                    "Refreshed at": format_timestamp(item.refreshed_at),
                                    "Records": item.record_count,
                                    "Status": item.freshness.title(),
                                }
                                for item in selected_summary.cti_sources
                            ]
                        )
                    ),
                    hide_index=True,
                    width="stretch",
                )
            else:
                st.caption(tr("No CTI source refresh metadata was captured."))

    comparison = compare_analysis_runs(db_path, run_id)
    with st.expander(tr("Compare with previous analysis"), expanded=False):
        if comparison.previous_run_id is None:
            st.caption(
                tr(
                    "No earlier saved analysis exists. Every domain in this run "
                    "is new relative to saved history."
                )
            )
        else:
            st.caption(
                f"Comparing run #{run_id} with previous run "
                f"#{comparison.previous_run_id}."
            )
        compare_columns = st.columns(3)
        compare_columns[0].metric(tr("New domains"), len(comparison.new_domains))
        compare_columns[1].metric(
            tr("No longer present"),
            len(comparison.removed_domains),
        )
        compare_columns[2].metric(
            tr("Verdict changes"),
            len(comparison.verdict_changes),
        )
        if comparison.new_domains:
            st.write(f"**{tr('New since previous analysis')}**")
            st.dataframe(
                pd.DataFrame({"Domain": comparison.new_domains}),
                hide_index=True,
                width="stretch",
            )
        if comparison.removed_domains:
            st.write(f"**{tr('No longer present')}**")
            st.dataframe(
                pd.DataFrame({"Domain": comparison.removed_domains}),
                hide_index=True,
                width="stretch",
            )
        if comparison.verdict_changes:
            st.write(f"**{tr('Verdict changes')}**")
            st.dataframe(
                translate_dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Domain": item.domain,
                                "Previous verdict": item.previous_verdict,
                                "Current verdict": item.current_verdict,
                            }
                            for item in comparison.verdict_changes
                        ]
                    )
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
            lambda value: f"{value:.4f}" if value is not None else ""
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
            tr("Verdict"),
            ["All", *sorted(frame["Verdict"].unique())],
            key=f"history_verdict_filter_{run_id}",
            format_func=tr,
        )
        review_filter = filter_columns[1].selectbox(
            tr("Review state"),
            [
                "All",
                "Unreviewed",
                "Reviewed",
                "Confirmed Threat",
                "Benign",
                "Uncertain",
            ],
            key=f"history_review_filter_{run_id}",
            format_func=tr,
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
            tr("CTI source"),
            ["All", *source_values],
            key=f"history_source_filter_{run_id}",
            format_func=tr,
        )

        filtered_frame = frame.copy()
        if verdict_filter != "All":
            filtered_frame = filtered_frame[filtered_frame["Verdict"] == verdict_filter]
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
                    lambda value: (
                        source_filter in {item.strip() for item in value.split(",")}
                    )
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
            st.info(tr("No saved findings match the current triage filters."))
        else:
            st.dataframe(
                translate_dataframe(filtered_frame[compact_columns]),
                hide_index=True,
                width="stretch",
                column_config={
                    "Domain": st.column_config.TextColumn(width="medium"),
                    "Verdict": st.column_config.TextColumn(width="small"),
                    "ML score": st.column_config.TextColumn(width="small"),
                    "ML tier": st.column_config.TextColumn(width="small"),
                    "DNS events": st.column_config.NumberColumn(width="small"),
                    "Known CTI sources": st.column_config.TextColumn(width="medium"),
                    "Analyst feedback": st.column_config.TextColumn(width="medium"),
                },
            )

        st.write(f"**{tr('Analyst review')}**")
        st.caption(
            tr(
                "Feedback is local analyst context only. It does not change the "
                "original verdict, retrain the model, or alter frozen evaluation."
            )
        )

        feedback_options = {
            "Confirmed Threat": "confirmed_threat",
            "Benign": "benign",
            "Uncertain": "uncertain",
        }
        option_labels = list(feedback_options)

        with st.expander(tr("Bulk review selected findings"), expanded=False):
            bulk_candidates = (
                filtered_frame["Domain"].tolist()
                if not filtered_frame.empty
                else [assessment.domain for assessment in assessments]
            )
            bulk_domains = st.multiselect(
                tr("Findings to review"),
                bulk_candidates,
                key=f"bulk_feedback_domains_{run_id}",
            )
            bulk_label = st.selectbox(
                tr("Bulk analyst label"),
                option_labels,
                key=f"bulk_feedback_label_{run_id}",
                format_func=tr,
            )
            bulk_note = st.text_area(
                tr("Optional bulk analyst note"),
                max_chars=500,
                key=f"bulk_feedback_note_{run_id}",
            )
            bulk_confirm = st.checkbox(
                tr("Apply this label only to the selected findings."),
                key=f"bulk_feedback_confirm_{run_id}",
            )
            if st.button(
                tr("Apply bulk review"),
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
            tr("Finding to review"),
            review_domains,
            key=f"feedback_domain_{run_id}",
        )
        current = feedback_by_domain.get(feedback_domain)
        current_label = (
            feedback_label(current.label) if current is not None else "Uncertain"
        )
        current_index = (
            option_labels.index(current_label)
            if current_label in option_labels
            else option_labels.index("Uncertain")
        )

        with st.form(f"analyst_feedback_{run_id}_{feedback_domain}"):
            selected_feedback = st.selectbox(
                tr("Analyst label"),
                option_labels,
                index=current_index,
                format_func=tr,
            )
            note = st.text_area(
                tr("Optional analyst note"),
                value=(current.note if current is not None and current.note else ""),
                max_chars=500,
            )
            submitted = st.form_submit_button(tr("Save analyst feedback"))

        if submitted:
            save_analyst_feedback(
                db_path,
                run_id,
                feedback_domain,
                feedback_options[selected_feedback],
                note=note,
            )
            st.success(
                tr(
                    "Analyst feedback saved. The original ThreatFusion verdict "
                    "was not changed."
                )
            )
            st.rerun()

    with st.expander(tr("History retention and deletion"), expanded=False):
        st.warning(
            tr(
                "These controls permanently delete local saved history. "
                "Detector logic and the current in-memory analysis are unchanged."
            )
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
                tr("Retention: keep latest N saved runs"),
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
            tr("Apply retention cleanup"),
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
                st.info(tr("No saved runs were old enough to delete."))
