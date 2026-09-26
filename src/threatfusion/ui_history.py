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
            "No saved analyses yet",
            "Analyze telemetry, then choose Save aggregate analysis history under Export & save. Only aggregate findings are saved.",
        )
        return

    st.dataframe(
        pd.DataFrame(history_rows(summaries))[
            ["Run ID", "Created at", "Domains", "Known Threat", "High Risk", "Review"]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            "Created at": st.column_config.TextColumn(width="medium"),
            "Model": st.column_config.TextColumn(width="large"),
        },
    )

    with st.expander("All run statistics", expanded=False):
        st.dataframe(
            pd.DataFrame(history_rows(summaries)), hide_index=True, width="stretch"
        )

    selected_id = st.selectbox(
        "Inspect saved run",
        [summary.id for summary in summaries],
    )
    run_id = int(selected_id)
    selected_summary = next(summary for summary in summaries if summary.id == run_id)
    with st.expander("Reproducibility metadata", expanded=False):
        if selected_summary.audit_captured_at is None:
            st.caption(
                "This is a legacy saved run created before audit metadata was added."
            )
        else:
            st.write(
                "**Audit captured:** "
                + format_timestamp(selected_summary.audit_captured_at)
            )
            st.write("**Artifact:** " + (selected_summary.model_name or "Unknown"))
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
                                "Refreshed at": format_timestamp(item.refreshed_at),
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
                    "Known CTI sources": st.column_config.TextColumn(width="medium"),
                    "Analyst feedback": st.column_config.TextColumn(width="medium"),
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
            feedback_label(current.label) if current is not None else "Uncertain"
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
                value=(current.note if current is not None and current.note else ""),
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
