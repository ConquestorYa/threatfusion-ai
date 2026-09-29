"""Frozen evaluation presentation; no training or scoring runs from this page."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from .evaluation_dashboard import (
    operating_point_rows,
    source_metric_rows,
    summarize_holdout_report,
)
from .i18n import tr, translate_dataframe
from .ml_evaluation_report import read_frozen_holdout_report
from .ml_artifact import LEXICAL_C4_DEVELOPMENT_CANDIDATE
from .ml_final_provenance import (
    LEXICAL_C4_ARTIFACT_SHA256,
    LEXICAL_C4_FREEZE_CUTOFF,
)
from .ui_theme import apply_plotly_theme, metric_card, palette


def _is_current_lexical_final_report(report) -> bool:
    identity = report.provenance
    try:
        report_cutoff_matches = (
            datetime.fromisoformat(
                report.malicious_first_seen_after.replace("Z", "+00:00")
            )
            == datetime.fromisoformat(
                LEXICAL_C4_FREEZE_CUTOFF.replace("Z", "+00:00")
            )
        )
    except (AttributeError, ValueError):
        report_cutoff_matches = False
    return bool(
        report.model_name == LEXICAL_C4_DEVELOPMENT_CANDIDATE
        and report.protocol == "fresh_collection_disjoint_first_seen_filtered"
        and report_cutoff_matches
        and identity is not None
        and identity.schema_version == 1
        and identity.protocol
        == "post_freeze_temporal_malicious_plus_confirmed_benign_dns"
        and identity.model_name == LEXICAL_C4_DEVELOPMENT_CANDIDATE
        and identity.artifact_sha256 == LEXICAL_C4_ARTIFACT_SHA256
        and identity.cutoff == LEXICAL_C4_FREEZE_CUTOFF
    )


def _show_model_evaluation(report_path: Path) -> None:

    if not report_path.is_file():
        with st.container(border=True):
            st.markdown(f"### {tr('Final holdout not evaluated')}")
            st.write(
                tr(
                    "The frozen Lexical C4 model's final evaluation is pending. "
                    "The historical C4 final result does not apply to it."
                )
            )
            st.caption(
                tr(
                    "Use a new untouched post-freeze holdout and verify its "
                    "provenance before reporting Lexical C4 final metrics."
                )
            )
            with st.expander(tr("Show final-evaluation command"), expanded=False):
                st.code(
                    "python scripts\\evaluate_ml_final_holdout.py "
                    "--artifact-dir data\\models\\development-v4-lexical-c4 "
                    f"--expected-artifact-sha256 {LEXICAL_C4_ARTIFACT_SHA256} "
                    "--development-snapshot-dir data\\snapshots\\development-v2 "
                    "--holdout-snapshot-dir data\\snapshots\\holdout-lexical-c4-final "
                    f"--malicious-first-seen-after {LEXICAL_C4_FREEZE_CUTOFF} "
                    "--json-output data\\evaluation\\final_holdout_lexical_c4.json",
                    language="powershell",
                )
        return

    try:
        report = read_frozen_holdout_report(report_path)
    except (OSError, TypeError, ValueError) as error:
        st.error(tr("The final holdout report could not be loaded."))
        st.caption(type(error).__name__)
        return

    summary = summarize_holdout_report(report)

    if _is_current_lexical_final_report(report):
        st.success(tr("Frozen Lexical C4 final report loaded with provenance."))
    else:
        st.info(
            tr(
                "Historical or unbound model report. Frozen Lexical C4 final "
                "evaluation is pending."
            )
        )
    st.write(f"**{tr('Model')}:** {summary.model_name}")
    st.write(
        f"**{tr('Snapshot dates')}:** "
        f"{tr('development')} {summary.development_snapshot_date} → "
        f"{tr('holdout')} {summary.holdout_snapshot_date}"
    )

    columns = st.columns(5)
    metric_card(
        columns[0],
        tr("Input samples"),
        summary.input_count,
        accent="neutral",
    )
    metric_card(
        columns[1],
        tr("Overlap removed"),
        summary.overlap_removed,
        accent="neutral",
    )
    metric_card(
        columns[2],
        tr("Retained"),
        summary.retained_count,
        accent="neutral",
    )
    metric_card(
        columns[3],
        tr("Malicious"),
        summary.malicious_count,
        accent="neutral",
    )
    metric_card(
        columns[4],
        tr("Benign"),
        summary.benign_count,
        accent="neutral",
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
        display_frame[column] = display_frame[column].map(lambda value: f"{value:.2%}")
    display_frame["Threshold"] = display_frame["Threshold"].map(
        lambda value: f"{value:.6f}"
    )

    st.write(f"**{tr('Frozen operating points')}**")
    st.dataframe(
        translate_dataframe(display_frame),
        hide_index=True,
        width="stretch",
    )

    chart_frame = frame[["Operating point", "Recall", "False-positive rate"]].melt(
        id_vars="Operating point",
        var_name="Metric",
        value_name="Rate",
    )
    chart_frame["Operating point"] = chart_frame["Operating point"].map(tr)
    chart_frame["Metric"] = chart_frame["Metric"].map(tr)
    figure = px.bar(
        chart_frame,
        x="Operating point",
        y="Rate",
        color="Metric",
        barmode="group",
        title=tr("Final holdout recall vs false-positive rate"),
        labels={"Rate": tr("Rate"), "Operating point": tr("Operating point"), "Metric": tr("Metric")},
        color_discrete_map={
            tr("Recall"): palette()["cyan"],
            tr("False-positive rate"): palette()["muted"],
        },
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
                lambda value: "n/a" if pd.isna(value) else f"{value:.2%}"
            )
        with st.expander(tr("Source-aware holdout diagnostics"), expanded=False):
            st.write(f"**{tr('Source-aware holdout diagnostics')}**")
            st.dataframe(
                translate_dataframe(source_frame),
                hide_index=True,
                width="stretch",
            )
            st.caption(
                tr(
                    "Recall is shown for malicious samples and false-positive rate "
                    "for benign samples. A source with no samples for one class shows "
                    "n/a for that class-specific rate."
                )
            )

    st.info(
        tr(
            "Dataset precision is not the same as operational positive predictive "
            "value (PPV). Real DNS traffic may contain a much lower malicious "
            "base rate, so even a small false-positive rate can produce many "
            "benign alerts."
        )
    )
    if report.malicious_first_seen_after is not None:
        st.caption(
            tr(
                "Protocol: development-domain overlap removed; malicious "
                "first_seen must be strictly after the displayed cutoff."
            )
            + f" {report.malicious_first_seen_after}"
        )
    else:
        st.caption(
            tr(
                "Protocol: fresh-collection disjoint holdout with development "
                "overlap removed; no malicious first_seen filter was applied."
            )
        )
