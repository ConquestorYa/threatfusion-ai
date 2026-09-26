"""Reusable UI panels. All filtering here affects presentation only."""

from __future__ import annotations

from collections.abc import Sequence

import pandas as pd
import streamlit as st

from .i18n import tr, translate_dataframe
from .ui_theme import safe_text

VERDICT_ORDER = ("Known Threat", "High Risk", "Review", "Low")


def empty_state(title: str, description: str) -> None:
    st.markdown(
        f'<div class="tf-empty"><strong>{safe_text(title)}</strong>'
        f"<p>{safe_text(description)}</p></div>",
        unsafe_allow_html=True,
    )


def intake_steps() -> None:
    st.markdown(
        f'<div class="tf-steps" aria-label="{safe_text(tr("Analysis workflow"))}">'
        '<div class="tf-step tf-step--active">'
        '<div class="tf-step-number">01</div>'
        f'<div><div class="tf-step-title">{safe_text(tr("Choose source"))}</div>'
        f'<div class="tf-step-sub">{safe_text(tr("Select the telemetry format you want to analyze."))}</div></div>'
        '</div>'
        '<div class="tf-step">'
        '<div class="tf-step-number">02</div>'
        f'<div><div class="tf-step-title">{safe_text(tr("Upload telemetry"))}</div>'
        f'<div class="tf-step-sub">{safe_text(tr("Provide DNS CSV, Zeek, Pi-hole or AdGuard data."))}</div></div>'
        '</div>'
        '<div class="tf-step">'
        '<div class="tf-step-number">03</div>'
        f'<div><div class="tf-step-title">{safe_text(tr("Analyze & triage"))}</div>'
        f'<div class="tf-step-sub">{safe_text(tr("Correlate CTI, ML and DNS behavior, then prioritize findings."))}</div></div>'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def source_status_html(row: dict[str, object]) -> str:
    """Render backend-provided freshness without recalculating its meaning."""
    status = str(row["Status"])
    tone = {"Fresh": "good", "Stale": "warn"}.get(status, "info")
    age = str(row.get("Age", "Unknown"))
    try:
        hours = float(age.removesuffix(" h"))
        updated = (
            tr("Updated just now")
            if hours < 0.1
            else (
                tr("Updated {minutes}m ago", minutes=round(hours * 60))
                if hours < 1
                else tr("Updated {hours}h ago", hours=f"{hours:g}")
                if hours < 48
                else tr("Updated {days}d ago", days=f"{hours / 24:.0f}")
            )
        )
    except ValueError:
        updated = tr("Update time unavailable")
    source = str(row["Source"])
    source_label = (
        tr("PhishTank · Verified & Online")
        if source == "PhishTank"
        else source
    )
    count = row.get("Records")
    if count is None:
        count_text = tr("No cached indicators")
    elif source == "PhishTank":
        count_text = tr(
            "{count} verified & online phishing URLs",
            count=f"{int(count):,}",
        )
    else:
        count_text = tr("{count} active indicators", count=f"{int(count):,}")
    return (
        '<div class="tf-source"><div class="tf-source-heading">'
        f'<span class="tf-source-name">{safe_text(source_label)}</span>'
        f'<span class="tf-tone-{tone}">{safe_text(tr(status))}</span></div>'
        f'<div class="tf-source-count">{safe_text(count_text)}</div>'
        f'<div class="tf-source-age">{safe_text(updated)}</div></div>'
    )


def render_source_status(row: dict[str, object]) -> None:
    st.sidebar.markdown(source_status_html(row), unsafe_allow_html=True)
    with st.sidebar.expander(
        tr("{source} details", source=row["Source"]),
        expanded=False,
    ):
        st.caption(tr("Last refresh (UTC)"))
        st.text(str(row.get("Refreshed at") or tr("Unavailable")))
        st.caption(
            tr(
                "Freshness threshold: {value}",
                value=row.get("Stale after", tr("Unavailable")),
            )
        )
        st.caption(
            tr(
                "Inactive history: {count}",
                count=f"{row.get('Inactive history', 0):,}",
            )
        )
        if str(row["Source"]) == "PhishTank":
            st.caption(
                tr(
                    "ThreatFusion uses PhishTank's verified-online public feed. "
                    "Unverified, invalid, or offline archive submissions are not included."
                )
            )
        if row["Status"] == "Not cached":
            st.caption(tr("Refresh this source to enable its known-IOC matching."))


def filter_findings(
    rows: Sequence[dict[str, object]],
    *,
    query: str = "",
    verdict: str = "All",
    source: str = "All",
) -> list[dict[str, object]]:
    """Literal domain search, preserving original risk order and row data."""
    needle = query.strip().casefold()
    return [
        row
        for row in rows
        if (not needle or needle in str(row["Domain"]).casefold())
        and (verdict == "All" or row["Verdict"] == verdict)
        and (
            source == "All"
            or source
            in {
                item.strip()
                for item in str(row.get("Known CTI sources", "")).split(",")
            }
        )
    ]


def render_findings_table(rows: list[dict[str, object]], *, key: str) -> None:
    if not rows:
        empty_state(
            tr("No domain findings"),
            tr("This analysis did not produce any domain assessments."),
        )
        return
    search_col, verdict_col, source_col = st.columns([2, 1, 1])
    query = search_col.text_input(
        tr("Search domains"),
        key=f"{key}_search",
        placeholder=tr("Domain or part of a hostname"),
    )
    verdict = verdict_col.selectbox(
        tr("Verdict"),
        ["All", *VERDICT_ORDER],
        key=f"{key}_verdict",
        format_func=tr,
    )
    sources = sorted(
        {
            part.strip()
            for row in rows
            for part in str(row.get("Known CTI sources", "")).split(",")
            if part.strip()
        }
    )
    source = source_col.selectbox(
        tr("CTI source"),
        ["All", *sources],
        key=f"{key}_source",
        format_func=tr,
    )
    filtered = filter_findings(rows, query=query, verdict=verdict, source=source)
    st.caption(
        tr(
            "{shown} of {total} domains · ordered by verdict priority",
            shown=f"{len(filtered):,}",
            total=f"{len(rows):,}",
        )
    )
    if not filtered:
        st.info(tr("No domains match these filters. Clear the search or choose All."))
        return
    frame = pd.DataFrame(filtered)
    columns = ["Domain", "Verdict", "ML tier", "DNS events", "Known CTI sources"]
    st.dataframe(
        translate_dataframe(frame[columns]),
        hide_index=True,
        width="stretch",
        height=min(420, 38 + len(filtered) * 35),
        column_config={"Domain": st.column_config.TextColumn(width="large")},
    )
    with st.expander(tr("All aggregate fields"), expanded=False):
        st.dataframe(
            translate_dataframe(frame),
            hide_index=True,
            width="stretch",
            column_config={"ML score": st.column_config.NumberColumn(format="%.4f")},
        )
        st.caption(
            tr("ML scores are uncalibrated decision scores, not malware probabilities.")
        )
