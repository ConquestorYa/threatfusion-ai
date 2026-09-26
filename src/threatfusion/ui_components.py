"""Reusable UI panels. All filtering here affects presentation only."""

from __future__ import annotations

from collections.abc import Sequence

import pandas as pd
import streamlit as st

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
        '<div class="tf-steps" aria-label="Analysis workflow">'
        "<span><strong>01</strong> Choose source</span>"
        "<span><strong>02</strong> Upload telemetry</span>"
        "<span><strong>03</strong> Analyze &amp; triage</span></div>",
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
            "Updated just now"
            if hours < 0.1
            else (
                f"Updated {round(hours * 60)}m ago"
                if hours < 1
                else f"Updated {hours:g}h ago"
                if hours < 48
                else f"Updated {hours / 24:.0f}d ago"
            )
        )
    except ValueError:
        updated = "Update time unavailable"
    count = row.get("Records")
    count_text = (
        f"{int(count):,} active indicators"
        if count is not None
        else "No cached indicators"
    )
    return (
        '<div class="tf-source"><div class="tf-source-heading">'
        f'<span class="tf-source-name">{safe_text(row["Source"])}</span>'
        f'<span class="tf-tone-{tone}">{safe_text(status)}</span></div>'
        f'<div class="tf-source-count">{safe_text(count_text)}</div>'
        f'<div class="tf-source-age">{safe_text(updated)}</div></div>'
    )


def render_source_status(row: dict[str, object]) -> None:
    st.sidebar.markdown(source_status_html(row), unsafe_allow_html=True)
    with st.sidebar.expander(f"{row['Source']} details", expanded=False):
        st.caption("Last refresh (UTC)")
        st.text(str(row.get("Refreshed at") or "Unavailable"))
        st.caption(f"Freshness threshold: {row.get('Stale after', 'Unavailable')}")
        st.caption(f"Inactive history: {row.get('Inactive history', 0):,}")
        if row["Status"] == "Not cached":
            st.caption("Refresh this source to enable its known-IOC matching.")


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
            "No domain findings",
            "This analysis did not produce any domain assessments.",
        )
        return
    search_col, verdict_col, source_col = st.columns([2, 1, 1])
    query = search_col.text_input(
        "Search domains",
        key=f"{key}_search",
        placeholder="Domain or part of a hostname",
    )
    verdict = verdict_col.selectbox(
        "Verdict", ["All", *VERDICT_ORDER], key=f"{key}_verdict"
    )
    sources = sorted(
        {
            part.strip()
            for row in rows
            for part in str(row.get("Known CTI sources", "")).split(",")
            if part.strip()
        }
    )
    source = source_col.selectbox("CTI source", ["All", *sources], key=f"{key}_source")
    filtered = filter_findings(rows, query=query, verdict=verdict, source=source)
    st.caption(
        f"{len(filtered):,} of {len(rows):,} domains · ordered by verdict priority"
    )
    if not filtered:
        st.info("No domains match these filters. Clear the search or choose All.")
        return
    frame = pd.DataFrame(filtered)
    columns = ["Domain", "Verdict", "ML tier", "DNS events", "Known CTI sources"]
    st.dataframe(
        frame[columns],
        hide_index=True,
        width="stretch",
        height=min(420, 38 + len(filtered) * 35),
        column_config={"Domain": st.column_config.TextColumn(width="large")},
    )
    with st.expander("All aggregate fields", expanded=False):
        st.dataframe(
            frame,
            hide_index=True,
            width="stretch",
            column_config={"ML score": st.column_config.NumberColumn(format="%.4f")},
        )
        st.caption(
            "ML scores are uncalibrated decision scores, not malware probabilities."
        )
