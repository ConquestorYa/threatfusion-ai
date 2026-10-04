"""Shared bounded TCP-attempt review queue for uploads and collector snapshots."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from .i18n import tr, translate_dataframe


def render_attempts(payload):
    if not payload or not (
        payload.get("eligible_records") or payload.get("excluded_tcp_records")
    ):
        return
    st.subheader(tr("TCP attempt reviews"))
    st.caption(
        tr(
            "These patterns can come from inventory scans, blocked services or outages. Review observed behavior before deciding its cause."
        )
    )
    st.caption(
        tr(
            "Sliding window: 5 minutes; at least 20 failed ports/hosts, or 30 repeated failures with at least 90% failures. Expected declarations do not hide this queue."
        )
    )
    if payload["excluded_tcp_records"]:
        st.warning(
            tr(
                "{count} TCP records lack comparable evidence. Retry ratios require complete source-window coverage; observed port/host diversity can still appear with coverage limits.",
                count=payload["excluded_tcp_records"],
            )
        )
    if payload["omitted_findings"]:
        st.warning(
            tr(
                "{count} additional attempt reviews exceed the 500-finding limit.",
                count=payload["omitted_findings"],
            )
        )
    rows = [dict(row) for row in payload["findings"]]
    for row in rows:
        for field in ("Originator", "Responder"):
            value = str(row[field])
            row[field] = (
                tr("Host {number}", number=value[5:])
                if value.startswith("Host ")
                else tr(value)
            )
        row["Pattern"] = tr(row["Pattern"])
    if rows:
        st.dataframe(
            translate_dataframe(pd.DataFrame(rows)), hide_index=True, width="stretch"
        )
    else:
        st.info(
            tr(
                "No TCP attempt pattern crossed these review gates. Check capture coverage before interpreting this result."
            )
        )
