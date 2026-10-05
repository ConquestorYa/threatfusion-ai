"""Shared investigation view for uploaded and collector connection summaries."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from .i18n import tr, translate_dataframe
from .ui_review_guidance import render_connection_guidance


def render_timeline(rows: list[dict[str, object]], timelines: dict, *, key: str, revision: str | None = None):
    if not rows:
        return
    st.subheader(tr("Connection investigation"))
    by_group = {row["Group"]: row for row in rows if "Group" in row}
    if not by_group:
        st.info(tr("Restart the collector to generate connection timelines."))
        return
    if revision is not None and st.session_state.get(f"{key}_timeline_revision") != revision:
        # Report-local aliases/group numbers can change on the next snapshot.
        # Never silently carry the previous selection into a different report.
        st.session_state[f"{key}_timeline_revision"] = revision
        st.session_state.pop(f"{key}_timeline_group", None)
    if st.session_state.get(f"{key}_timeline_group") not in by_group:
        st.session_state.pop(f"{key}_timeline_group", None)
    def host(value):
        return tr("Host {number}", number=str(value)[5:]) if str(value).startswith("Host ") else value
    # Resolve translations in the script context, not a later widget callback.
    labels = {group: f"{group}: {host(row.get('Originator', ''))} → {host(row.get('Responder', ''))}:{row.get('Responder port')} / {row.get('Protocol')}"
              for group, row in by_group.items()}
    group = st.selectbox(tr("Select a connection group"), options=list(by_group),
                         format_func=lambda group: labels.get(group, str(group)), key=f"{key}_timeline_group")
    render_connection_guidance(by_group[group])
    timeline = next((item for item in timelines.get("groups", []) if item["group"] == group), None)
    if timeline is None:
        st.info(tr("No timeline for this group. Timelines cover the first 200 groups, with Review groups first; the full findings remain available."))
        return
    st.caption(tr("UTC buckets: {seconds} seconds. Counts, bytes and states are assigned to connection start time, not transfer time.", seconds=timeline["bucket_seconds"]))
    st.caption(tr("A zero bucket means no retained connection starts, not proof that the network was idle. States describe Zeek observations, not malware verdicts."))
    if timeline["untimed_connections"]:
        st.warning(tr("{count} connections have missing or ambiguous time and are excluded from the chart.", count=timeline["untimed_connections"]))
    buckets = timeline["buckets"]
    if not buckets:
        st.info(tr("No comparable timestamps for this connection group."))
        return
    chart = pd.DataFrame({tr("UTC bucket start"): pd.to_datetime([b["start_utc"] for b in buckets], utc=True),
                          tr("Connection starts"): [b["connections"] for b in buckets]})
    st.line_chart(chart, x=tr("UTC bucket start"), y=tr("Connection starts"))
    details = [{"UTC bucket start": b["start_utc"], "Connection starts": b["connections"],
                "Known originator bytes": b["originator_bytes"],
                "Unknown originator byte counts": b["originator_bytes_unknown"],
                "Known responder bytes": b["responder_bytes"],
                "Unknown responder byte counts": b["responder_bytes_unknown"],
                "Zeek states": "; ".join(f"{state}: {count}" for state, count in b["states"].items())}
               for b in buckets]
    st.dataframe(translate_dataframe(pd.DataFrame(details)), hide_index=True, width="stretch")
    st.caption(tr("Known bytes are partial sums when byte counts are missing. Duplicate and conflicting UIDs are excluded as in the connection findings."))
