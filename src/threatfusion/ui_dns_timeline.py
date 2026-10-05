"""Shared bounded device/domain query investigation for uploads and collection."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from .i18n import tr, translate_dataframe


def render_dns_timeline(rows, payload, *, key, revision):
    if not rows:
        return
    st.subheader(tr("Device DNS investigation"))
    if not payload or not all("Group" in row for row in rows):
        st.info(tr("Restart the updated collector to generate DNS timelines."))
        return
    revision_key = f"{key}_dns_revision"
    if st.session_state.get(revision_key) != revision:
        st.session_state[revision_key] = revision
        for suffix in ("device", "target"):
            st.session_state.pop(f"{key}_dns_{suffix}", None)
    devices = list(dict.fromkeys(row["Device"] for row in rows))
    device = st.selectbox(
        tr("Select an observed device"), devices, key=f"{key}_dns_device"
    )
    selected = {row["Group"]: row for row in rows if row["Device"] == device}
    target_key = f"{key}_dns_target"
    if st.session_state.get(target_key) not in selected:
        st.session_state.pop(target_key, None)
    group = st.selectbox(
        tr("Select a queried domain"),
        list(selected),
        # A previous widget state may be serialized during a device change.
        # Its old group can be outside this device's domain options.
        format_func=lambda number: str(selected.get(number, {}).get("Target", "")),
        key=target_key,
    )
    row = selected[group]
    st.caption(tr("Selected query evidence: {evidence}", evidence=row["Evidence"]))
    item = next((item for item in payload["groups"] if item["group"] == group), None)
    if item is None:
        st.info(
            tr(
                "No DNS timeline for this group. At most 200 eligible client/domain groups are charted; unknown clients and IP fallback targets are excluded."
            )
        )
        return
    st.caption(
        tr(
            "UTC query buckets: {seconds} seconds. Queries do not prove connections, downloads or execution.",
            seconds=item["bucket_seconds"],
        )
    )
    st.caption(
        tr(
            "Zero buckets mean no retained query records, not proof that DNS traffic was absent."
        )
    )
    if item["untimed_queries"]:
        st.warning(
            tr(
                "{count} queries have missing or ambiguous time and are excluded from the chart.",
                count=item["untimed_queries"],
            )
        )
    buckets = item["buckets"]
    if not buckets:
        st.info(tr("No comparable query timestamps for this group."))
        return
    chart = pd.DataFrame(
        {
            tr("UTC bucket start"): pd.to_datetime(
                [b["start_utc"] for b in buckets], utc=True
            ),
            tr("DNS queries"): [b["queries"] for b in buckets],
        }
    )
    st.bar_chart(chart, x=tr("UTC bucket start"), y=tr("DNS queries"))
    details = [
        {
            "UTC bucket start": b["start_utc"],
            "DNS queries": b["queries"],
            "DNS response categories": "; ".join(
                f"{name}: {count}" for name, count in b["responses"].items()
            ),
        }
        for b in buckets
    ]
    st.dataframe(
        translate_dataframe(pd.DataFrame(details)), hide_index=True, width="stretch"
    )
