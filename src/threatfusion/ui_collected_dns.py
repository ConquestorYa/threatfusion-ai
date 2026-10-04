"""Bilingual bounded DNS queue from the private collector snapshot."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from .i18n import tr, translate_dataframe


def render_collected_dns(block):
    if block is None:
        st.caption(tr("Restart the updated collector to include DNS logs."))
        return
    st.subheader(tr("Collected DNS observations"))
    if not block["coverage"]["retained_records"]:
        st.info(
            tr(
                "No completed DNS records in the retained window. This does not prove absence of DNS traffic."
            )
        )
        return
    coverage = block["coverage"]
    columns = st.columns(3)
    columns[0].metric(tr("Analyzed DNS transactions"), coverage["analyzed_events"])
    columns[1].metric(
        tr("DNS transport: UDP / TCP"),
        f"{coverage['transports']['udp']} / {coverage['transports']['tcp']}",
    )
    columns[2].metric(tr("Excluded DNS records"), coverage["excluded_records"])
    st.caption(
        tr(
            "DNS shows queries, not confirmed connections or downloads. A client address may belong to a resolver or NAT."
        )
    )
    st.caption(
        tr(
            "DNS device aliases and connection host aliases are independent within this snapshot."
        )
    )
    if coverage["excluded_records"]:
        st.warning(
            tr(
                "Conflicting DNS transaction records were excluded. Check source integrity before trusting coverage."
            )
        )
    if block["omitted_findings"]:
        st.warning(
            tr(
                "DNS snapshot contains at most 1,000 prioritized groups. Omitted groups: {count}.",
                count=block["omitted_findings"],
            )
        )
    observations = st.checkbox(
        tr("Include observations without review priority"),
        value=False,
        key="collector_dns_observe",
    )
    rows = [
        dict(row)
        for row in block["report"]["findings"]
        if observations or row["Queue priority"] != "Observe"
    ]
    for row in rows[:500]:
        if row["Device"].startswith("Device "):
            row["Device"] = tr("Device {number}", number=row["Device"][7:])
        row["Coverage limits"] = "; ".join(
            tr(text) for text in row["Coverage limits"].split("; ")
        )
    if rows:
        st.dataframe(
            translate_dataframe(pd.DataFrame(rows[:500])),
            hide_index=True,
            width="stretch",
        )
    else:
        st.info(tr("No device observations currently require review."))
    if len(rows) > 500:
        st.caption(
            tr(
                "Showing the first 500 DNS groups. Download includes all snapshot groups, subject to the 1,000-group cap."
            )
        )
    st.caption(
        tr(
            "Sustained periodic DNS enters Review after at least 20 distinct, fully timestamped observations over 30 minutes. Legitimate updates may also qualify."
        )
    )
