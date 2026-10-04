from __future__ import annotations

import pandas as pd
import streamlit as st

from .dashboard import connection_finding_rows
from .i18n import tr, translate_dataframe
from .reporting import build_connection_report
from .runtime_analysis import RuntimeAnalysisResult


def render_connections(result: RuntimeAnalysisResult, *, public_mode: bool) -> None:
    st.caption(tr("Connection timing, duration and byte counts are review context. They do not prove malware or downloads."))
    st.caption(tr("Direction means originator to responder. Hostnames and inbound/outbound direction are not inferred."))
    if not result.connection_findings:
        st.info(tr("Upload a Zeek conn.log to inspect connection activity."))
        return
    include_ips = False
    if not public_mode:
        include_ips = st.checkbox(tr("Show connection endpoint IPs in this view and export"),
                                  value=False, key="connection_include_ips")
    reviews_only = st.checkbox(tr("Show only connection reviews"), value=True, key="connection_reviews_only")
    rows = connection_finding_rows(result.connection_findings, include_ips=include_ips)
    for row in rows:
        for key in ("Originator", "Responder"):
            if str(row[key]).startswith("Host "):
                row[key] = tr("Host {number}", number=str(row[key])[5:])
        for key in ("Evidence", "Coverage limits"):
            row[key] = "; ".join(tr(text) for text in str(row[key]).split("; "))
    visible = [r for r in rows if r["Queue priority"] == "Review"] if reviews_only else rows
    if visible:
        st.dataframe(translate_dataframe(pd.DataFrame(visible)), hide_index=True, width="stretch")
    else:
        st.info(tr("No connection groups currently require review."))
    st.download_button(tr("Download connection review JSON"),
                       data=build_connection_report(result, include_ips=include_ips),
                       file_name="threatfusion_connections.json", mime="application/json")
    st.caption(tr("Connection exports remain sensitive telemetry. Host aliases apply only to this report."))
