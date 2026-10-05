from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

import pandas as pd
import streamlit as st

from .dashboard import contextual_connection_rows
from .expected_connections import MAX_RULE_BYTES, parse_expected_connections
from .i18n import tr, translate_dataframe
from .reporting import build_connection_report
from .runtime_analysis import RuntimeAnalysisResult
from .connection_timeline import timeline_report
from .ui_connection_timeline import render_timeline
from .ui_connection_attempts import render_attempts
from .connection_attempts import attempt_report
from .ui_review_guidance import render_review_summary


def render_connections(result: RuntimeAnalysisResult, *, public_mode: bool) -> None:
    st.caption(tr("Connection timing, duration and byte counts are review context. They do not prove malware or downloads."))
    st.caption(tr("Direction means originator to responder. Hostnames and inbound/outbound direction are not inferred."))
    if not result.connection_findings:
        st.info(tr("Upload a Zeek conn.log to inspect connection activity."))
        return
    include_ips = False
    rules = ()
    if not public_mode:
        include_ips = st.checkbox(tr("Show connection endpoint IPs in this view and export"),
                                  value=False, key="connection_include_ips")
        st.caption(tr("Expected activity is your declaration, not verified software identity. Exact endpoints, traffic limits and expiry are required; CTI conflicts stay visible."))
        uploaded = st.file_uploader(tr("Optional expected-connection JSON (local session only)"),
                                    type=["json"], key="expected_connections_upload")
        if uploaded is not None:
            try:
                if uploaded.size > MAX_RULE_BYTES:
                    raise ValueError("Expected-connection file exceeds 64 KiB")
                rules = parse_expected_connections(uploaded.getvalue())
            except ValueError:
                st.error(tr("Invalid expected-connection file. No declarations applied."))
    now = datetime.now(timezone.utc)
    rows = contextual_connection_rows(result, rules, include_ips=include_ips, evaluated_at=now)
    render_review_summary(rows)
    reviews_only = st.checkbox(tr("Show only connection reviews"), value=True, key="connection_reviews_only")
    show_expected = st.checkbox(tr("Include declared expected activity"), value=False,
                                key="connection_show_expected") if rules else True
    visible = [r for r in rows if (not reviews_only or r["Queue priority"] == "Review" or r["CTI match"])
               and (show_expected or not r["Declared expected"] or r["CTI match"])]
    display = [dict(row) for row in visible[:500]]
    for row in display:
        for key in ("Originator", "Responder"):
            if str(row[key]).startswith("Host "):
                row[key] = tr("Host {number}", number=str(row[key])[5:])
        for key in ("Evidence", "Coverage limits", "Analyst context", "Context reason"):
            row[key] = "; ".join(tr(text) for text in str(row[key]).split("; "))
    if visible:
        st.dataframe(translate_dataframe(pd.DataFrame(display)), hide_index=True, width="stretch")
    else:
        st.info(tr("No unexplained connection reviews in this view." if rules else "No connection groups currently require review."))
    if len(visible) > 500:
        st.caption(tr("Showing the first 500 groups. The download contains all retained groups."))
    identity = [(f.originator_ip, f.responder_ip, f.responder_port, f.protocol) for f in result.connection_findings]
    revision = hashlib.sha256(json.dumps([identity, include_ips]).encode()).hexdigest()
    render_timeline(visible[:500], timeline_report(result.connection_timelines, len(rows)), key="connection", revision=revision)
    render_attempts(attempt_report(result.connection_attempts, result.connection_findings, include_ips=include_ips))
    st.download_button(tr("Download connection review JSON"),
                       data=build_connection_report(result, include_ips=include_ips, expected_rules=rules, evaluated_at=now),
                       file_name="threatfusion_connections.json", mime="application/json")
    st.caption(tr("Connection exports remain sensitive telemetry. Host aliases apply only to this report."))
