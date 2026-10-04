from __future__ import annotations

import pandas as pd
import streamlit as st

from .dashboard import device_finding_rows
from .i18n import tr, translate_dataframe
from .reporting import build_device_report
from .runtime_analysis import RuntimeAnalysisResult


def render_device_triage(result: RuntimeAnalysisResult, *, public_mode: bool) -> None:
    st.caption(tr(
        "Client/domain observations are assessed separately. Queue priority is not proof of compromise."
    ))
    st.caption(tr(
        "DNS shows queries, not confirmed connections or downloads. A client address may belong to a resolver or NAT."
    ))
    include_ips = False
    if not public_mode:
        include_ips = st.checkbox(
            tr("Show observed client IPs in this view and device export"),
            value=False, key="device_triage_include_ips",
        )
    include_observe = st.checkbox(
        tr("Include observations without review priority"),
        value=False, key="device_triage_include_observe",
    )
    rows = device_finding_rows(result.device_findings, include_client_ips=include_ips)
    for row in rows:
        if str(row["Device"]).startswith("Device "):
            row["Device"] = tr("Device {number}", number=str(row["Device"])[7:])
        row["Coverage limits"] = "; ".join(
            tr(text) for text in str(row["Coverage limits"]).split("; ")
        )
    visible = rows if include_observe else [r for r in rows if r["Queue priority"] != "Observe"]
    if visible:
        st.dataframe(
            translate_dataframe(pd.DataFrame(visible)),
            hide_index=True, width="stretch",
        )
    else:
        st.info(tr("No device observations currently require review."))
    st.caption(tr(
        "Sustained periodic DNS enters Review after at least 20 distinct, fully timestamped observations over 30 minutes. Legitimate updates may also qualify."
    ))
    st.download_button(
        tr("Download device triage JSON"),
        data=build_device_report(result, include_client_ips=include_ips),
        file_name="threatfusion_device_triage.json", mime="application/json",
        key="device_triage_download",
    )
    st.caption(tr(
        "Device aliases apply only to this report. Domains and timestamps remain sensitive telemetry; keep this export local."
    ))
