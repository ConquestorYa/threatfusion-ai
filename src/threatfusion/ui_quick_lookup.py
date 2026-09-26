"""Streamlit presentation for passive single URL/domain lookup."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from .dashboard import format_timestamp, reason_label, verdict_label
from .quick_lookup import QuickLookupResult
from .ui_theme import metric_card, section_label, verdict_badge


def _match_type_label(value: str) -> str:
    labels = {
        "exact_url": "Exact URL",
        "query_domain": "Exact domain",
        "url_hostname": "URL hostname context",
    }
    return labels.get(value, value.replace("_", " ").title())


def render_quick_lookup_result(result: QuickLookupResult) -> None:
    verdict = verdict_label(result.verdict.value)

    st.markdown("### Lookup result")
    head_left, head_right = st.columns([3, 1])
    with head_left:
        st.code(result.normalized_url or result.normalized_domain, language="text")
        st.caption(
            f"{result.input_type} input · normalized domain: {result.normalized_domain}"
        )
    with head_right:
        st.markdown(verdict_badge(verdict), unsafe_allow_html=True)

    columns = st.columns(4)
    metric_card(columns[0], "Verdict", verdict, accent="neutral")
    metric_card(
        columns[1],
        "ML score",
        f"{result.ml_score:.4f}" if result.ml_score is not None else "Not scored",
        accent="neutral",
    )
    metric_card(
        columns[2],
        "ML tier",
        result.ml_tier.title() if result.ml_tier else "Below threshold",
        accent="neutral",
    )
    metric_card(
        columns[3],
        "CTI matches",
        len(result.evidence),
        accent="neutral",
    )

    section_label("Why this verdict?")
    if result.reasons:
        for reason in result.reasons:
            if reason == "exact_url_ioc_match":
                label = "Exact URL appears in the local CTI cache"
            else:
                label = reason_label(reason)
            st.markdown(f"- {label}")
    else:
        st.caption("No cached CTI or ML threshold signal raised this lookup.")

    section_label("Threat intelligence evidence")
    if result.evidence:
        rows = [
            {
                "Source": item.source,
                "Match": _match_type_label(item.match_type),
                "IOC type": item.ioc_type.upper(),
                "Indicator": item.indicator_value,
                "Threat type": item.threat_type or "",
                "Confidence": item.confidence,
                "First seen": (
                    format_timestamp(item.first_seen.isoformat())
                    if item.first_seen is not None
                    else ""
                ),
                "Last seen": (
                    format_timestamp(item.last_seen.isoformat())
                    if item.last_seen is not None
                    else ""
                ),
                "Tags": ", ".join(item.tags),
            }
            for item in result.evidence
        ]
        st.dataframe(
            pd.DataFrame(rows),
            hide_index=True,
            width="stretch",
            column_config={
                "Indicator": st.column_config.TextColumn(width="large"),
            },
        )
    else:
        st.info("No matching indicator was found in the local CTI cache.")

    section_label("Domain shape context")
    lexical = result.lexical_context
    shape_columns = st.columns(4)
    metric_card(
        shape_columns[0],
        "Labels",
        lexical.label_count,
        accent="neutral",
    )
    metric_card(
        shape_columns[1],
        "Subdomain depth",
        lexical.subdomain_depth,
        accent="neutral",
    )
    metric_card(
        shape_columns[2],
        "Numeric ratio",
        (
            f"{lexical.numeric_character_ratio:.2f}"
            if lexical.numeric_character_ratio is not None
            else "N/A"
        ),
        accent="neutral",
    )
    metric_card(
        shape_columns[3],
        "Hostname entropy",
        (
            f"{lexical.hostname_entropy:.2f}"
            if lexical.hostname_entropy is not None
            else "N/A"
        ),
        accent="neutral",
    )

    st.caption(
        "Quick lookup is passive: ThreatFusion does not open the URL, resolve "
        "the domain, or download content. DNS behavior signals such as NXDOMAIN "
        "ratio, churn, periodicity, query volume, and client count require "
        "telemetry and are not inferred from a single lookup."
    )
