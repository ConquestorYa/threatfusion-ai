"""Streamlit presentation for passive single URL/domain lookup."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
import streamlit as st

from .dashboard import format_timestamp, reason_label
from .quick_lookup import QuickLookupResult
from .ui_theme import metric_card, safe_text, section_label


@dataclass(frozen=True)
class LookupPresentation:
    css_class: str
    icon: str
    kicker: str
    title: str
    summary: str
    signal_tone: str


_LOOKUP_PRESENTATIONS = {
    "low": LookupPresentation(
        css_class="safe",
        icon="✓",
        kicker="Low risk",
        title="No threat signal found",
        summary=(
            "Nothing in the available local CTI cache or ML thresholds currently "
            "raises this domain or URL for review."
        ),
        signal_tone="safe",
    ),
    "review": LookupPresentation(
        css_class="review",
        icon="!",
        kicker="Review recommended",
        title="Some signals need a closer look",
        summary=(
            "ThreatFusion found contextual CTI or an ML signal that is worth "
            "reviewing before you trust this destination."
        ),
        signal_tone="review",
    ),
    "high_risk": LookupPresentation(
        css_class="danger",
        icon="!",
        kicker="High risk",
        title="Elevated risk detected",
        summary=(
            "The domain crossed the high ML threshold. Treat the result as a "
            "strong warning and review the evidence before proceeding."
        ),
        signal_tone="danger",
    ),
    "known_threat": LookupPresentation(
        css_class="critical",
        icon="×",
        kicker="Known threat",
        title="Threat intelligence match found",
        summary=(
            "The submitted domain or exact URL matched known threat intelligence "
            "in the local cache."
        ),
        signal_tone="danger",
    ),
}


def _presentation_for(verdict: str) -> LookupPresentation:
    return _LOOKUP_PRESENTATIONS.get(
        verdict,
        LookupPresentation(
            css_class="review",
            icon="?",
            kicker="Unknown",
            title="Result needs review",
            summary="ThreatFusion could not map this lookup to a known result state.",
            signal_tone="review",
        ),
    )


def _match_type_label(value: str) -> str:
    labels = {
        "exact_url": "Exact URL",
        "query_domain": "Exact domain",
        "url_hostname": "URL hostname context",
    }
    return labels.get(value, value.replace("_", " ").title())


def _ml_signal_label(result: QuickLookupResult) -> tuple[str, str]:
    if result.ml_score is None:
        return "Not scored", "No ML score was available"
    if result.ml_tier:
        return result.ml_tier.title(), f"Score {result.ml_score:.4f}"
    return "Below threshold", f"Score {result.ml_score:.4f}"


def _cti_signal_label(result: QuickLookupResult) -> tuple[str, str]:
    count = len(result.evidence)
    if count == 0:
        return "No matches", "Local CTI cache"
    return f"{count} match" + ("" if count == 1 else "es"), "Local CTI cache"


def _reason_text(reason: str) -> str:
    if reason == "exact_url_ioc_match":
        return "The exact submitted URL appears in the local CTI cache."
    return reason_label(reason)


def _render_outcome_banner(result: QuickLookupResult) -> None:
    visual = _presentation_for(result.verdict.value)
    target = result.normalized_url or result.normalized_domain
    input_label = (
        f"{result.input_type} · normalized domain {result.normalized_domain}"
    )

    st.markdown(
        f'<section class="tf-lookup-result tf-lookup-result--{visual.css_class}" '
        f'aria-label="{safe_text(visual.kicker)} lookup result">'
        '<div class="tf-lookup-result-top">'
        '<div class="tf-lookup-result-copy">'
        f'<div class="tf-lookup-icon" aria-hidden="true">{safe_text(visual.icon)}</div>'
        '<div>'
        f'<div class="tf-lookup-kicker">{safe_text(visual.kicker)}</div>'
        f'<div class="tf-lookup-title">{safe_text(visual.title)}</div>'
        f'<div class="tf-lookup-summary">{safe_text(visual.summary)}</div>'
        '</div></div>'
        f'<div class="tf-lookup-target">{safe_text(target)}</div>'
        '</div>'
        '<div class="tf-lookup-meta">'
        f'<span><strong>Input:</strong> {safe_text(input_label)}</span>'
        '<span><strong>Method:</strong> passive lookup only</span>'
        '<span><strong>Network requests:</strong> none</span>'
        '</div></section>',
        unsafe_allow_html=True,
    )


def _render_signal_summary(result: QuickLookupResult) -> None:
    visual = _presentation_for(result.verdict.value)
    cti_value, cti_sub = _cti_signal_label(result)
    ml_value, ml_sub = _ml_signal_label(result)

    st.markdown(
        '<div class="tf-signal-grid">'
        f'<div class="tf-signal tf-signal--{visual.signal_tone}">'
        '<div class="tf-signal-label">Overall result</div>'
        f'<div class="tf-signal-value">{safe_text(visual.kicker)}</div>'
        '<div class="tf-signal-sub">CTI + ML decision boundary</div></div>'
        f'<div class="tf-signal tf-signal--{"danger" if result.evidence else "safe"}">'
        '<div class="tf-signal-label">Threat intelligence</div>'
        f'<div class="tf-signal-value">{safe_text(cti_value)}</div>'
        f'<div class="tf-signal-sub">{safe_text(cti_sub)}</div></div>'
        f'<div class="tf-signal tf-signal--{visual.signal_tone}">'
        '<div class="tf-signal-label">ML signal</div>'
        f'<div class="tf-signal-value">{safe_text(ml_value)}</div>'
        f'<div class="tf-signal-sub">{safe_text(ml_sub)}</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _render_reasons(result: QuickLookupResult) -> None:
    section_label("Why this result?")
    reasons = [_reason_text(reason) for reason in result.reasons]
    if not reasons:
        reasons = [
            "No cached CTI match was found.",
            "The ML score did not cross a review threshold.",
        ]

    rows = "".join(
        '<div class="tf-reason-row">'
        '<span class="tf-reason-icon" aria-hidden="true">›</span>'
        f'<span>{safe_text(reason)}</span></div>'
        for reason in reasons
    )
    st.markdown(f'<div class="tf-reason-list">{rows}</div>', unsafe_allow_html=True)


def _render_evidence_state(result: QuickLookupResult) -> None:
    if result.evidence:
        if result.verdict.value == "known_threat":
            tone = "danger"
            icon = "!"
            heading = "Known threat intelligence matched"
            copy = (
                "Review the matching source records below. Exact URL/domain "
                "evidence is stronger than hostname-only context."
            )
        else:
            tone = "review"
            icon = "!"
            heading = "Threat intelligence context found"
            copy = (
                "Context was found in the local CTI cache. Review its scope "
                "before deciding how to treat the destination."
            )
    else:
        tone = "safe"
        icon = "✓"
        heading = "No CTI match found"
        copy = (
            "The current local CTI cache contains no matching indicator. This "
            "does not guarantee that the destination is safe."
        )

    st.markdown(
        f'<div class="tf-evidence-state tf-evidence-state--{tone}">'
        f'<span class="tf-evidence-state-icon" aria-hidden="true">{safe_text(icon)}</span>'
        '<div>'
        f'<strong>{safe_text(heading)}</strong>'
        f'<span>{safe_text(copy)}</span>'
        '</div></div>',
        unsafe_allow_html=True,
    )


def render_quick_lookup_result(result: QuickLookupResult) -> None:
    _render_outcome_banner(result)
    _render_signal_summary(result)
    _render_reasons(result)

    section_label("Threat intelligence evidence")
    _render_evidence_state(result)

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

    with st.expander("Technical domain details", expanded=False):
        st.caption(
            "These are descriptive hostname-shape features. They are context, "
            "not proof that a domain is malicious."
        )
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
        "the domain, or download content. A low-risk result means no current "
        "signal was raised by the available local CTI cache and model; it is "
        "not a guarantee that a destination is safe."
    )
