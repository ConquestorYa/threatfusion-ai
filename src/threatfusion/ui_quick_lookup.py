"""Streamlit presentation for passive single URL/domain lookup."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from .dashboard import format_timestamp, reason_label
from .i18n import tr, translate_dataframe
from .quick_lookup import QuickLookupResult
from .ui_theme import apply_plotly_theme, metric_card, palette, safe_text, section_label


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
            "The submitted domain, IP, or exact URL matched known threat intelligence "
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
        "exact_ip": "Exact IP",
        "query_domain": "Exact domain",
        "url_hostname": "URL hostname context",
    }
    return tr(labels.get(value, value.replace("_", " ").title()))


def _ml_signal_label(result: QuickLookupResult) -> tuple[str, str]:
    if result.ml_score is None:
        return tr("Not scored"), tr("No ML score was available")
    if result.ml_tier:
        return tr(result.ml_tier.title()), tr("Score {score}", score=f"{result.ml_score:.4f}")
    return tr("Below threshold"), tr("Score {score}", score=f"{result.ml_score:.4f}")


def _cti_signal_label(result: QuickLookupResult) -> tuple[str, str]:
    count = len(result.evidence)
    if count == 0:
        return tr("No matches"), tr("Local CTI cache")
    match_text = tr("{count} match", count=count) if count == 1 else tr("{count} matches", count=count)
    return match_text, tr("Local CTI cache")


def _reason_text(reason: str) -> str:
    if reason == "exact_url_ioc_match":
        return tr("The exact submitted URL appears in the local CTI cache.")
    if reason == "exact_ip_ioc_match":
        return tr("The submitted IP address appears directly in the local CTI cache.")
    if reason == "public_ip_literal_url":
        return tr(
            "The URL connects directly to a public IP address instead of a domain. "
            "This is context only and is not proof of maliciousness."
        )
    if reason == "plaintext_http_transport":
        return tr(
            "The submitted URL uses HTTP, so traffic is not protected by HTTPS "
            "transport encryption."
        )
    return tr(reason_label(reason))


def _render_outcome_banner(result: QuickLookupResult) -> None:
    visual = _presentation_for(result.verdict.value)
    target = result.normalized_url or result.normalized_domain
    normalized_label = (
        f"normalized IP {result.normalized_ip}"
        if result.normalized_ip is not None
        else f"normalized domain {result.normalized_domain}"
    )
    input_label = f"{result.input_type} · {normalized_label}"
    visual_kicker = tr(visual.kicker)
    visual_title = tr(visual.title)
    visual_summary = tr(visual.summary)

    st.markdown(
        f'<section class="tf-lookup-result tf-lookup-result--{visual.css_class}" '
        f'aria-label="{safe_text(visual_kicker)} lookup result">'
        '<div class="tf-lookup-result-top">'
        '<div class="tf-lookup-result-copy">'
        f'<div class="tf-lookup-icon" aria-hidden="true">{safe_text(visual.icon)}</div>'
        '<div>'
        f'<div class="tf-lookup-kicker">{safe_text(visual_kicker)}</div>'
        f'<div class="tf-lookup-title">{safe_text(visual_title)}</div>'
        f'<div class="tf-lookup-summary">{safe_text(visual_summary)}</div>'
        '</div></div>'
        f'<div class="tf-lookup-target">{safe_text(target)}</div>'
        '</div>'
        '<div class="tf-lookup-meta">'
        f'<span><strong>{safe_text(tr("Input"))}:</strong> {safe_text(input_label)}</span>'
        f'<span><strong>{safe_text(tr("Method"))}:</strong> {safe_text(tr("passive lookup only"))}</span>'
        f'<span><strong>{safe_text(tr("Network requests"))}:</strong> {safe_text(tr("none"))}</span>'
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
        f'<div class="tf-signal-label">{safe_text(tr("Overall result"))}</div>'
        f'<div class="tf-signal-value">{safe_text(tr(visual.kicker))}</div>'
        '<div class="tf-signal-sub">CTI + ML decision boundary</div></div>'
        f'<div class="tf-signal tf-signal--{"danger" if result.evidence else "safe"}">'
        f'<div class="tf-signal-label">{safe_text(tr("Threat intelligence"))}</div>'
        f'<div class="tf-signal-value">{safe_text(cti_value)}</div>'
        f'<div class="tf-signal-sub">{safe_text(cti_sub)}</div></div>'
        f'<div class="tf-signal tf-signal--{visual.signal_tone}">'
        f'<div class="tf-signal-label">{safe_text(tr("ML signal"))}</div>'
        f'<div class="tf-signal-value">{safe_text(ml_value)}</div>'
        f'<div class="tf-signal-sub">{safe_text(ml_sub)}</div></div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _ml_score_figure(result: QuickLookupResult) -> go.Figure:
    """Render the model's 0-1 score without presenting it as a probability."""
    colors = palette()
    visual = _presentation_for(result.verdict.value)
    semantic_color = {
        "safe": colors["green"],
        "review": colors["yellow"],
        "danger": colors["red"],
    }.get(visual.signal_tone, colors["cyan"])

    score = float(result.ml_score or 0.0)
    figure = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={
                "valueformat": ".3f",
                "font": {"size": 30, "color": colors["text"]},
            },
            gauge={
                "axis": {
                    "range": [0, 1],
                    "tickvals": [0, 0.25, 0.5, 0.75, 1],
                    "ticktext": ["0", ".25", ".50", ".75", "1"],
                    "tickfont": {"size": 10, "color": colors["muted"]},
                },
                "bar": {"color": semantic_color, "thickness": 0.34},
                "bgcolor": colors["panel_alt"],
                "borderwidth": 0,
            },
            title={
                "text": (
                    "<b>ML model score</b><br>"
                    "<span style='font-size:11px'>Uncalibrated score · not probability</span>"
                ),
                "font": {"size": 14, "color": colors["muted"]},
            },
        )
    )
    return apply_plotly_theme(figure, height=250)


def _render_signal_console(result: QuickLookupResult) -> None:
    visual = _presentation_for(result.verdict.value)
    cti_count = len(result.evidence)
    cti_tone = "danger" if cti_count else "safe"
    cti_value = (
        f"{cti_count} CTI match" + ("" if cti_count == 1 else "es")
        if cti_count
        else "No CTI match"
    )

    if result.ml_score is None:
        ml_tone = "info"
        ml_value = "Not scored"
        ml_sub = "No model score was available"
    elif result.ml_tier == "high":
        ml_tone = "danger"
        ml_value = "High ML tier"
        ml_sub = f"Model score {result.ml_score:.4f}"
    elif result.ml_tier in {"medium", "low"}:
        ml_tone = "review"
        ml_value = f"{result.ml_tier.title()} ML tier"
        ml_sub = f"Model score {result.ml_score:.4f}"
    else:
        ml_tone = "safe"
        ml_value = "Below threshold"
        ml_sub = f"Model score {result.ml_score:.4f}"

    lexical = result.lexical_context
    shape_bits = [
        f"depth {lexical.subdomain_depth}",
        (
            f"numeric {lexical.numeric_character_ratio:.2f}"
            if lexical.numeric_character_ratio is not None
            else "numeric n/a"
        ),
        (
            f"entropy {lexical.hostname_entropy:.2f}"
            if lexical.hostname_entropy is not None
            else "entropy n/a"
        ),
    ]

    st.markdown(
        '<div class="tf-signal-console">'
        f'<div class="tf-signal-node tf-signal-node--{cti_tone}">'
        '<span class="tf-signal-node-arrow" aria-hidden="true">→</span>'
        '<div class="tf-signal-node-label">Local threat intelligence</div>'
        f'<div class="tf-signal-node-value">{safe_text(cti_value)}</div>'
        '<div class="tf-signal-node-sub">ThreatFox · URLhaus · PhishTank · SGB cache</div>'
        '</div>'
        f'<div class="tf-signal-node tf-signal-node--{ml_tone}">'
        '<span class="tf-signal-node-arrow" aria-hidden="true">→</span>'
        '<div class="tf-signal-node-label">Host model</div>'
        f'<div class="tf-signal-node-value">{safe_text(ml_value)}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(ml_sub)}</div>'
        '</div>'
        '<div class="tf-signal-node tf-signal-node--info">'
        '<span class="tf-signal-node-arrow" aria-hidden="true">→</span>'
        '<div class="tf-signal-node-label">Host shape context</div>'
        f'<div class="tf-signal-node-value">{safe_text(result.normalized_domain)}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(" · ".join(shape_bits))}</div>'
        '</div>'
        f'<div class="tf-signal-node tf-signal-node--{visual.signal_tone}">'
        '<div class="tf-signal-node-label">Decision</div>'
        f'<div class="tf-signal-node-value">{safe_text(visual.kicker)}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(visual.title)}</div>'
        '</div>'
        '</div>'
        '<div class="tf-console-caption">'
        'The diagram shows which local evidence paths contributed context. '
        'It does not represent a probability or live website scan.'
        '</div>',
        unsafe_allow_html=True,
    )


def _render_graphic_overview(result: QuickLookupResult) -> None:
    section_label(tr("Signal overview"))
    chart_col, flow_col = st.columns([1, 1.65], vertical_alignment="center")
    with chart_col:
        st.plotly_chart(
            _ml_score_figure(result),
            width="stretch",
            config={"displayModeBar": False},
        )
    with flow_col:
        _render_signal_console(result)


def _render_reasons(result: QuickLookupResult) -> None:
    section_label(tr("Why this result?"))
    reasons = [_reason_text(reason) for reason in result.reasons]
    if not reasons:
        reasons = [
            tr("No cached CTI match was found."),
            tr("The ML score did not cross a review threshold."),
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
            heading = tr("Known threat intelligence matched")
            copy = (
                "Review the matching source records below. Exact URL/domain/IP "
                "evidence is stronger than hostname-only context."
            )
        else:
            tone = "review"
            icon = "!"
            heading = tr("Threat intelligence context found")
            copy = (
                "Context was found in the local CTI cache. Review its scope "
                "before deciding how to treat the destination."
            )
    else:
        tone = "safe"
        icon = "✓"
        heading = tr("No CTI match found")
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


def render_quick_lookup_empty_state() -> None:
    st.markdown(
        '<div class="tf-lookup-empty-visual">'
        '<div class="tf-lookup-empty-step">'
        '<div class="tf-lookup-empty-step-num">01 · Input</div>'
        f'<div class="tf-lookup-empty-step-title">{safe_text(tr("URL, domain or IP"))}</div>'
        f'<div class="tf-lookup-empty-step-copy">{safe_text(tr("Paste one URL, domain or IP into the lookup field above."))}</div>'
        '</div>'
        '<div class="tf-lookup-empty-arrow" aria-hidden="true">→</div>'
        '<div class="tf-lookup-empty-step">'
        '<div class="tf-lookup-empty-step-num">02 · Signals</div>'
        '<div class="tf-lookup-empty-step-title">CTI + ML</div>'
        '<div class="tf-lookup-empty-step-copy">Check the local ThreatFox, URLhaus, PhishTank and SGB cache plus the domain model.</div>'
        '</div>'
        '<div class="tf-lookup-empty-arrow" aria-hidden="true">→</div>'
        '<div class="tf-lookup-empty-step">'
        '<div class="tf-lookup-empty-step-num">03 · Result</div>'
        '<div class="tf-lookup-empty-step-title">Clear verdict</div>'
        '<div class="tf-lookup-empty-step-copy">See a color-coded result, evidence path and model signal overview.</div>'
        '</div>'
        '</div>'
        '<div class="tf-lookup-empty-note">Passive analysis only · the destination is never opened or resolved.</div>',
        unsafe_allow_html=True,
    )


def render_quick_lookup_result(result: QuickLookupResult) -> None:
    if result.uses_plain_http:
        st.warning(
            tr(
                "HTTP link detected. This connection is not protected by HTTPS. "
                "Transport security alone does not determine whether a site is malicious."
            )
        )
    if result.uses_public_ip_literal:
        st.info(
            tr(
                "Direct public-IP URL detected. ThreatFusion treats this as contextual "
                "evidence only; the IP or URL must match CTI or other stronger signals "
                "to be classified as a known threat."
            )
        )

    _render_outcome_banner(result)
    _render_graphic_overview(result)
    _render_reasons(result)

    section_label(tr("Threat intelligence evidence"))
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
            translate_dataframe(pd.DataFrame(rows)),
            hide_index=True,
            width="stretch",
            column_config={
                "Indicator": st.column_config.TextColumn(width="large"),
            },
        )

    with st.expander(tr("Technical domain details"), expanded=False):
        st.caption(
            tr(
                "These are descriptive hostname-shape features. They are context, "
                "not proof that a domain is malicious."
            )
        )
        lexical = result.lexical_context
        shape_columns = st.columns(4)
        metric_card(
            shape_columns[0],
            tr("Labels"),
            lexical.label_count,
            accent="neutral",
        )
        metric_card(
            shape_columns[1],
            tr("Subdomain depth"),
            lexical.subdomain_depth,
            accent="neutral",
        )
        metric_card(
            shape_columns[2],
            tr("Numeric ratio"),
            (
                f"{lexical.numeric_character_ratio:.2f}"
                if lexical.numeric_character_ratio is not None
                else "N/A"
            ),
            accent="neutral",
        )
        metric_card(
            shape_columns[3],
            tr("Hostname entropy"),
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
