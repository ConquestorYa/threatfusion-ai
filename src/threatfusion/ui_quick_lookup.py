"""Streamlit presentation for passive single URL/domain lookup."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
import streamlit as st

from .dashboard import format_timestamp, reason_label
from .i18n import tr, translate_dataframe
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
        tr("normalized IP {value}", value=result.normalized_ip)
        if result.normalized_ip is not None
        else tr("normalized domain {value}", value=result.normalized_domain)
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
        f'<div class="tf-signal-sub">{safe_text(tr("CTI + ML decision boundary"))}</div></div>'
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


def _ml_signal_presentation(result: QuickLookupResult) -> tuple[str, str, str, int, str]:
    """Return a simple model-signal grade without presenting the score as probability."""
    if result.ml_score is None:
        return (
            "neutral",
            tr("Not scored"),
            tr("No model score was available"),
            0,
            tr("Model signal unavailable"),
        )

    score = max(0, min(100, round(float(result.ml_score) * 100)))

    if result.ml_tier == "high":
        return (
            "danger",
            tr("High"),
            tr("Strong model signal"),
            score,
            tr("This score crossed the model's high review threshold."),
        )
    if result.ml_tier == "medium":
        return (
            "review",
            tr("Medium"),
            tr("Moderate model signal"),
            score,
            tr("This score crossed the model's medium review threshold."),
        )
    if result.ml_tier == "low":
        return (
            "low",
            tr("Low"),
            tr("Weak model signal"),
            score,
            tr("This score crossed the model's low review threshold."),
        )

    return (
        "safe",
        tr("Minimal"),
        tr("Below review threshold"),
        score,
        tr("The model did not raise this target for review."),
    )


def _render_ml_risk_card(result: QuickLookupResult) -> None:
    tone, level, subtitle, score, explanation = _ml_signal_presentation(result)
    score_text = "—" if result.ml_score is None else f"{score}"
    width = 0 if result.ml_score is None else score

    st.markdown(
        f'<div class="tf-ml-risk-card tf-ml-risk-card--{tone}">'
        '<div class="tf-ml-risk-head">'
        '<div>'
        f'<div class="tf-ml-risk-kicker">{safe_text(tr("ML risk signal"))}</div>'
        f'<div class="tf-ml-risk-level">{safe_text(level)}</div>'
        '</div>'
        f'<div class="tf-ml-risk-score"><strong>{safe_text(score_text)}</strong><span>/100</span></div>'
        '</div>'
        f'<div class="tf-ml-risk-subtitle">{safe_text(subtitle)}</div>'
        '<div class="tf-ml-risk-track" aria-hidden="true">'
        f'<span class="tf-ml-risk-fill" style="width:{width}%"></span>'
        '</div>'
        '<div class="tf-ml-risk-scale">'
        f'<span>{safe_text(tr("Minimal"))}</span>'
        f'<span>{safe_text(tr("Low"))}</span>'
        f'<span>{safe_text(tr("Medium"))}</span>'
        f'<span>{safe_text(tr("High"))}</span>'
        '</div>'
        f'<div class="tf-ml-risk-explanation">{safe_text(explanation)}</div>'
        f'<div class="tf-ml-risk-note">{safe_text(tr("Model signal strength · not a probability"))}</div>'
        '</div>',
        unsafe_allow_html=True,
    )

def _render_signal_console(result: QuickLookupResult) -> None:
    visual = _presentation_for(result.verdict.value)
    cti_count = len(result.evidence)
    cti_tone = "danger" if cti_count else "safe"
    cti_value = (
        (tr("{count} CTI match", count=cti_count) if cti_count == 1 else tr("{count} CTI matches", count=cti_count))
        if cti_count
        else tr("No CTI match")
    )

    if result.ml_score is None:
        ml_tone = "info"
        ml_value = tr("Not scored")
        ml_sub = tr("No model score was available")
    elif result.ml_tier == "high":
        ml_tone = "danger"
        ml_value = tr("High ML tier")
        ml_sub = tr("Model score {score}", score=f"{result.ml_score:.4f}")
    elif result.ml_tier in {"medium", "low"}:
        ml_tone = "review"
        ml_value = tr("{tier} ML tier", tier=tr(result.ml_tier.title()))
        ml_sub = tr("Model score {score}", score=f"{result.ml_score:.4f}")
    else:
        ml_tone = "safe"
        ml_value = tr("Below threshold")
        ml_sub = tr("Model score {score}", score=f"{result.ml_score:.4f}")

    lexical = result.lexical_context
    shape_bits = [
        tr("depth {value}", value=lexical.subdomain_depth),
        (
            tr("numeric {value}", value=f"{lexical.numeric_character_ratio:.2f}")
            if lexical.numeric_character_ratio is not None
            else tr("numeric n/a")
        ),
        (
            tr("entropy {value}", value=f"{lexical.hostname_entropy:.2f}")
            if lexical.hostname_entropy is not None
            else tr("entropy n/a")
        ),
    ]

    st.markdown(
        '<div class="tf-signal-console">'
        f'<div class="tf-signal-node tf-signal-node--{cti_tone}">'
        '<span class="tf-signal-node-arrow" aria-hidden="true">→</span>'
        f'<div class="tf-signal-node-label">{safe_text(tr("Local threat intelligence"))}</div>'
        f'<div class="tf-signal-node-value">{safe_text(cti_value)}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(tr("ThreatFox · URLhaus · PhishTank · SGB cache"))}</div>'
        '</div>'
        f'<div class="tf-signal-node tf-signal-node--{ml_tone}">'
        '<span class="tf-signal-node-arrow" aria-hidden="true">→</span>'
        f'<div class="tf-signal-node-label">{safe_text(tr("Host model"))}</div>'
        f'<div class="tf-signal-node-value">{safe_text(ml_value)}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(ml_sub)}</div>'
        '</div>'
        '<div class="tf-signal-node tf-signal-node--info">'
        '<span class="tf-signal-node-arrow" aria-hidden="true">→</span>'
        f'<div class="tf-signal-node-label">{safe_text(tr("Host shape context"))}</div>'
        f'<div class="tf-signal-node-value">{safe_text(result.normalized_domain)}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(" · ".join(shape_bits))}</div>'
        '</div>'
        f'<div class="tf-signal-node tf-signal-node--{visual.signal_tone}">'
        f'<div class="tf-signal-node-label">{safe_text(tr("Decision"))}</div>'
        f'<div class="tf-signal-node-value">{safe_text(tr(visual.kicker))}</div>'
        f'<div class="tf-signal-node-sub">{safe_text(tr(visual.title))}</div>'
        '</div>'
        '</div>'
        '<div class="tf-console-caption">'
        f'{safe_text(tr("The diagram shows which local evidence paths contributed context. It does not represent a probability or live website scan."))}'
        '</div>',
        unsafe_allow_html=True,
    )


def _render_graphic_overview(result: QuickLookupResult) -> None:
    section_label(tr("Signal overview"))
    ml_col, flow_col = st.columns([1, 1.65], vertical_alignment="center")
    with ml_col:
        _render_ml_risk_card(result)
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
            copy = tr(
                "Review the matching source records below. Exact URL/domain/IP "
                "evidence is stronger than hostname-only context."
            )
        else:
            tone = "review"
            icon = "!"
            heading = tr("Threat intelligence context found")
            copy = tr(
                "Context was found in the local CTI cache. Review its scope "
                "before deciding how to treat the destination."
            )
    else:
        tone = "safe"
        icon = "✓"
        heading = tr("No CTI match found")
        copy = tr(
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
        f'<div class="tf-lookup-empty-step-num">01 · {safe_text(tr("Input"))}</div>'
        f'<div class="tf-lookup-empty-step-title">{safe_text(tr("URL, domain or IP"))}</div>'
        f'<div class="tf-lookup-empty-step-copy">{safe_text(tr("Paste one URL, domain or IP into the lookup field above."))}</div>'
        '</div>'
        '<div class="tf-lookup-empty-arrow" aria-hidden="true">→</div>'
        '<div class="tf-lookup-empty-step">'
        f'<div class="tf-lookup-empty-step-num">02 · {safe_text(tr("Signals"))}</div>'
        '<div class="tf-lookup-empty-step-title">CTI + ML</div>'
        f'<div class="tf-lookup-empty-step-copy">{safe_text(tr("Check the local ThreatFox, URLhaus, PhishTank and SGB cache plus the domain model."))}</div>'
        '</div>'
        '<div class="tf-lookup-empty-arrow" aria-hidden="true">→</div>'
        '<div class="tf-lookup-empty-step">'
        f'<div class="tf-lookup-empty-step-num">03 · {safe_text(tr("Result"))}</div>'
        f'<div class="tf-lookup-empty-step-title">{safe_text(tr("Clear verdict"))}</div>'
        f'<div class="tf-lookup-empty-step-copy">{safe_text(tr("See a color-coded result, evidence path and model signal overview."))}</div>'
        '</div>'
        '</div>'
        f'<div class="tf-lookup-empty-note">{safe_text(tr("Passive analysis only · the destination is never opened or resolved."))}</div>',
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
        tr(
            "Quick lookup is passive: ThreatFusion does not open the URL, resolve "
            "the domain, or download content. A low-risk result means no current "
            "signal was raised by the available local CTI cache and model; it is "
            "not a guarantee that a destination is safe."
        )
    )
