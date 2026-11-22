"""Streamlit presentation for passive single URL/domain lookup."""

from __future__ import annotations

from dataclasses import dataclass

from .dashboard import reason_label
from .i18n import tr
from .quick_lookup import QuickLookupResult


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
            "Nothing in the available local CTI cache (or ML, when it is enabled) "
            "currently raises this target for review."
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
        "response_ip_network": "IPv6 network context",
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


def _ml_signal_presentation(result: QuickLookupResult) -> tuple[str, str, str, int, str]:
    """Return a simple model-signal grade without presenting the score as probability."""
    known_threat = (
        getattr(getattr(result, "verdict", None), "value", None) == "known_threat"
    )

    if result.ml_score is None:
        if known_threat:
            return (
                "neutral",
                tr("Context only"),
                tr("Final decision comes from CTI"),
                0,
                tr(
                    "Known threat intelligence matched this target. No model score was available, and the CTI verdict remains authoritative."
                ),
            )
        return (
            "neutral",
            tr("Not scored"),
            tr("No model score was available"),
            0,
            tr("Model signal unavailable"),
        )

    score = max(0, min(100, round(float(result.ml_score) * 100)))

    if known_threat:
        return (
            "neutral",
            tr("Context only"),
            tr("Final decision comes from CTI"),
            score,
            tr(
                "Known threat intelligence matched this target. The ML score is shown only as additional context and does not override the CTI verdict."
            ),
        )

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


_AGE_TONES = {"very_new": ("danger", "Very new site"), "new": ("review", "Young site"),
              "established": ("safe", "Established site")}


def _age_text(days: int) -> str:
    if days < 60:
        return tr("{count} days old", count=days)
    if days < 730:
        return tr("{count} months old", count=days // 30)
    return tr("{count} years old", count=days // 365)


