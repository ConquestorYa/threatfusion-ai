"""Passive single URL/domain lookup using the existing local CTI and ML assets."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .cti_cache import lookup_ioc_records
from .dns import DNSEvent
from .dns_behavior import DomainBehavior, aggregate_dns_behavior
from .hybrid_assessment import HybridVerdict
from .matching import DNSIOCMatch, match_dns_events
from .ml_artifact import TrainedMLArtifact, predict_domain_scores
from .models import IOCRecord, IOCType
from .normalization import normalize_domain_name, normalize_url_for_lookup


@dataclass(frozen=True)
class QuickLookupEvidence:
    source: str
    match_type: str
    ioc_type: str
    indicator_value: str
    threat_type: str | None
    confidence: float | None
    first_seen: datetime | None
    last_seen: datetime | None
    tags: tuple[str, ...]


@dataclass(frozen=True)
class QuickLookupResult:
    raw_input: str
    input_type: str
    normalized_domain: str
    normalized_url: str | None
    uses_plain_http: bool
    verdict: HybridVerdict
    ml_score: float | None
    ml_tier: str | None
    evidence: tuple[QuickLookupEvidence, ...]
    lexical_context: DomainBehavior
    reasons: tuple[str, ...]


def _parse_lookup_input(value: str) -> tuple[str, str, str | None]:
    candidate = value.strip()
    if not candidate:
        raise ValueError("URL or domain is required")

    looks_like_url = (
        "://" in candidate
        or "/" in candidate
        or "?" in candidate
        or "#" in candidate
    )
    if looks_like_url:
        normalized_url, domain = normalize_url_for_lookup(candidate)
        return "URL", domain, normalized_url

    domain = normalize_domain_name(candidate, strict=True)
    return "Domain", domain, None


def _normalize_indicator_url(value: str) -> str | None:
    try:
        normalized, _ = normalize_url_for_lookup(value)
    except (TypeError, ValueError):
        return None
    return normalized


def _ml_tier(artifact: TrainedMLArtifact, score: float | None) -> str | None:
    if score is None:
        return None
    if score >= artifact.thresholds.high_confidence:
        return "high"
    if score >= artifact.thresholds.medium_confidence:
        return "medium"
    if score >= artifact.thresholds.low_confidence:
        return "low"
    return None


def _evidence_from_match(match: DNSIOCMatch) -> QuickLookupEvidence:
    indicator = match.indicator
    return QuickLookupEvidence(
        source=indicator.source,
        match_type=match.match_type,
        ioc_type=indicator.ioc_type.value,
        indicator_value=indicator.value,
        threat_type=indicator.threat_type,
        confidence=indicator.confidence,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        tags=tuple(indicator.tags),
    )


def analyze_quick_lookup(
    value: str,
    indicators: list[IOCRecord] | tuple[IOCRecord, ...],
    artifact: TrainedMLArtifact,
) -> QuickLookupResult:
    """Analyze one inert URL/domain without DNS resolution or HTTP requests."""
    input_type, domain, normalized_url = _parse_lookup_input(value)
    indicator_list = list(indicators)

    event = DNSEvent(query_name=domain)
    matches = match_dns_events([event], indicator_list)

    exact_url_indicators: list[IOCRecord] = []
    if normalized_url is not None:
        for indicator in indicator_list:
            if indicator.ioc_type is not IOCType.URL:
                continue
            if _normalize_indicator_url(indicator.value) == normalized_url:
                exact_url_indicators.append(indicator)

    exact_url_ids = {id(indicator) for indicator in exact_url_indicators}
    evidence = [
        _evidence_from_match(match)
        for match in matches
        if not (
            match.match_type == "url_hostname"
            and id(match.indicator) in exact_url_ids
        )
    ]
    evidence.extend(
        QuickLookupEvidence(
            source=indicator.source,
            match_type="exact_url",
            ioc_type=indicator.ioc_type.value,
            indicator_value=indicator.value,
            threat_type=indicator.threat_type,
            confidence=indicator.confidence,
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen,
            tags=tuple(indicator.tags),
        )
        for indicator in exact_url_indicators
    )

    scores = predict_domain_scores(artifact, [domain])
    score = scores.get(domain)
    tier = _ml_tier(artifact, score)

    lexical = aggregate_dns_behavior([event])[0]
    match_types = {item.match_type for item in evidence}

    uses_plain_http = bool(
        normalized_url is not None and normalized_url.startswith("http://")
    )

    reasons: list[str] = []
    if uses_plain_http:
        reasons.append("plaintext_http_transport")
    if "exact_url" in match_types:
        reasons.append("exact_url_ioc_match")
    if "query_domain" in match_types:
        reasons.append("known_ioc_match")
    if "url_hostname" in match_types:
        reasons.append("url_hostname_ioc_context")
    if tier is not None:
        reasons.append(f"ml_{tier}_confidence")
    if (
        lexical.numeric_character_ratio is not None
        and lexical.numeric_character_ratio >= 0.3
    ):
        reasons.append("numeric_heavy_hostname")
    if lexical.random_like_hostname:
        reasons.append("random_like_hostname")

    if {"exact_url", "query_domain"} & match_types:
        verdict = HybridVerdict.KNOWN_THREAT
    elif tier == "high":
        verdict = HybridVerdict.HIGH_RISK
    elif "url_hostname" in match_types or tier in {"medium", "low"}:
        verdict = HybridVerdict.REVIEW
    else:
        verdict = HybridVerdict.LOW

    return QuickLookupResult(
        raw_input=value,
        input_type=input_type,
        normalized_domain=domain,
        normalized_url=normalized_url,
        uses_plain_http=uses_plain_http,
        verdict=verdict,
        ml_score=score,
        ml_tier=tier,
        evidence=tuple(evidence),
        lexical_context=lexical,
        reasons=tuple(reasons),
    )


def analyze_quick_lookup_from_cache(
    value: str,
    db_path,
    artifact: TrainedMLArtifact,
) -> QuickLookupResult:
    """Query only relevant indexed CTI rows, then run the normal lookup logic."""
    _, domain, normalized_url = _parse_lookup_input(value)
    indicators = lookup_ioc_records(
        db_path,
        domain=domain,
        normalized_url=normalized_url,
    )
    return analyze_quick_lookup(value, indicators, artifact)
