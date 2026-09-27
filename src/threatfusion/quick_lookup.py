"""Passive single URL/domain lookup using the existing local CTI and ML assets."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .cti_cache import lookup_ioc_records
from .dns import DNSEvent
from .dns_behavior import DomainBehavior, aggregate_dns_behavior
from .hybrid_assessment import HybridVerdict
from .matching import DNSIOCMatch, match_dns_events
from .ml_artifact import TrainedMLArtifact, predict_domain_scores
from .models import IOCRecord, IOCType
from .normalization import normalize_domain_name


MAX_LOOKUP_INPUT_CHARS = 4096


def _bounded_lookup_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("URL or domain must be a string")
    if len(value) > MAX_LOOKUP_INPUT_CHARS:
        raise ValueError(
            f"URL or domain exceeds the {MAX_LOOKUP_INPUT_CHARS}-character lookup limit"
        )
    candidate = value.strip()
    if not candidate:
        raise ValueError("URL or domain is required")
    return candidate


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
    normalized_ip: str | None
    uses_plain_http: bool
    uses_public_ip_literal: bool
    verdict: HybridVerdict
    ml_score: float | None
    ml_tier: str | None
    evidence: tuple[QuickLookupEvidence, ...]
    lexical_context: DomainBehavior
    reasons: tuple[str, ...]


def _normalize_host(value: str) -> tuple[str, str | None]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return normalize_domain_name(value, strict=True), None
    return str(address), str(address)


def _normalized_url_parts(value: str) -> tuple[str, str, str | None]:
    candidate = _bounded_lookup_text(value)

    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parsed = urlsplit(candidate)
    except ValueError as error:
        raise ValueError("URL could not be parsed") from error

    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"}:
        raise ValueError("only http and https URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not supported")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")

    host_value, normalized_ip = _normalize_host(parsed.hostname)

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid port") from error

    if normalized_ip is not None and ":" in normalized_ip:
        netloc = f"[{normalized_ip}]"
    else:
        netloc = host_value

    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    if port is not None and not default_port:
        netloc = f"{netloc}:{port}"

    normalized = urlunsplit(
        SplitResult(
            scheme=scheme,
            netloc=netloc,
            path=parsed.path or "/",
            query=parsed.query,
            fragment="",
        )
    )
    return normalized, host_value, normalized_ip


def _parse_lookup_input(
    value: str,
) -> tuple[str, str, str | None, str | None]:
    candidate = _bounded_lookup_text(value)

    looks_like_url = (
        "://" in candidate
        or "/" in candidate
        or "?" in candidate
        or "#" in candidate
    )
    if looks_like_url:
        normalized_url, host, normalized_ip = _normalized_url_parts(candidate)
        return "URL", host, normalized_url, normalized_ip

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        domain = normalize_domain_name(candidate, strict=True)
        return "Domain", domain, None, None

    normalized_ip = str(address)
    return f"IPv{address.version}", normalized_ip, None, normalized_ip


def _normalize_indicator_url(value: str) -> str | None:
    try:
        normalized, _, _ = _normalized_url_parts(value)
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


def analyze_quick_lookup_from_cache(
    value: str,
    db_path: Path,
    artifact: TrainedMLArtifact,
) -> QuickLookupResult:
    """Analyze one target using indexed CTI candidates instead of loading the full cache."""
    _, domain, normalized_url, normalized_ip = _parse_lookup_input(value)
    indicators = lookup_ioc_records(
        db_path,
        domain=domain,
        normalized_url=normalized_url,
        ip_address=normalized_ip,
    )
    return analyze_quick_lookup(value, indicators, artifact)


def analyze_quick_lookup(
    value: str,
    indicators: list[IOCRecord] | tuple[IOCRecord, ...],
    artifact: TrainedMLArtifact,
) -> QuickLookupResult:
    """Analyze one inert URL/domain without DNS resolution or HTTP requests."""
    input_type, domain, normalized_url, normalized_ip = _parse_lookup_input(value)
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

    exact_ip_indicators: list[IOCRecord] = []
    if normalized_ip is not None:
        expected_type = (
            IOCType.IPV4
            if ipaddress.ip_address(normalized_ip).version == 4
            else IOCType.IPV6
        )
        for indicator in indicator_list:
            if indicator.ioc_type is not expected_type:
                continue
            try:
                candidate_ip = str(ipaddress.ip_address(indicator.value.strip()))
            except ValueError:
                continue
            if candidate_ip == normalized_ip:
                exact_ip_indicators.append(indicator)

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
            match_type="exact_ip",
            ioc_type=indicator.ioc_type.value,
            indicator_value=indicator.value,
            threat_type=indicator.threat_type,
            confidence=indicator.confidence,
            first_seen=indicator.first_seen,
            last_seen=indicator.last_seen,
            tags=tuple(indicator.tags),
        )
        for indicator in exact_ip_indicators
    )
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

    if normalized_ip is None:
        scores = predict_domain_scores(artifact, [domain])
        score = scores.get(domain)
        tier = _ml_tier(artifact, score)
    else:
        score = None
        tier = None

    lexical = aggregate_dns_behavior([event])[0]
    match_types = {item.match_type for item in evidence}

    uses_plain_http = bool(
        normalized_url is not None and normalized_url.startswith("http://")
    )
    uses_public_ip_literal = False
    if normalized_url is not None and normalized_ip is not None:
        uses_public_ip_literal = ipaddress.ip_address(normalized_ip).is_global

    reasons: list[str] = []
    if uses_plain_http:
        reasons.append("plaintext_http_transport")
    if uses_public_ip_literal:
        reasons.append("public_ip_literal_url")
    if "exact_ip" in match_types:
        reasons.append("exact_ip_ioc_match")
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

    ml_high_corroborated = (
        "url_hostname" in match_types or lexical.random_like_hostname is True
    )
    if tier == "high" and not ml_high_corroborated:
        reasons.append("ml_high_uncorroborated")

    if {"exact_url", "exact_ip", "query_domain"} & match_types:
        verdict = HybridVerdict.KNOWN_THREAT
    elif tier == "high" and ml_high_corroborated:
        verdict = HybridVerdict.HIGH_RISK
    elif "url_hostname" in match_types or tier in {"high", "medium", "low"}:
        verdict = HybridVerdict.REVIEW
    else:
        verdict = HybridVerdict.LOW

    return QuickLookupResult(
        raw_input=value,
        input_type=input_type,
        normalized_domain=domain,
        normalized_url=normalized_url,
        normalized_ip=normalized_ip,
        uses_plain_http=uses_plain_http,
        uses_public_ip_literal=uses_public_ip_literal,
        verdict=verdict,
        ml_score=score,
        ml_tier=tier,
        evidence=tuple(evidence),
        lexical_context=lexical,
        reasons=tuple(reasons),
    )
