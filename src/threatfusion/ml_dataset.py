from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import IOCRecord, IOCType
from .normalization import normalize_ioc_value


@dataclass(frozen=True)
class DomainSample:
    domain: str
    label: int
    source: str



_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_valid_internet_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False

    labels = domain.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return False

    return all(_DOMAIN_LABEL.fullmatch(label) is not None for label in labels)

def normalize_domain_candidate(value: str) -> str | None:
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    if not candidate:
        return None

    normalized = normalize_ioc_value(candidate, IOCType.DOMAIN)
    if not normalized:
        return None

    if any(ch.isspace() for ch in candidate):
        return None

    if any(token in candidate for token in ("/", "@", ":")):
        return None

    if not _is_valid_internet_domain(normalized):
        return None

    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return None

    return normalized


def _hostname_from_url(url_value: str) -> str | None:
    if not isinstance(url_value, str):
        return None

    try:
        parsed = urlsplit(url_value.strip())
        hostname = parsed.hostname
    except ValueError:
        return None

    if not hostname:
        return None

    return hostname


def extract_malicious_domains(indicators: Iterable[IOCRecord]) -> list[DomainSample]:
    """Extract malicious domain samples from IOC records.

    Domain-level deduplication matters for later ML evaluation because the same
    observed domain must not appear under conflicting labels in the dataset.
    """
    samples: list[DomainSample] = []

    for indicator in indicators:
        if indicator.ioc_type is IOCType.DOMAIN:
            normalized = normalize_domain_candidate(indicator.value)
            if normalized is not None:
                samples.append(
                    DomainSample(domain=normalized, label=1, source=indicator.source)
                )
        elif indicator.ioc_type is IOCType.URL:
            hostname = _hostname_from_url(indicator.value)
            if hostname is None:
                continue

            normalized = normalize_domain_candidate(hostname)
            if normalized is not None:
                samples.append(
                    DomainSample(domain=normalized, label=1, source=indicator.source)
                )

    return samples


def build_benign_samples(
    domains: Iterable[str],
    source: str = "Tranco",
) -> list[DomainSample]:
    """Create benign domain samples from caller-supplied domain strings.

    This function accepts already-loaded benign domains and does not fetch any
    external dataset. The caller is responsible for dataset acquisition.
    """
    samples: list[DomainSample] = []
    seen: set[str] = set()

    for value in domains:
        normalized = normalize_domain_candidate(value)
        if normalized is None or normalized in seen:
            continue

        seen.add(normalized)
        samples.append(DomainSample(domain=normalized, label=0, source=source))

    return samples


def build_domain_dataset(
    malicious_samples: Iterable[DomainSample],
    benign_samples: Iterable[DomainSample],
) -> list[DomainSample]:
    """Construct a deterministic labeled domain dataset.

    Domain-level deduplication is required to avoid the same normalized domain
    appearing once as benign and once as malicious, which would leak label
    information across train/test evaluation.
    """
    malicious_by_domain: dict[str, DomainSample] = {}
    benign_by_domain: dict[str, DomainSample] = {}

    for sample in malicious_samples:
        if not isinstance(sample, DomainSample):
            continue
        normalized = normalize_domain_candidate(sample.domain)
        if normalized is None:
            continue
        malicious_by_domain.setdefault(
            normalized,
            DomainSample(domain=normalized, label=1, source=sample.source),
        )

    for sample in benign_samples:
        if not isinstance(sample, DomainSample):
            continue
        normalized = normalize_domain_candidate(sample.domain)
        if normalized is None:
            continue
        benign_by_domain.setdefault(
            normalized,
            DomainSample(domain=normalized, label=0, source=sample.source),
        )

    return [
        *malicious_by_domain.values(),
        *(
            sample
            for domain, sample in benign_by_domain.items()
            if domain not in malicious_by_domain
        ),
    ]
