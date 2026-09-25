from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .dns import DNSEvent
from .models import IOCRecord, IOCType
from .normalization import normalize_ioc_value


def _safe_normalize_ioc_value(value: str, ioc_type: IOCType) -> str | None:
    try:
        normalized = normalize_ioc_value(value, ioc_type)
    except ValueError:
        return None

    return normalized or None


@dataclass
class DNSIOCMatch:
    event: DNSEvent
    indicator: IOCRecord
    match_type: str


def _hostname_from_url(value: str) -> str | None:
    if not isinstance(value, str):
        return None

    try:
        parsed = urlsplit(value.strip())
        hostname = parsed.hostname
    except ValueError:
        return None

    if not hostname:
        return None

    return hostname


def _normalized_event_ip(event: DNSEvent) -> tuple[str, str] | None:
    if not event.response_ip:
        return None

    try:
        address = ipaddress.ip_address(event.response_ip)
    except ValueError:
        return None

    return str(address), "ipv4" if address.version == 4 else "ipv6"


def match_dns_events(
    events: Iterable[DNSEvent],
    indicators: Iterable[IOCRecord],
) -> list[DNSIOCMatch]:
    events = list(events)
    indicators = list(indicators)
    if not events or not indicators:
        return []

    domain_index: dict[str, list[IOCRecord]] = defaultdict(list)
    url_hostname_index: dict[str, list[IOCRecord]] = defaultdict(list)
    ipv4_index: dict[str, list[IOCRecord]] = defaultdict(list)
    ipv6_index: dict[str, list[IOCRecord]] = defaultdict(list)
    ipv6_networks: list[tuple[ipaddress.IPv6Network, IOCRecord]] = []

    for indicator in indicators:
        if indicator.ioc_type is IOCType.DOMAIN:
            normalized = _safe_normalize_ioc_value(indicator.value, IOCType.DOMAIN)
            if normalized:
                domain_index[normalized].append(indicator)
        elif indicator.ioc_type is IOCType.URL:
            hostname = _hostname_from_url(indicator.value)
            if hostname is not None:
                normalized = _safe_normalize_ioc_value(hostname, IOCType.DOMAIN)
                if normalized:
                    url_hostname_index[normalized].append(indicator)
        elif indicator.ioc_type is IOCType.IPV4:
            normalized = _safe_normalize_ioc_value(indicator.value, IOCType.IPV4)
            if normalized:
                ipv4_index[normalized].append(indicator)
        elif indicator.ioc_type is IOCType.IPV6:
            normalized = _safe_normalize_ioc_value(indicator.value, IOCType.IPV6)
            if normalized:
                ipv6_index[normalized].append(indicator)
        elif indicator.ioc_type is IOCType.IPV6_NETWORK:
            normalized = _safe_normalize_ioc_value(
                indicator.value,
                IOCType.IPV6_NETWORK,
            )
            if normalized:
                ipv6_networks.append(
                    (ipaddress.IPv6Network(normalized), indicator)
                )

    matches: list[DNSIOCMatch] = []

    for event in events:
        query_name = event.query_name.strip() if isinstance(event.query_name, str) else ""
        if query_name:
            normalized_query = normalize_ioc_value(query_name, IOCType.DOMAIN)
            if normalized_query:
                for indicator in domain_index.get(normalized_query, []):
                    matches.append(
                        DNSIOCMatch(
                            event=event,
                            indicator=indicator,
                            match_type="query_domain",
                        )
                    )
                for indicator in url_hostname_index.get(normalized_query, []):
                    matches.append(
                        DNSIOCMatch(
                            event=event,
                            indicator=indicator,
                            match_type="url_hostname",
                        )
                    )

        response_ip_data = _normalized_event_ip(event)
        if response_ip_data is None:
            continue

        normalized_ip, ip_version = response_ip_data
        target_index = ipv4_index if ip_version == "ipv4" else ipv6_index
        for indicator in target_index.get(normalized_ip, []):
            matches.append(
                DNSIOCMatch(
                    event=event,
                    indicator=indicator,
                    match_type="response_ip",
                )
            )

        if ip_version == "ipv6":
            address = ipaddress.IPv6Address(normalized_ip)
            for network, indicator in ipv6_networks:
                if address in network:
                    matches.append(
                        DNSIOCMatch(
                            event=event,
                            indicator=indicator,
                            match_type="response_ip_network",
                        )
                    )

    return matches
