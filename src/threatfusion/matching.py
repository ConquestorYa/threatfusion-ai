from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .dns import DNSEvent, response_ip_addresses
from .models import IOCRecord, IOCType
from .normalization import normalize_ioc_value

MAX_IOC_MATCHES = 250_000
MAX_MATCH_LOOKUPS = 1_000_000


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
    matched_ip: str | None = None


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
    ipv6_networks = defaultdict(list)

    for order, indicator in enumerate(indicators):
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
                network = ipaddress.IPv6Network(normalized)
                ipv6_networks[(network.prefixlen, int(network.network_address))].append((order, indicator))

    matches: list[DNSIOCMatch] = []
    prefixes = sorted({prefix for prefix, _ in ipv6_networks})
    network_cache = {}
    lookups = 0

    def budget(amount=1):
        nonlocal lookups
        lookups += amount
        if lookups > MAX_MATCH_LOOKUPS:
            raise ValueError("IOC matching exceeds its work budget; use a smaller telemetry window")

    def add(event, records, kind, matched_ip=None):
        if len(matches) + len(records) > MAX_IOC_MATCHES:
            raise ValueError("IOC evidence exceeds the 250000 match limit; use a smaller telemetry window")
        matches.extend(DNSIOCMatch(event, record, kind, matched_ip) for record in records)

    for event in events:
        budget()
        query_name = event.query_name.strip() if isinstance(event.query_name, str) else ""
        if query_name:
            normalized_query = normalize_ioc_value(query_name, IOCType.DOMAIN)
            if normalized_query:
                add(event, domain_index.get(normalized_query, []), "query_domain")
                add(event, url_hostname_index.get(normalized_query, []), "url_hostname")

        first = _normalized_event_ip(event)
        for normalized_ip in response_ip_addresses(event):
            budget()
            address = ipaddress.ip_address(normalized_ip)
            matched_ip = None if first and first[0] == normalized_ip else normalized_ip
            target_index = ipv4_index if address.version == 4 else ipv6_index
            add(event, target_index.get(normalized_ip, []), "response_ip", matched_ip)
            if address.version == 6:
                if normalized_ip not in network_cache:
                    budget(len(prefixes))
                    found = []
                    for prefix in prefixes:
                        key = (prefix, int(address) >> (128 - prefix) << (128 - prefix))
                        found.extend(ipv6_networks.get(key, ()))
                        if len(found) > MAX_IOC_MATCHES:
                            raise ValueError("IOC network evidence exceeds the safe match limit")
                    network_cache[normalized_ip] = [record for _, record in sorted(found, key=lambda pair: pair[0])]
                add(event, network_cache[normalized_ip], "response_ip_network", matched_ip)

    return matches
