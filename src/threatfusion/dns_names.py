"""Local DNS name context for addresses and names; no network activity."""
from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

from .dns import DNSEvent, response_ip_addresses

MAX_NAMES = 3
# An address answered for very many names (a shared CDN edge) says nothing
# about any one of them and would make the comparison quadratic.
MAX_NAMES_PER_SHARED_ADDRESS = 50
# Names that never leave the local network: mDNS/DNS-SD, reverse lookups and
# special-use local zones (RFC 6762, RFC 8375, RFC 6761 section 6.3).
_LOCAL_SUFFIXES = (".local", ".arpa", ".localhost", ".internal", ".lan", ".home")


def is_local_name(name: str) -> bool:
    value = name.strip().casefold().rstrip(".")
    return bool(value) and ("." not in value or value.endswith(_LOCAL_SUFFIXES))


def _top(counter: Counter) -> tuple[str, ...]:
    return tuple(name for name, _ in sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:MAX_NAMES])


def names_by_address(events: Iterable[DNSEvent]) -> dict[str, tuple[str, ...]]:
    """Most frequent query names whose answers contained each address."""
    counts: dict[str, Counter] = defaultdict(Counter)
    for event in events:
        name = event.query_name.strip().casefold().rstrip(".")
        for address in response_ip_addresses(event):
            counts[address][name] += 1
    return {address: _top(counter) for address, counter in counts.items()}


def names_sharing_addresses(events: Iterable[DNSEvent]) -> dict[str, tuple[str, ...]]:
    """Other names answered with any of the same addresses (e.g. a CNAME's origin)."""
    events = list(events)
    by_address = defaultdict(Counter)
    addresses_by_name = defaultdict(set)
    for event in events:
        name = event.query_name.strip().casefold().rstrip(".")
        for address in response_ip_addresses(event):
            by_address[address][name] += 1
            addresses_by_name[name].add(address)
    shared = {}
    for name, addresses in addresses_by_name.items():
        others = Counter()
        for address in addresses:
            if len(by_address[address]) > MAX_NAMES_PER_SHARED_ADDRESS:
                continue
            for other, count in by_address[address].items():
                if other != name:
                    others[other] += count
        shared[name] = _top(others)
    return shared
