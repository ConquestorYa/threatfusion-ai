"""Domain registration age from the registry's public RDAP service.

This is the only Quick Lookup feature that sends anything: it runs only when
the analyst presses its button and sends just the registrable domain (never the
full hostname, URL path or any telemetry) to the RDAP server that IANA lists
for the domain's top-level domain. Age is context, never a verdict: many new
sites are harmless and old domains can be compromised.
"""
from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from .http_safety import read_bounded_response_bytes
from .normalization import normalize_domain_name
from .popular_domains import registrable_domain

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
REQUEST_TIMEOUT_SECONDS = 10
MAX_BOOTSTRAP_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
BOOTSTRAP_TTL_SECONDS = 24 * 3600
VERY_NEW_DAYS = 30
NEW_DAYS = 180

_bootstrap_cache: tuple[float, dict[str, str]] | None = None
_new_session = requests.Session  # replaced in tests so nothing reaches a registry


@dataclass(frozen=True)
class DomainAge:
    domain: str
    status: str  # found | not_found | shared_platform | unsupported | error
    registered_at: datetime | None = None
    age_days: int | None = None
    registrar: str | None = None
    server: str | None = None
    platform: str | None = None  # shared_platform: the registered parent (e.g. a free hosting service)

    @property
    def tier(self) -> str | None:
        if self.age_days is None:
            return None
        return "very_new" if self.age_days <= VERY_NEW_DAYS else "new" if self.age_days <= NEW_DAYS else "established"


def rdap_domain(name: str, suffix_rules: frozenset[str] = frozenset()) -> str | None:
    """The registrable domain RDAP is asked about, or None when nothing may be sent."""
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    domain = normalize_domain_name(name)
    if not domain or "." not in domain:
        return None
    if suffix_rules:
        return registrable_domain(domain, suffix_rules)
    return ".".join(domain.split(".")[-2:])


def _https(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and bool(parts.hostname)


def _get(session: requests.Session, url: str, max_bytes: int, label: str) -> tuple[int, bytes]:
    response = session.get(url, timeout=REQUEST_TIMEOUT_SECONDS, stream=True,
                           headers={"Accept": "application/rdap+json, application/json"})
    try:
        # Registries may redirect between their own servers; never leave HTTPS.
        if not _https(response.url or url) or any(not _https(r.url) for r in response.history):
            raise ValueError(f"{label} redirected away from HTTPS")
        if response.status_code in (400, 404):
            # 404: not registered; 400: some registries refuse names below a registered domain.
            return 404, b""
        response.raise_for_status()
        return response.status_code, read_bounded_response_bytes(response, max_bytes=max_bytes, label=label)
    finally:
        response.close()


def _bootstrap(session: requests.Session, now: float) -> dict[str, str]:
    global _bootstrap_cache
    if _bootstrap_cache and now - _bootstrap_cache[0] < BOOTSTRAP_TTL_SECONDS:
        return _bootstrap_cache[1]
    _, body = _get(session, BOOTSTRAP_URL, MAX_BOOTSTRAP_BYTES, "IANA RDAP bootstrap")
    servers = {}
    for tlds, urls in json.loads(body)["services"]:
        base = next((u for u in urls if _https(u)), None)
        if base:
            for tld in tlds:
                servers[tld.casefold()] = base if base.endswith("/") else base + "/"
    if not servers:
        raise ValueError("IANA RDAP bootstrap is empty")
    _bootstrap_cache = (now, servers)
    return servers


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _registrar(payload: dict) -> str | None:
    for entity in payload.get("entities") or ():
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or ()):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) > 3 and item[0] == "fn" and isinstance(item[3], str):
                    return item[3].strip()[:120] or None
    return None


def parse_rdap_domain(domain: str, payload: dict, *, now: datetime, server: str | None = None) -> DomainAge:
    registered = None
    for event in payload.get("events") or ():
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            registered = _parse_time(event.get("eventDate"))
            break
    if registered is None:
        return DomainAge(domain, "found", registrar=_registrar(payload), server=server)
    age = max(0, (now - registered).days)
    return DomainAge(domain, "found", registered, age, _registrar(payload), server)


def lookup_domain_age(name: str, *, suffix_rules: frozenset[str] = frozenset(),
                      session: requests.Session | None = None, now: datetime | None = None) -> DomainAge:
    """RDAP lookup for the registrable domain of `name` (network; button only).

    Only when the registry does not know that domain, its parent domains are
    asked too (at most a few requests, each sending only a shorter name).
    """
    domain = rdap_domain(name, suffix_rules)
    if domain is None:
        return DomainAge(name, "unsupported")
    now = now or datetime.now(timezone.utc)
    session = session or _new_session()
    try:
        base = _bootstrap(session, time.monotonic()).get(domain.rsplit(".", 1)[-1])
        if base is None:
            return DomainAge(domain, "unsupported")
        status, body = _get(session, f"{base}domain/{domain}", MAX_RESPONSE_BYTES, "RDAP response")
        server = urlsplit(base).hostname
        if status == 404:
            # A name on a shared platform (Public Suffix List private section, e.g. a free
            # hosting service) has no registry entry of its own; its parent does.
            labels = domain.split(".")
            for index in range(1, len(labels) - 1):
                parent = ".".join(labels[index:])
                status, _ = _get(session, f"{base}domain/{parent}", MAX_RESPONSE_BYTES, "RDAP response")
                if status != 404:
                    return DomainAge(domain, "shared_platform", server=server, platform=parent)
            return DomainAge(domain, "not_found", server=server)
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError("RDAP response is not an object")
        return parse_rdap_domain(domain, payload, now=now, server=server)
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return DomainAge(domain, "error")
