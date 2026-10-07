"""Reject browser requests that reach the loopback app under a foreign name.

The local workspace binds to 127.0.0.1, but Streamlit accepts any Host header
and treats a matching Origin as same-origin. A DNS-rebinding page can therefore
point its own hostname at 127.0.0.1 and drive the local session. Browsers always
send the name they resolved, so an allowlist of loopback names blocks that path.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def host_header_name(value: str) -> str | None:
    """Return the lower-case hostname from a Host header, or None if invalid."""
    candidate = value.strip()
    if not candidate or any(character in candidate for character in "/\\@?# "):
        return None
    try:
        parsed = urlsplit("//" + candidate)
        hostname = parsed.hostname
        parsed.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        return None
    if not hostname:
        return None
    return hostname.removesuffix(".")


def allowed_hostnames(environment: Mapping[str, str]) -> frozenset[str]:
    extra = environment.get("THREATFUSION_ALLOWED_HOSTS", "")
    names = {name.strip().casefold() for name in extra.split(",") if name.strip()}
    return LOOPBACK_HOSTNAMES | names


def is_allowed_host(value: str | None, environment: Mapping[str, str]) -> bool:
    """Allow requests without a Host header; browsers always send one."""
    if value is None:
        return True
    hostname = host_header_name(value)
    return hostname is not None and hostname in allowed_hostnames(environment)
