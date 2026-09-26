import ipaddress
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .models import IOCType

_ASCII_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain_name(
    value: str,
    *,
    strict: bool = False,
) -> str:
    """Canonicalize a domain name, including Unicode/IDNA hostnames."""
    if not isinstance(value, str):
        raise TypeError("domain value must be a string")

    candidate = value.strip().removesuffix(".")
    if not candidate:
        return ""

    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        if strict:
            raise ValueError("domain contains invalid IDNA text") from error
        return candidate.casefold()

    if not strict:
        return normalized

    if len(normalized) > 253:
        raise ValueError("domain exceeds the maximum length")

    labels = normalized.split(".")
    if len(labels) < 2:
        raise ValueError("internet domain must contain at least two labels")
    if any(not _ASCII_DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("domain contains an invalid label")

    return normalized


def normalize_ioc_value(value: str, ioc_type: IOCType) -> str:
    """Normalize an IOC value according to its type."""
    stripped_value = value.strip()

    if ioc_type is IOCType.DOMAIN:
        return normalize_domain_name(stripped_value)

    if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
        return stripped_value.lower()

    if ioc_type is IOCType.IPV4:
        return str(ipaddress.IPv4Address(stripped_value))

    if ioc_type is IOCType.IPV6:
        return str(ipaddress.IPv6Address(stripped_value))

    if ioc_type is IOCType.IPV6_NETWORK:
        return str(ipaddress.IPv6Network(stripped_value, strict=False))

    return stripped_value



def normalize_url_for_lookup(value: str) -> tuple[str, str]:
    """Canonicalize an HTTP(S) URL and return (url, hostname)."""
    if not isinstance(value, str):
        raise TypeError("URL value must be a string")

    candidate = value.strip()
    if not candidate:
        raise ValueError("URL value must not be empty")
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

    domain = normalize_domain_name(parsed.hostname, strict=True)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid port") from error

    host = domain
    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    if port is not None and not default_port:
        host = f"{host}:{port}"

    normalized = urlunsplit(
        SplitResult(
            scheme=scheme,
            netloc=host,
            path=parsed.path or "/",
            query=parsed.query,
            fragment="",
        )
    )
    return normalized, domain
