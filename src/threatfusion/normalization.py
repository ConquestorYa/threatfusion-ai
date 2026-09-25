import ipaddress
import re

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
