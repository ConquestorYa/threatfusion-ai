import ipaddress

from .models import IOCType


def normalize_ioc_value(value: str, ioc_type: IOCType) -> str:
    """Normalize an IOC value according to its type."""
    stripped_value = value.strip()

    if ioc_type is IOCType.DOMAIN:
        return stripped_value.lower().removesuffix(".")

    if ioc_type in {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}:
        return stripped_value.lower()

    if ioc_type is IOCType.IPV4:
        return str(ipaddress.IPv4Address(stripped_value))

    if ioc_type is IOCType.IPV6:
        return str(ipaddress.IPv6Address(stripped_value))

    return stripped_value