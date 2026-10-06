"""Report-local aliases for literal IP targets, never reversible identifiers."""

from ipaddress import ip_address


def target_type(value: str) -> str:
    try:
        return f"ipv{ip_address(value).version}"
    except ValueError:
        return "domain"


def target_aliases(values):
    targets = sorted({value for value in values if target_type(value) != "domain"})
    return {value: f"IP target {index:03d}" for index, value in enumerate(targets, 1)}
