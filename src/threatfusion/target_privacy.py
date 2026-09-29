"""Stable per-run labels for targets in portable output and local history."""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class SafeTarget:
    target_type: str
    label: str
    domain: str | None


def safe_target_labels(targets: Iterable[str]) -> dict[str, SafeTarget]:
    values = set(targets)
    ip_targets: list[str] = []
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        ip_targets.append(value)

    labels = {
        value: SafeTarget("domain", value, value)
        for value in values
        if value not in ip_targets
    }
    for index, value in enumerate(sorted(ip_targets), start=1):
        labels[value] = SafeTarget("ip", f"IP target {index}", None)
    return labels
