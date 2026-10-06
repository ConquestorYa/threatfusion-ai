"""Explicit local identity display; the mapping never enters shared reports."""

from __future__ import annotations

import copy
import json
from ipaddress import ip_address

from .collector_reports import read_private

IDENTITY_FILE = "collector-identities.json"
MAX_IDENTITY_BYTES = 16 * 1024 * 1024


def identity_payload(result, dns_identity, revision):
    hosts = sorted(
        {
            ip
            for f in result.connection_findings
            for ip in (f.originator_ip, f.responder_ip)
            if ip
        }
    )
    clients = sorted({client for client, _ in dns_identity if client})
    return {
        "schema_version": 1,
        "selection_revision": revision,
        "hosts": {f"Host {i:03d}": ip for i, ip in enumerate(hosts, 1)},
        "devices": {f"Device {i:03d}": ip for i, ip in enumerate(clients, 1)},
    }


def local_identity_view(root, payload):
    """Fail closed on stale generation, symlinks or non-private mapping files."""
    from .ui_collector import read_snapshot

    # Revalidate the directory and ensure the selected snapshot is still current.
    current = read_snapshot(root)
    revision = payload["collector"].get("selection_revision")
    if not revision or current["collector"].get("selection_revision") != revision:
        raise ValueError("Collector identity generation changed")
    try:
        identities = json.loads(read_private(root / IDENTITY_FILE, MAX_IDENTITY_BYTES))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Invalid collector identity mapping") from None
    if (
        not isinstance(identities, dict)
        or set(identities)
        != {"schema_version", "selection_revision", "hosts", "devices"}
        or identities["schema_version"] != 1
        or identities["selection_revision"] != revision
    ):
        raise ValueError("Collector identity generation changed")
    for namespace, prefix in (("hosts", "Host "), ("devices", "Device ")):
        mapping = identities[namespace]
        if not isinstance(mapping, dict) or len(mapping) > 200_000:
            raise ValueError("Invalid collector identity bounds")
        for alias, value in mapping.items():
            if (
                not isinstance(alias, str)
                or not alias.startswith(prefix)
                or not alias[len(prefix) :].isascii()
                or not alias[len(prefix) :].isdecimal()
                or not isinstance(value, str)
                or len(value) > 64
            ):
                raise ValueError("Invalid collector identity")
            ip_address(value)
    view = copy.deepcopy(payload)
    hosts = identities["hosts"]
    for row in view["findings"]:
        for field in ("Originator", "Responder"):
            if row[field] in hosts:
                row[field] = hosts[row[field]]
    for row in view.get("attempts", {}).get("findings", []):
        for field in ("Originator", "Responder"):
            if row.get(field) in hosts:
                row[field] = hosts[row[field]]
    for row in view.get("dns", {}).get("report", {}).get("findings", []):
        if row["Device"] in identities["devices"]:
            row["Device"] = identities["devices"][row["Device"]]
    return view
