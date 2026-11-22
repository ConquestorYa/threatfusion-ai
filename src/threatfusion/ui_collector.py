"""Read the private atomic collector snapshot without accessing its raw DB."""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path

from .connection_timeline import validate_timeline_report
from .connection_attempts import validate_attempt_report
from .dns_collection import validate_dns_snapshot
from .collector_health import validate_collector_health
from .collector_reports import validate_projection

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024


def read_snapshot(root: Path):
    info = root.lstat()
    if (not root.is_absolute() or root.is_symlink() or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("Snapshot requires a private directory")
    fd = os.open(root / "connections.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        info = os.fstat(file.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077 or info.st_size > MAX_SNAPSHOT_BYTES):
            raise ValueError("Snapshot requires a bounded private file")
        raw = file.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot is too large")
    try:
        payload = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("Invalid collector snapshot") from None
    if (not isinstance(payload, dict) or payload.get("schema_version") != 2
        or not isinstance(payload.get("privacy"), dict)
        or not isinstance(payload.get("collector"), dict)
        or payload.get("privacy", {}).get("endpoint_ips_included") is not False
        or not isinstance(payload.get("findings"), list) or len(payload["findings"]) > 100_000
        or payload.get("collector", {}).get("policy") not in ("closed-zeek-collector-v1", "closed-zeek-collector-v2")):
        raise ValueError("Unsupported collector snapshot")
    status = payload["collector"]
    if not isinstance(status.get("counts"), dict) or type(status.get("cti_indicators")) is not int:
        raise ValueError("Invalid collector status")
    if not isinstance(status.get("updated_at"), str):
        raise ValueError("Invalid collector timestamp")
    timestamp = datetime.fromisoformat(status["updated_at"])
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Collector snapshot requires aware time")
    for key in ("retained_records", "review_groups", "rejected_files"):
        value = status["counts"].get(key)
        if type(value) is not int or not 0 <= value <= 100_000:
            raise ValueError("Invalid collector counts")
    required = {"Originator", "Responder", "Queue priority", "CTI match", "Declared expected",
                "Evidence", "Coverage limits", "Analyst context", "Context reason"}
    if any(not isinstance(row, dict) or not required.issubset(row) for row in payload["findings"]):
        raise ValueError("Invalid collected findings")
    if "timelines" in payload:
        validate_timeline_report(payload["timelines"], payload["findings"])
    if "attempts" in payload:
        validate_attempt_report(payload["attempts"])
    if status["policy"] == "closed-zeek-collector-v2" and "dns" not in payload:
        raise ValueError("Missing collected DNS coverage")
    if "dns" in payload:
        validate_dns_snapshot(payload["dns"])
        for key in ("retained_total_records", "retained_dns_records", "analyzed_dns_events", "dns_review_groups", "dns_omitted_groups"):
            value = status["counts"].get(key)
            if type(value) is not int or not 0 <= value <= 100_000:
                raise ValueError("Invalid collected DNS counts")
        coverage = payload["dns"]["coverage"]
        if (status["counts"]["retained_total_records"] != status["counts"]["retained_records"] + coverage["retained_records"]
            or status["counts"]["retained_dns_records"] != coverage["retained_records"]
            or status["counts"]["analyzed_dns_events"] != coverage["analyzed_events"]
            or status["counts"]["dns_omitted_groups"] != payload["dns"]["omitted_findings"]
            or status["counts"]["dns_review_groups"] != sum(row["Queue priority"] != "Observe" for row in payload["dns"]["report"]["findings"])):
            raise ValueError("Inconsistent collected DNS counts")
    validate_collector_health(status)
    validate_projection(payload)
    return payload


COLLECTOR_GUIDE = """**What it is for:** Quick lookup checks one address you already suspect. This page works the other way round: it watches your network's Zeek logs by itself and answers *which device talked to which destination, and which of those deserve a look*.

**Where the data comes from:** Zeek, a network monitor you run separately, writes `conn.log` (who connected to whom, on which port, for how long, with how many bytes) and `dns.log` (which names were looked up). ThreatFusion does not capture traffic itself. The `threatfusion-ai collect` command reads every completed log in the folder you gave it every 10 seconds and keeps the last 24 hours.

**What it does with it:**
1. Groups connections by device, destination and port.
2. Compares each destination with your local CTI cache of known malicious addresses.
3. Looks for behavior that often deserves attention: connections repeating at steady intervals (typical of malware check-ins, but also of updaters), very long two-way sessions and repeated failed connection attempts.
4. Lists groups that need a look as **Review**; everything else stays visible as **Observe**.

**How to read it:** Start at the top of the table; each row says why it was raised. A raised row is a reason to check, not proof of an infection; normal software can look the same. Activity you know is normal can be declared as expected and hidden."""


def _local_view(state_dir, payload):
    """Real IPs on this screen (the user's own machine); downloads keep aliases. None if unavailable."""
    from .collector_identity import local_identity_view
    try:
        return local_identity_view(state_dir, payload)
    except (OSError, ValueError, TypeError, KeyError):
        return None


