"""Private DNS transaction reconciliation and bounded, aliased snapshots."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from datetime import datetime

from .dns import DNSEvent
from .dns_zeek import ZeekDNSTransaction
from .reporting import build_device_report
from .runtime_analysis import analyze_dns_events

POLICY_ID = "closed-zeek-dns-collector-v1"
MAX_FINDINGS = 1000


def transaction_payload(record: ZeekDNSTransaction) -> str:
    payload = asdict(record)
    payload["answer_coverage"] = "all-ip-answers-v1"
    payload["event"]["timestamp"] = record.event.timestamp.isoformat()
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def build_dns_snapshot(
    payloads: list[str], indicators, *, generated_at: datetime, selection_identity=None
):
    by_key = {}
    conflicts = set()
    decoded = [json.loads(text) for text in payloads]
    superseded = set()
    representatives = {}
    for index, payload in enumerate(decoded):
        # A schema-2 and schema-3 representation of the very same source row
        # must not become two queries or a fictitious transaction conflict.
        identity = (payload["uid"], payload["transaction_id"], payload["event"]["timestamp"], payload.get("source_row_hash"))
        old_index = representatives.get(identity)
        if old_index is not None and identity[-1]:
            old = decoded[old_index]
            old_core = {k: v for k, v in old.items() if k != "answer_coverage"}
            new_core = {k: v for k, v in payload.items() if k != "answer_coverage"}
            old_core["event"] = {k: v for k, v in old["event"].items() if k != "response_ips"}
            new_core["event"] = {k: v for k, v in payload["event"].items() if k != "response_ips"}
            if old_core == new_core and old.get("answer_coverage") != payload.get("answer_coverage"):
                keep_new = payload.get("answer_coverage") == "all-ip-answers-v1"
                superseded.add(old_index if keep_new else index)
                if keep_new:
                    representatives[identity] = index
                continue
        representatives[identity] = index
    for index, payload in enumerate(decoded):
        if index in superseded:
            continue
        key = (payload["uid"], payload["transaction_id"], payload["event"]["timestamp"])
        if key in by_key and by_key[key] != payload:
            conflicts.add(key)
        by_key[key] = payload
    events = []
    transports = {"tcp": 0, "udp": 0}
    excluded = 0
    legacy = 0
    for index, payload in enumerate(decoded):
        if index in superseded:
            excluded += 1
            continue
        key = (payload["uid"], payload["transaction_id"], payload["event"]["timestamp"])
        if key in conflicts:
            excluded += 1
            continue
        values = payload["event"]
        values["timestamp"] = datetime.fromisoformat(values["timestamp"])
        events.append(DNSEvent(**values))
        legacy += payload.get("answer_coverage") != "all-ip-answers-v1"
        transports[payload["protocol"]] += 1
    result = analyze_dns_events(events, indicators, None)
    total = len(result.device_findings)
    if selection_identity is not None:
        # Caller-private mapping; never add raw clients to the snapshot envelope.
        selection_identity.extend(
            (f.client_ip, f.assessment.domain)
            for f in result.device_findings[:MAX_FINDINGS]
        )
    report = json.loads(
        build_device_report(
            replace(result, device_findings=result.device_findings[:MAX_FINDINGS]),
            generated_at=generated_at,
        )
    )
    return {
        "policy": POLICY_ID,
        "coverage": {
            "retained_records": len(payloads),
            "analyzed_events": len(events),
            "conflicting_transactions": len(conflicts),
            "excluded_records": excluded,
            "legacy_first_answer_events": legacy,
            "superseded_representations": len(superseded),
            "transports": transports,
        },
        "total_findings": total,
        "omitted_findings": max(0, total - MAX_FINDINGS),
        "report": report,
    }


def validate_dns_snapshot(block):
    """Reject malformed or unbounded snapshots before UI access; no raw DB read."""
    if not isinstance(block, dict) or block.get("policy") != POLICY_ID:
        raise ValueError("Unsupported DNS snapshot")
    coverage = block.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("Invalid DNS coverage")

    def count(value):
        if type(value) is not int or not 0 <= value <= 100_000:
            raise ValueError("Invalid DNS count")
        return value

    retained, analyzed, excluded, conflicts = (
        count(coverage.get(key))
        for key in (
            "retained_records",
            "analyzed_events",
            "excluded_records",
            "conflicting_transactions",
        )
    )
    transports = coverage.get("transports")
    legacy = count(coverage.get("legacy_first_answer_events", 0))
    superseded = count(coverage.get("superseded_representations", 0))
    if (
        not isinstance(transports, dict)
        or set(transports) != {"tcp", "udp"}
        or sum(count(value) for value in transports.values()) != analyzed
        or retained != analyzed + excluded
        or conflicts * 2 > excluded
        or legacy > analyzed or superseded > excluded
    ):
        raise ValueError("Inconsistent DNS coverage")
    total, omitted = (
        count(block.get("total_findings")),
        count(block.get("omitted_findings")),
    )
    report = block.get("report")
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != 1
        or report.get("policy") != "dns-device-triage-v1"
        or not isinstance(report.get("privacy"), dict)
        or any(
            report["privacy"].get(key) is not False
            for key in (
                "client_ip_values_included",
                "response_ip_values_included",
                "raw_dns_rows_included",
            )
        )
    ):
        raise ValueError("Unsupported DNS report privacy")
    rows = report.get("findings")
    required = {
        "Device",
        "Target",
        "Queue priority",
        "Verdict",
        "Telemetry events",
        "Distinct timestamps",
        "First observed",
        "Last observed",
        "Coverage limits",
        "Evidence",
        "Known CTI sources",
    }
    if (
        not isinstance(rows, list)
        or len(rows) != min(total, MAX_FINDINGS)
        or omitted != total - len(rows)
        or total > analyzed
    ):
        raise ValueError("Invalid DNS finding bounds")
    observed = 0
    for row in rows:
        if (
            not isinstance(row, dict)
            or not required.issubset(row)
            or row["Queue priority"] not in ("Investigate", "Review", "Observe")
            or not isinstance(row["Device"], str)
            or not (
                row["Device"] == "Unattributed"
                or (
                    row["Device"].startswith("Device ")
                    and row["Device"][7:].isascii()
                    and row["Device"][7:].isdecimal()
                )
            )
            or not isinstance(row["Target"], str)
            or len(row["Target"]) > 1024
        ):
            raise ValueError("Invalid DNS findings")
        events = count(row["Telemetry events"])
        from .target_privacy import target_type
        if target_type(row["Target"]) != "domain":
            raise ValueError("Unaliased IP target in private-by-default DNS report")
        if events < 1 or count(row["Distinct timestamps"]) > events:
            raise ValueError("Invalid DNS evidence counts")
        observed += events
        for key in ("First observed", "Last observed"):
            value = row[key]
            if value is not None:
                if not isinstance(value, str) or len(value) > 64:
                    raise ValueError("Invalid DNS evidence time")
                timestamp = datetime.fromisoformat(value)
                if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                    raise ValueError("Ambiguous DNS evidence time")
    if observed > analyzed:
        raise ValueError("DNS findings exceed evidence")
    if "timelines" in report:
        from .dns_timeline import validate_dns_timelines

        validate_dns_timelines(report["timelines"], rows)
