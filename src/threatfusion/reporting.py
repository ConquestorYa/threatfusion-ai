from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .dashboard import contextual_connection_rows, device_finding_rows, ml_tier_label, reason_label, verdict_label
from .expected_connections import POLICY_ID as EXPECTATION_POLICY_ID
from .expected_connections import ExpectedConnectionRule
from .connections import POLICY_ID as CONNECTION_POLICY_ID
from .device_triage import POLICY_ID
from .runtime_analysis import RuntimeAnalysisResult


@dataclass(frozen=True)
class AnalysisReport:
    json_text: str
    csv_text: str
    generated_at: str


def build_connection_report(
    result: RuntimeAnalysisResult, *, include_ips: bool = False,
    generated_at: datetime | None = None,
    expected_rules: tuple[ExpectedConnectionRule, ...] = (), evaluated_at: datetime | None = None,
) -> str:
    from .connection_timeline import timeline_report
    from .connection_attempts import attempt_report

    evaluated_at = evaluated_at or datetime.now(timezone.utc)
    return json.dumps({
        "schema_version": 2, "policy": CONNECTION_POLICY_ID,
        "generated_at": _generated_at_text(generated_at),
        "context_policy": EXPECTATION_POLICY_ID,
        "context_evaluated_at": _generated_at_text(evaluated_at),
        "declaration_count": len(expected_rules),
        "findings": contextual_connection_rows(result, expected_rules, include_ips=include_ips, evaluated_at=evaluated_at),
        "timelines": timeline_report(result.connection_timelines, len(result.connection_findings)),
        "attempts": attempt_report(result.connection_attempts, result.connection_findings, include_ips=include_ips),
        "privacy": {"endpoint_ips_included": include_ips, "raw_connection_rows_included": False,
                    "connection_uids_included": False, "host_alias_scope": "this_report_only",
                    "rule_ids_and_configuration_included": False},
        "limitations": [
            "Review priority is not proof of C2, malware, downloads or execution.",
            "Observation direction is originator to responder, not inferred inbound/outbound.",
            "No DNS hostname association is inferred from shared IPs.",
            "Legitimate updates and long-lived services can also enter review.",
            "Aliases do not anonymize timestamps, ports and traffic statistics.",
            "Timeline bytes/states are assigned to connection start buckets, not transfer time; unknown bytes are counted separately.",
            "Timelines cover at most 200 groups and 48 buckets per group; absent buckets are not proof of absent network traffic.",
            "Expected activity is an expiring analyst declaration, not verified software identity or safety.",
            "CTI conflicts override expected activity; original priorities and evidence are retained.",
        ],
    }, indent=2, ensure_ascii=False) + "\n"


def build_device_report(
    result: RuntimeAnalysisResult, *, include_client_ips: bool = False,
    generated_at: datetime | None = None,
) -> str:
    """Explicit separate export; original aggregate export stays unchanged.

    Domain names and timestamps are still telemetry. Device aliases are local
    to this report and are not anonymization or stable asset identities.
    """
    from .dns_timeline import build_dns_timelines

    return json.dumps({
        "schema_version": 1,
        "policy": POLICY_ID,
        "generated_at": _generated_at_text(generated_at),
        "findings": device_finding_rows(
            result.device_findings, include_client_ips=include_client_ips,
        ),
        "timelines": build_dns_timelines(result.events, result.device_findings),
        "privacy": {
            "client_ip_values_included": include_client_ips,
            "response_ip_values_included": False,
            "raw_dns_rows_included": False,
            "device_alias_scope": "this_report_only",
        },
        "limitations": [
            "Queue priority is an engineering heuristic, not proof of compromise.",
            "DNS queries do not prove connections, downloads or execution.",
            "Observed clients may be resolvers or NAT addresses, not endpoints.",
            "Aliases do not anonymize domain names, timestamps or other evidence.",
            "Periodicity review does not distinguish legitimate updates from C2.",
        ],
    }, indent=2, ensure_ascii=False) + "\n"


def _generated_at_text(value: datetime | None) -> str:
    timestamp = value or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")
    return timestamp.astimezone(timezone.utc).isoformat()


def _verdict_counts(result: RuntimeAnalysisResult) -> dict[str, int]:
    counts = {
        "known_threat": 0,
        "high_risk": 0,
        "review": 0,
        "low": 0,
    }
    for assessment in result.assessments:
        counts[assessment.verdict.value] += 1
    return counts


def _finding_rows(result: RuntimeAnalysisResult) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []

    for assessment in sorted(
        result.assessments,
        key=lambda item: item.domain,
    ):
        behavior = assessment.behavior
        rows.append(
            {
                "domain": assessment.domain,
                "verdict": verdict_label(assessment.verdict.value),
                "ml_score": assessment.ml_score,
                "ml_tier": ml_tier_label(
                    assessment.ml_tier,
                    scored=assessment.ml_score is not None,
                ),
                "dns_events": behavior.event_count,
                "unique_clients": behavior.unique_client_count,
                "unique_response_ips": behavior.unique_response_ip_count,
                "query_types": list(behavior.query_types),
                "known_cti_sources": list(assessment.known_ioc_sources),
                "evidence": [
                    reason_label(reason)
                    for reason in assessment.reasons
                ],
            }
        )

    return rows


def _spreadsheet_safe_text(value: object) -> object:
    """Prevent exported text cells from being interpreted as formulas."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _csv_text(rows: list[dict[str, object]]) -> str:
    output = io.StringIO(newline="")
    fieldnames = [
        "domain",
        "verdict",
        "ml_score",
        "ml_tier",
        "dns_events",
        "unique_clients",
        "unique_response_ips",
        "query_types",
        "known_cti_sources",
        "evidence",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for row in rows:
        csv_row = {
            **row,
            "query_types": ", ".join(row["query_types"]),
            "known_cti_sources": ", ".join(row["known_cti_sources"]),
            "evidence": "; ".join(row["evidence"]),
        }
        writer.writerow(
            {
                key: _spreadsheet_safe_text(value)
                for key, value in csv_row.items()
            }
        )

    return output.getvalue()


def build_analysis_report(
    result: RuntimeAnalysisResult,
    *,
    model_name: str,
    generated_at: datetime | None = None,
) -> AnalysisReport:
    """Build privacy-conscious JSON and CSV reports from aggregate findings."""
    if not isinstance(model_name, str) or not model_name.strip():
        raise ValueError("model_name must be a non-empty string")

    generated_text = _generated_at_text(generated_at)
    rows = _finding_rows(result)
    counts = _verdict_counts(result)

    payload = {
        "generated_at": generated_text,
        "model_name": model_name.strip(),
        "summary": {
            "dns_events": len(result.events),
            "unique_domains": len(result.assessments),
            "known_ioc_matches": len(result.matches),
            "known_threat": counts["known_threat"],
            "high_risk": counts["high_risk"],
            "review": counts["review"],
            "low": counts["low"],
        },
        "findings": rows,
        "privacy": {
            "raw_dns_rows_included": False,
            "client_ip_values_included": False,
            "response_ip_values_included": False,
        },
    }

    return AnalysisReport(
        json_text=json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        csv_text=_csv_text(rows),
        generated_at=generated_text,
    )
