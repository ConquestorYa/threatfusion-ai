from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .dashboard import device_finding_rows, ml_tier_label, reason_label, verdict_label
from .device_triage import POLICY_ID
from .runtime_analysis import RuntimeAnalysisResult


@dataclass(frozen=True)
class AnalysisReport:
    json_text: str
    csv_text: str
    generated_at: str


def build_device_report(
    result: RuntimeAnalysisResult, *, include_client_ips: bool = False,
    generated_at: datetime | None = None,
) -> str:
    """Explicit separate export; original aggregate export stays unchanged.

    Domain names and timestamps are still telemetry. Device aliases are local
    to this report and are not anonymization or stable asset identities.
    """
    return json.dumps({
        "schema_version": 1,
        "policy": POLICY_ID,
        "generated_at": _generated_at_text(generated_at),
        "findings": device_finding_rows(
            result.device_findings, include_client_ips=include_client_ips,
        ),
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
