from __future__ import annotations

import argparse
import os
import tempfile
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from .cti_cache import load_ioc_records
from .expected_connections import MAX_RULE_BYTES, connection_contexts, parse_expected_connections
from .ml_artifact import load_trusted_ml_artifact
from .reporting import build_analysis_report, build_connection_report, build_device_report
from .runtime_analysis import (
    analyze_adguard_query_log_with_diagnostics,
    analyze_dns_csv_with_diagnostics,
    analyze_pihole_query_db_with_diagnostics,
    analyze_zeek_dns_log_with_diagnostics,
    analyze_zeek_conn_log_with_diagnostics,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze local DNS telemetry with ThreatFusion AI"
    )
    parser.add_argument("input", type=Path, help="Telemetry file to analyze")
    parser.add_argument(
        "--cti-only",
        action="store_true",
        help="Use CTI matching and DNS behavior without loading any ML artifact",
    )
    parser.add_argument(
        "--format",
        choices=("dns-csv", "zeek", "zeek-conn", "pihole", "adguard"),
        default="dns-csv",
        help="Input telemetry format",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("data/threatfusion.sqlite"),
        help="Local ThreatFusion SQLite CTI cache",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("data/models/development-001"),
        help="Trusted local ML artifact directory",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional JSON report output path",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        help="Optional CSV findings output path",
    )
    parser.add_argument("--include-target-ips", action="store_true",
                        help="Include literal IP targets in explicit aggregate JSON/CSV exports")
    parser.add_argument(
        "--device-json-output", type=Path,
        help="Separate client/domain triage report (report-local device aliases)",
    )
    parser.add_argument(
        "--include-client-ips", action="store_true",
        help="Include observed client IPs only in the explicit device report",
    )
    parser.add_argument("--connection-json-output", type=Path,
                        help="Separate connection review report with host aliases by default")
    parser.add_argument("--include-connection-ips", action="store_true",
                        help="Include both endpoint IPs only in the explicit connection report")
    parser.add_argument("--expected-connections", type=Path,
                        help="Local expiring exact-endpoint declarations for the separate connection report")
    return parser


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".threatfusion-report-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(content)
        if path.is_symlink():
            raise ValueError("Report output cannot be a symlink")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(content)


def _load_input(path: Path, telemetry_format: str) -> str | bytes:
    if telemetry_format == "pihole":
        return path.read_bytes()
    return path.read_text(encoding="utf-8-sig")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.include_target_ips and args.json_output is None and args.csv_output is None:
        parser.error("--include-target-ips requires --json-output or --csv-output")
    if args.include_client_ips and args.device_json_output is None:
        parser.error("--include-client-ips requires --device-json-output")
    if args.include_connection_ips and args.connection_json_output is None:
        parser.error("--include-connection-ips requires --connection-json-output")
    rules = ()
    if args.expected_connections is not None:
        if args.format != "zeek-conn" or args.connection_json_output is None:
            parser.error("--expected-connections requires --format zeek-conn and --connection-json-output")
        try:
            with args.expected_connections.open("rb") as file:
                rules = parse_expected_connections(file.read(MAX_RULE_BYTES + 1))
        except (ValueError, OSError):
            parser.error("Invalid or unreadable expected-connection file; no rules applied")
    content = _load_input(args.input, args.format)

    artifact = None if args.cti_only else load_trusted_ml_artifact(args.model_dir)
    indicators = load_ioc_records(args.db)

    if args.format == "dns-csv":
        result, diagnostics = analyze_dns_csv_with_diagnostics(
            str(content),
            indicators,
            artifact,
        )
    elif args.format == "zeek-conn":
        result, diagnostics = analyze_zeek_conn_log_with_diagnostics(
            str(content), indicators, artifact,
        )
    elif args.format == "zeek":
        result, diagnostics = analyze_zeek_dns_log_with_diagnostics(
            str(content),
            indicators,
            artifact,
        )
    elif args.format == "adguard":
        result, diagnostics = analyze_adguard_query_log_with_diagnostics(
            str(content),
            indicators,
            artifact,
        )
    else:
        if not isinstance(content, bytes):
            raise TypeError("Pi-hole input must be binary SQLite content")
        result, diagnostics = analyze_pihole_query_db_with_diagnostics(
            content,
            indicators,
            artifact,
        )

    context_time = datetime.now(timezone.utc)
    report = build_analysis_report(
        result,
        model_name=artifact.metadata.model_name if artifact else "cti_only_ml_disabled",
        include_target_ips=args.include_target_ips,
    )

    if args.json_output is not None:
        _write_text(args.json_output, report.json_text)
    if args.csv_output is not None:
        _write_text(args.csv_output, report.csv_text)
    if args.device_json_output is not None:
        content = build_device_report(result, include_client_ips=args.include_client_ips)
        _write_private(args.device_json_output, content)
    if args.connection_json_output is not None:
        _write_private(args.connection_json_output, build_connection_report(
            result, include_ips=args.include_connection_ips, expected_rules=rules, evaluated_at=context_time,
        ))

    verdict_counts = {
        "known_threat": 0,
        "high_risk": 0,
        "review": 0,
        "low": 0,
    }
    for assessment in result.assessments:
        verdict_counts[assessment.verdict.value] += 1

    print("ThreatFusion analysis complete")
    if args.cti_only:
        print("  Mode: CTI and DNS behavior only; ML disabled")
    print(f"  Input rows: {diagnostics.total_rows}")
    print(f"  Accepted rows: {diagnostics.accepted_rows}")
    print(f"  Domains: {len(result.assessments)}")
    print(f"  Known Threat: {verdict_counts['known_threat']}")
    print(f"  High Risk: {verdict_counts['high_risk']}")
    print(f"  Review: {verdict_counts['review']}")
    print(f"  Low: {verdict_counts['low']}")
    print(f"  IOC matches: {len(result.matches)}")
    print(f"  Device/domain observations: {len(result.device_findings)}")
    print("  Device queue: " + ", ".join(
        f"{priority}={sum(f.priority == priority for f in result.device_findings)}"
        for priority in ("investigate", "review", "observe")
    ))
    print(f"  Connection groups: {len(result.connection_findings)}")
    print(f"  Connection reviews: {sum(f.priority == 'review' for f in result.connection_findings)}")
    contexts = connection_contexts(result, rules, evaluated_at=context_time)
    print(f"  Declared expected groups: {sum(c.expected for c in contexts)}")
    print(f"  Unexplained connection reviews: {sum(f.priority == 'review' and not c.expected for f, c in zip(result.connection_findings, contexts, strict=True))}")
    print(f"  Connection CTI conflicts: {sum(c.cti_matched for c in contexts)}")
    print(f"  Invalid connection fields: {diagnostics.invalid_connection_fields}")
    return 0
