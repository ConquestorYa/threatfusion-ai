from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from .cti_cache import load_ioc_records
from .ml_artifact import load_trusted_ml_artifact
from .reporting import build_analysis_report
from .runtime_analysis import (
    analyze_dns_csv_with_diagnostics,
    analyze_pihole_query_db_with_diagnostics,
    analyze_zeek_dns_log_with_diagnostics,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze local DNS telemetry with ThreatFusion AI"
    )
    parser.add_argument("input", type=Path, help="Telemetry file to analyze")
    parser.add_argument(
        "--format",
        choices=("dns-csv", "zeek", "pihole"),
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
    return parser


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _load_input(path: Path, telemetry_format: str) -> str | bytes:
    if telemetry_format == "pihole":
        return path.read_bytes()
    return path.read_text(encoding="utf-8-sig")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    content = _load_input(args.input, args.format)

    artifact = load_trusted_ml_artifact(args.model_dir)
    indicators = load_ioc_records(args.db)

    if args.format == "dns-csv":
        result, diagnostics = analyze_dns_csv_with_diagnostics(
            str(content),
            indicators,
            artifact,
        )
    elif args.format == "zeek":
        result, diagnostics = analyze_zeek_dns_log_with_diagnostics(
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

    report = build_analysis_report(
        result,
        model_name=artifact.metadata.model_name,
    )

    if args.json_output is not None:
        _write_text(args.json_output, report.json_text)
    if args.csv_output is not None:
        _write_text(args.csv_output, report.csv_text)

    verdict_counts = {
        "known_threat": 0,
        "high_risk": 0,
        "review": 0,
        "low": 0,
    }
    for assessment in result.assessments:
        verdict_counts[assessment.verdict.value] += 1

    print("ThreatFusion analysis complete")
    print(f"  Input rows: {diagnostics.total_rows}")
    print(f"  Accepted rows: {diagnostics.accepted_rows}")
    print(f"  Domains: {len(result.assessments)}")
    print(f"  Known Threat: {verdict_counts['known_threat']}")
    print(f"  High Risk: {verdict_counts['high_risk']}")
    print(f"  Review: {verdict_counts['review']}")
    print(f"  Low: {verdict_counts['low']}")
    print(f"  IOC matches: {len(result.matches)}")
    return 0
