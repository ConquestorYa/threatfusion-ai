from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.dns import DNSParseResult, parse_dns_csv_with_diagnostics
from threatfusion.dns_adguard import parse_adguard_query_log_with_diagnostics
from threatfusion.dns_pihole import parse_pihole_query_db_with_diagnostics
from threatfusion.dns_zeek import parse_zeek_dns_log_with_diagnostics
from threatfusion.ml_artifact import (
    compute_ml_artifact_checksum,
    load_trusted_ml_artifact,
)
from threatfusion.ml_benign_telemetry import (
    build_benign_telemetry_report,
    evaluate_benign_telemetry,
    write_benign_telemetry_report,
)
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate frozen ThreatFusion ML thresholds on operator-confirmed "
            "benign DNS telemetry"
        )
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--development-snapshot-dir", type=Path, required=True)
    parser.add_argument(
        "--confirm-benign-label",
        action="store_true",
        help=(
            "Acknowledge that the supplied telemetry is intentionally being "
            "treated as benign-labeled evaluation data"
        ),
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--dns-csv", type=Path)
    inputs.add_argument("--zeek-dns-log", type=Path)
    inputs.add_argument("--pihole-db", type=Path)
    inputs.add_argument("--adguard-query-log", type=Path)
    parser.add_argument("--json-output", type=Path, default=None)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def _load_input(args: argparse.Namespace) -> tuple[str, DNSParseResult]:
    if args.dns_csv is not None:
        return (
            "generic_dns_csv",
            parse_dns_csv_with_diagnostics(
                args.dns_csv.read_text(encoding="utf-8")
            ),
        )
    if args.zeek_dns_log is not None:
        return (
            "zeek_dns_log",
            parse_zeek_dns_log_with_diagnostics(
                args.zeek_dns_log.read_text(encoding="utf-8")
            ),
        )
    if args.pihole_db is not None:
        return (
            "pihole_ftl_sqlite",
            parse_pihole_query_db_with_diagnostics(args.pihole_db.read_bytes()),
        )
    if args.adguard_query_log is not None:
        return (
            "adguard_home_query_log",
            parse_adguard_query_log_with_diagnostics(
                args.adguard_query_log.read_text(encoding="utf-8")
            ),
        )
    raise ValueError("one DNS telemetry input is required")


def _print_operating_point(name: str, point) -> None:
    interval = point.false_positive_rate_ci
    print(
        f"  {name}: threshold={point.threshold:.6f} "
        f"FP={point.false_positive_count}/{point.benign_count} "
        f"fpr={point.false_positive_rate:.6f} "
        f"95% CI=[{interval.lower:.6f}, {interval.upper:.6f}]"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.confirm_benign_label:
        raise SystemExit(
            "Benign telemetry evaluation refused: pass --confirm-benign-label "
            "only when the supplied corpus is intentionally labeled benign. "
            "Absence from CTI is not proof of benignness."
        )

    try:
        artifact = load_trusted_ml_artifact(args.artifact_dir)
        checksum = compute_ml_artifact_checksum(args.artifact_dir)
        development = read_domain_snapshot(args.development_snapshot_dir)
        input_format, parsed = _load_input(args)
        evaluation = evaluate_benign_telemetry(
            artifact,
            development.samples,
            parsed.events,
        )

        report_path = None
        if args.json_output is not None:
            report = build_benign_telemetry_report(
                evaluation,
                model_name=artifact.metadata.model_name,
                artifact_checksum=checksum,
                input_format=input_format,
            )
            report_path = write_benign_telemetry_report(
                report,
                args.json_output,
                overwrite=args.overwrite,
            )
    except (OSError, TypeError, ValueError) as error:
        raise SystemExit(
            "Benign telemetry evaluation failed: "
            f"{type(error).__name__}: {error}"
        ) from None

    preparation = evaluation.preparation
    diagnostics = parsed.diagnostics
    print("ThreatFusion AI confirmed-benign DNS telemetry evaluation")
    print(f"  Model: {artifact.metadata.model_name}")
    print(f"  Artifact SHA-256: {checksum}")
    print(f"  Input format: {input_format}")
    print("Parser diagnostics:")
    print(f"  Total rows: {diagnostics.total_rows}")
    print(f"  Accepted rows: {diagnostics.accepted_rows}")
    print(f"  Missing query names: {diagnostics.skipped_missing_query_name}")
    print(f"  Invalid timestamps: {diagnostics.invalid_timestamps}")
    print(f"  Invalid response IPs: {diagnostics.invalid_response_ips}")
    print("Benign domain preparation:")
    print(f"  Input events: {preparation.input_event_count}")
    print(
        "  Public-domain candidate events: "
        f"{preparation.public_candidate_event_count}"
    )
    print(f"  Unique public-domain candidates: {preparation.unique_candidate_count}")
    print(
        "  Removed development overlap: "
        f"{preparation.development_overlap_removed}"
    )
    print(f"  Retained benign domains: {len(preparation.retained_domains)}")
    print("Frozen operating points:")
    _print_operating_point("high", evaluation.high)
    _print_operating_point("medium", evaluation.medium)
    _print_operating_point("low", evaluation.low)
    print(
        "Interpretation: all retained domains are treated as benign because "
        "the operator explicitly supplied them as benign-labeled evaluation data."
    )
    print(
        "This measures empirical false-positive behavior on this corpus only; "
        "it does not prove that arbitrary CTI-unmatched DNS traffic is benign."
    )
    if report_path is not None:
        print(f"Aggregate JSON report: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
