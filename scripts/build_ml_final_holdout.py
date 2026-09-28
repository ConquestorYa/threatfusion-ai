from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.cti_cache import load_ioc_records, list_cti_cache_status
from threatfusion.dns import parse_dns_csv_with_diagnostics
from threatfusion.ml_artifact import (
    C4_DEVELOPMENT_CANDIDATE,
    compute_ml_artifact_checksum,
    load_trusted_ml_artifact,
)
from threatfusion.ml_benign_telemetry import prepare_benign_telemetry
from threatfusion.ml_holdout_collection import (
    final_holdout_experiment_metadata,
    prepare_final_holdout_collection,
    validate_final_cti_refreshes,
)
from threatfusion.ml_snapshot import build_domain_snapshot
from threatfusion.ml_snapshot_io import read_domain_snapshot, write_domain_snapshot

_DEFAULT_SOURCES = ("ThreatFox", "URLhaus", "SGB")


def _timezone_aware_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "timestamp must use ISO 8601"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError(
            "timestamp must include a timezone offset"
        )
    return parsed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build the final ThreatFusion ML holdout from a post-freeze local "
            "CTI cache plus an untouched confirmed-benign DNS corpus"
        )
    )
    parser.add_argument("--db-path", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--expected-artifact-sha256", required=True)
    parser.add_argument("--development-snapshot-dir", type=Path, required=True)
    parser.add_argument("--benign-dns-csv", type=Path, required=True)
    parser.add_argument(
        "--confirm-benign-label",
        action="store_true",
        help=(
            "Acknowledge that the supplied DNS corpus is intentionally used "
            "as confirmed-benign final evaluation data"
        ),
    )
    parser.add_argument("--benign-source", default="CESNET")
    parser.add_argument("--benign-source-id", required=True)
    parser.add_argument(
        "--holdout-snapshot-date",
        required=True,
        help="Final holdout date in YYYY-MM-DD format",
    )
    parser.add_argument(
        "--malicious-first-seen-after",
        type=_timezone_aware_datetime,
        required=True,
        help=(
            "Explicit post-freeze timestamp cutoff. Required CTI sources must "
            "also have been refreshed after this cutoff."
        ),
    )
    parser.add_argument(
        "--required-sources",
        nargs="+",
        default=list(_DEFAULT_SOURCES),
        metavar="SOURCE",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.confirm_benign_label:
        raise SystemExit(
            "Final holdout creation refused: pass --confirm-benign-label only "
            "for an intentionally benign-labeled evaluation corpus."
        )

    try:
        artifact = load_trusted_ml_artifact(
            args.artifact_dir,
            expected_checksum=args.expected_artifact_sha256,
        )
        if artifact.metadata.model_name != C4_DEVELOPMENT_CANDIDATE:
            raise ValueError(
                "final v1 protocol requires the frozen C=4 candidate"
            )
        artifact_checksum = compute_ml_artifact_checksum(args.artifact_dir)

        development = read_domain_snapshot(args.development_snapshot_dir)
        context = prepare_final_holdout_collection(
            development_metadata=development.metadata,
            artifact_metadata=artifact.metadata,
            artifact_sha256=artifact_checksum,
            holdout_snapshot_id=args.benign_source_id,
            holdout_snapshot_date=args.holdout_snapshot_date,
            development_snapshot_dir=args.development_snapshot_dir,
            output_dir=args.output_dir,
        )

        statuses = list_cti_cache_status(args.db_path)
        final_statuses = validate_final_cti_refreshes(
            statuses,
            required_sources=args.required_sources,
            malicious_first_seen_after=args.malicious_first_seen_after,
        )
        indicators = load_ioc_records(
            args.db_path,
            sources=args.required_sources,
        )
        if not indicators:
            raise ValueError(
                "required CTI sources contain no active records"
            )

        benign_bytes = args.benign_dns_csv.read_bytes()
        parsed = parse_dns_csv_with_diagnostics(
            benign_bytes.decode("utf-8-sig")
        )
        benign_preparation = prepare_benign_telemetry(
            parsed.events,
            development.samples,
        )

        snapshot = build_domain_snapshot(
            indicators,
            benign_preparation.retained_domains,
            benign_source=args.benign_source,
            benign_snapshot_id=args.benign_source_id,
            benign_snapshot_date=args.holdout_snapshot_date,
        )

        experiment_metadata = final_holdout_experiment_metadata(context)
        experiment_metadata.update(
            {
                "evaluation_protocol": (
                    "post_freeze_temporal_malicious_plus_confirmed_benign_dns"
                ),
                "malicious_first_seen_after": (
                    args.malicious_first_seen_after.isoformat()
                ),
                "required_cti_sources": list(args.required_sources),
                "cti_refreshes": {
                    status.source: status.refreshed_at
                    for status in final_statuses
                },
                "active_ioc_records_loaded": len(indicators),
                "benign_source": args.benign_source,
                "benign_source_id": args.benign_source_id,
                "benign_input_sha256": _sha256(args.benign_dns_csv),
                "benign_input_events": benign_preparation.input_event_count,
                "benign_unique_candidates": (
                    benign_preparation.unique_candidate_count
                ),
                "benign_development_overlap_removed": (
                    benign_preparation.development_overlap_removed
                ),
                "benign_retained_domains": len(
                    benign_preparation.retained_domains
                ),
            }
        )

        dataset_path, metadata_path = write_domain_snapshot(
            snapshot,
            args.output_dir,
            experiment_metadata=experiment_metadata,
        )
    except (OSError, TypeError, UnicodeDecodeError, ValueError) as error:
        raise SystemExit(
            "Final holdout build failed: "
            f"{type(error).__name__}: {error}"
        ) from None

    print("ThreatFusion AI final temporal holdout snapshot")
    print(f"  Frozen model: {artifact.metadata.model_name}")
    print(f"  Frozen artifact SHA-256: {artifact_checksum}")
    print(
        "  Malicious first_seen cutoff: "
        f"{args.malicious_first_seen_after.isoformat()}"
    )
    print("  Required CTI refreshes:")
    for status in final_statuses:
        print(
            f"    {status.source}: {status.refreshed_at} "
            f"({status.record_count:,} records)"
        )
    print(f"  Active IOC records loaded: {len(indicators):,}")
    print(
        "  Benign development overlap removed: "
        f"{benign_preparation.development_overlap_removed:,}"
    )
    print(
        "  Retained confirmed-benign domains: "
        f"{len(benign_preparation.retained_domains):,}"
    )
    print(
        "  Snapshot malicious domains before temporal evaluation filter: "
        f"{snapshot.statistics.final_malicious_count:,}"
    )
    print(
        "  Snapshot benign domains: "
        f"{snapshot.statistics.final_benign_count:,}"
    )
    print(f"  Dataset: {dataset_path}")
    print(f"  Metadata: {metadata_path}")
    print(
        "Next step: run evaluate_ml_final_holdout.py with the same explicit "
        "post-freeze cutoff. Thresholds remain frozen."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
