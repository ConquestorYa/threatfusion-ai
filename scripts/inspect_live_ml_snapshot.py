from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import requests

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.collectors.sgb import SGBCollector
from threatfusion.collectors.threatfox import ThreatFoxCollector
from threatfusion.collectors.tranco import TrancoCollector
from threatfusion.collectors.urlhaus import URLhausCollector
from threatfusion.ml_artifact import (
    compute_ml_artifact_checksum,
    load_trusted_ml_artifact,
)
from threatfusion.ml_holdout_collection import (
    final_holdout_experiment_metadata,
    prepare_final_holdout_collection,
)
from threatfusion.ml_snapshot import (
    DomainDatasetSnapshot,
    build_domain_snapshot,
    parse_tranco_csv,
)
from threatfusion.ml_snapshot_io import (
    read_domain_snapshot,
    write_domain_snapshot,
)
from threatfusion.models import IOCRecord


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _threatfox_days(value: str) -> int:
    parsed = _positive_integer(value)
    if parsed > 7:
        raise argparse.ArgumentTypeError("must be between 1 and 7")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect or persist a live ML dataset snapshot"
    )
    parser.add_argument("--threatfox-days", type=_threatfox_days, default=7)
    parser.add_argument(
        "--sgb-max-pages",
        "--sgb-pages",
        dest="sgb_max_pages",
        type=_positive_integer,
        default=10,
    )
    parser.add_argument("--tranco-id", default="L5PV4")
    parser.add_argument("--tranco-date", default="2026-09-23")
    parser.add_argument("--tranco-limit", type=_positive_integer, default=50000)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument(
        "--final-holdout-against",
        type=Path,
        default=None,
        help=(
            "Enable final-holdout guardrails using this development "
            "snapshot directory"
        ),
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=None,
        help=(
            "Frozen trusted ML artifact directory; required with "
            "--final-holdout-against"
        ),
    )
    return parser


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def _collect_sgb_records(max_pages: int) -> tuple[list[IOCRecord], int]:
    result = SGBCollector().fetch_bounded_addresses(max_pages=max_pages)
    return list(result.records), result.pages_fetched


def _prepare_final_holdout_metadata(
    args: argparse.Namespace,
) -> dict[str, object]:
    if args.final_holdout_against is None:
        return {}
    if args.output_dir is None:
        raise SystemExit(
            "Final holdout collection requires --output-dir"
        )
    if args.artifact_dir is None:
        raise SystemExit(
            "Final holdout collection requires --artifact-dir"
        )

    try:
        development = read_domain_snapshot(args.final_holdout_against)
        artifact = load_trusted_ml_artifact(args.artifact_dir)
        checksum = compute_ml_artifact_checksum(args.artifact_dir)
        context = prepare_final_holdout_collection(
            development_metadata=development.metadata,
            artifact_metadata=artifact.metadata,
            artifact_sha256=checksum,
            holdout_snapshot_id=args.tranco_id,
            holdout_snapshot_date=args.tranco_date,
            development_snapshot_dir=args.final_holdout_against,
            output_dir=args.output_dir,
        )
    except (OSError, TypeError, ValueError) as error:
        raise SystemExit(
            f"Final holdout preflight failed: {error}"
        ) from None

    metadata = final_holdout_experiment_metadata(context)
    print("Final holdout preflight passed")
    print(f"  Development date: {context.development_snapshot_date}")
    print(f"  Holdout date: {context.holdout_snapshot_date}")
    print(f"  Frozen model: {context.model_name}")
    print(f"  Frozen artifact SHA-256: {context.artifact_sha256}")
    return metadata


def _print_report(
    args: argparse.Namespace,
    threatfox_count: int,
    urlhaus_count: int,
    sgb_count: int,
    snapshot: DomainDatasetSnapshot,
) -> None:
    statistics = snapshot.statistics
    print("ThreatFusion AI live ML snapshot")
    print("Collection configuration:")
    print(f"  ThreatFox days: {args.threatfox_days}")
    print(f"  SGB max pages: {args.sgb_max_pages}")
    print(f"  Tranco ID: {args.tranco_id}")
    print(f"  Tranco date: {args.tranco_date}")
    print(f"  Tranco row limit: {args.tranco_limit}")
    print("Raw IOC record counts:")
    print(f"  ThreatFox records: {threatfox_count}")
    print(f"  URLhaus records: {urlhaus_count}")
    print(f"  SGB records: {sgb_count}")
    print("Snapshot statistics:")
    print(f"  malicious_input_count: {statistics.malicious_input_count}")
    print(f"  malicious_unique_count: {statistics.malicious_unique_count}")
    print(f"  benign_input_count: {statistics.benign_input_count}")
    print(f"  benign_unique_count: {statistics.benign_unique_count}")
    print(
        "  overlap_removed_from_benign: "
        f"{statistics.overlap_removed_from_benign}"
    )
    print(f"  final_malicious_count: {statistics.final_malicious_count}")
    print(f"  final_benign_count: {statistics.final_benign_count}")
    print(f"  final_total_count: {statistics.final_total_count}")
    print(f"  malicious_by_source: {statistics.malicious_by_source}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    holdout_metadata = _prepare_final_holdout_metadata(args)

    threatfox_key = _required_environment_value("THREATFOX_AUTH_KEY")
    urlhaus_key = _required_environment_value("URLHAUS_AUTH_KEY")

    try:
        threatfox_records = ThreatFoxCollector(threatfox_key).fetch_recent_iocs(
            days=args.threatfox_days
        )
    except (requests.RequestException, TypeError, ValueError) as error:
        raise SystemExit(
            f"ThreatFox collection failed: {type(error).__name__}"
        ) from None

    try:
        urlhaus_records = URLhausCollector(urlhaus_key).fetch_recent_urls()
    except (requests.RequestException, TypeError, ValueError) as error:
        raise SystemExit(
            f"URLhaus collection failed: {type(error).__name__}"
        ) from None

    try:
        sgb_records, sgb_pages_fetched = _collect_sgb_records(
            args.sgb_max_pages
        )
    except (requests.RequestException, TypeError, ValueError) as error:
        raise SystemExit(
            f"SGB collection failed: {type(error).__name__}"
        ) from None

    try:
        tranco_csv = TrancoCollector(args.tranco_id).fetch_csv()
    except (requests.RequestException, TypeError, ValueError) as error:
        raise SystemExit(
            f"Tranco collection failed: {type(error).__name__}"
        ) from None

    benign_domains = parse_tranco_csv(tranco_csv, limit=args.tranco_limit)
    if not benign_domains:
        raise SystemExit("Tranco parsing failed: no valid domains returned")

    snapshot = build_domain_snapshot(
        [*threatfox_records, *urlhaus_records, *sgb_records],
        benign_domains,
        benign_source="Tranco",
        benign_snapshot_id=args.tranco_id,
        benign_snapshot_date=args.tranco_date,
    )
    if args.output_dir is not None:
        experiment_metadata = {
            "threatfox_days": args.threatfox_days,
            "sgb_max_pages": args.sgb_max_pages,
            "sgb_pages_fetched": sgb_pages_fetched,
            "tranco_limit": args.tranco_limit,
            "tranco_id": args.tranco_id,
            "tranco_date": args.tranco_date,
        }
        experiment_metadata.update(holdout_metadata)
        dataset_path, metadata_path = write_domain_snapshot(
            snapshot,
            args.output_dir,
            experiment_metadata=experiment_metadata,
        )
        print(f"Snapshot files written: {dataset_path} and {metadata_path}")

    _print_report(
        args,
        len(threatfox_records),
        len(urlhaus_records),
        len(sgb_records),
        snapshot,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
