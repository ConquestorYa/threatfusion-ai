from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.dns import parse_dns_csv_with_diagnostics
from threatfusion.ml_augmented_development import build_augmented_development_snapshot
from threatfusion.ml_snapshot_io import read_domain_snapshot, write_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a reproducible augmented ML development snapshot"
    )
    parser.add_argument("--base-snapshot-dir", type=Path, required=True)
    parser.add_argument("--benign-dns-csv", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--benign-source", default="CESNET")
    parser.add_argument(
        "--benign-source-id",
        default="zenodo-14332167-first20k",
        help="Stable non-secret identifier for the added benign corpus",
    )
    parser.add_argument(
        "--confirm-benign-label",
        action="store_true",
        help=(
            "Acknowledge that the supplied corpus is intentionally used as "
            "benign development data"
        ),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.confirm_benign_label:
        raise SystemExit(
            "Augmented snapshot creation refused: pass --confirm-benign-label "
            "only when the added corpus is intentionally labeled benign."
        )

    output_dir = args.output_dir
    if (
        output_dir.exists()
        and any(output_dir.iterdir())
        and not args.overwrite
    ):
        raise SystemExit(
            "Augmented snapshot output directory is not empty; "
            "use --overwrite to replace its snapshot files."
        )

    try:
        base = read_domain_snapshot(args.base_snapshot_dir)
        csv_bytes = args.benign_dns_csv.read_bytes()
        parsed = parse_dns_csv_with_diagnostics(csv_bytes.decode("utf-8"))
        snapshot, preparation = build_augmented_development_snapshot(
            base,
            parsed.events,
            source=args.benign_source,
            source_snapshot_id=args.benign_source_id,
        )
        source_sha256 = _sha256(args.benign_dns_csv)
        dataset_path, metadata_path = write_domain_snapshot(
            snapshot,
            output_dir,
            experiment_metadata={
                "collection_purpose": "development_v2",
                "base_benign_source": base.metadata.benign_source,
                "base_benign_snapshot_id": base.metadata.benign_snapshot_id,
                "base_benign_snapshot_date": base.metadata.benign_snapshot_date,
                "augmentation_source": args.benign_source,
                "augmentation_source_id": args.benign_source_id,
                "augmentation_label_basis": "operator_confirmed_benign",
                "augmentation_input_sha256": source_sha256,
                "augmentation_added_benign_count": preparation.added_benign_count,
                "augmentation_overlap_removed": (
                    preparation.overlap_with_base_removed
                ),
            },
        )
    except (OSError, UnicodeDecodeError, TypeError, ValueError) as error:
        raise SystemExit(
            "Augmented snapshot creation failed: "
            f"{type(error).__name__}: {error}"
        ) from None

    print("ThreatFusion AI augmented development snapshot written")
    print(f"  Base snapshot samples: {len(base.samples)}")
    print(f"  Added benign domains: {preparation.added_benign_count}")
    print(
        "  Removed overlap with base snapshot: "
        f"{preparation.overlap_with_base_removed}"
    )
    print(f"  Final samples: {len(snapshot.samples)}")
    print(f"  Added benign CSV SHA-256: {source_sha256}")
    print(f"  Dataset: {dataset_path}")
    print(f"  Metadata: {metadata_path}")
    print(
        "  Status: development data; it must not be reused as an untouched "
        "final holdout."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
