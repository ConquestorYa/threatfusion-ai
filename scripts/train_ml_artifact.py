from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_artifact import (
    SELECTED_DEVELOPMENT_MODEL,
    SUPPORTED_DEVELOPMENT_MODELS,
    train_selected_model_artifact,
    write_ml_artifact,
)
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train and persist the selected ThreatFusion ML artifact"
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--high-fpr-budget", type=float, default=0.01)
    parser.add_argument("--medium-fpr-budget", type=float, default=0.05)
    parser.add_argument("--low-fpr-budget", type=float, default=0.10)
    parser.add_argument(
        "--model-name",
        choices=SUPPORTED_DEVELOPMENT_MODELS,
        default=SELECTED_DEVELOPMENT_MODEL,
        help="Development model candidate to freeze",
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    print("Loading local snapshot...", flush=True)
    try:
        snapshot = read_domain_snapshot(args.snapshot_dir)
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"ML artifact training failed: {type(error).__name__}"
        ) from None

    print(
        f"Loaded {len(snapshot.samples)} samples. "
        "Training selected development model...",
        flush=True,
    )

    try:
        artifact = train_selected_model_artifact(
            snapshot.samples,
            high_fpr_budget=args.high_fpr_budget,
            medium_fpr_budget=args.medium_fpr_budget,
            low_fpr_budget=args.low_fpr_budget,
            model_name=args.model_name,
        )
        model_path, metadata_path = write_ml_artifact(
            artifact,
            args.output_dir,
            overwrite=args.overwrite,
        )
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"ML artifact training failed: {type(error).__name__}"
        ) from None

    metadata = artifact.metadata
    print("ThreatFusion AI ML artifact written")
    print(f"  Model: {metadata.model_name}")
    print(f"  Model file: {model_path}")
    print(f"  Metadata file: {metadata_path}")
    print("  Validation-selected thresholds:")
    print(
        f"    high: threshold={metadata.high_threshold:.6f} "
        f"at FPR budget={metadata.high_fpr_budget:.3f}"
    )
    print(
        f"    medium: threshold={metadata.medium_threshold:.6f} "
        f"at FPR budget={metadata.medium_fpr_budget:.3f}"
    )
    print(
        f"    low: threshold={metadata.low_threshold:.6f} "
        f"at FPR budget={metadata.low_fpr_budget:.3f}"
    )
    print(
        "  Status: development-only; final performance still requires "
        "a fresh holdout."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
