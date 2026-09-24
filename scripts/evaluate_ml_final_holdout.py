from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_artifact import load_trusted_ml_artifact
from threatfusion.ml_holdout import (
    evaluate_frozen_artifact_on_holdout,
    validate_fresh_snapshot_dates,
)
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the frozen ThreatFusion ML artifact on a fresh holdout"
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--development-snapshot-dir", type=Path, required=True)
    parser.add_argument("--holdout-snapshot-dir", type=Path, required=True)
    return parser


def _print_metrics(name: str, metrics) -> None:
    print(
        f"  {name}: threshold={metrics.threshold:.6f} "
        f"precision={metrics.precision:.4f} "
        f"recall={metrics.recall:.4f} "
        f"f1={metrics.f1:.4f} "
        f"fpr={metrics.false_positive_rate:.4f} "
        f"TN={metrics.true_negative} FP={metrics.false_positive} "
        f"FN={metrics.false_negative} TP={metrics.true_positive}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        artifact = load_trusted_ml_artifact(args.artifact_dir)
        development = read_domain_snapshot(args.development_snapshot_dir)
        holdout = read_domain_snapshot(args.holdout_snapshot_dir)
        validate_fresh_snapshot_dates(
            development.metadata.benign_snapshot_date,
            holdout.metadata.benign_snapshot_date,
        )
        evaluation = evaluate_frozen_artifact_on_holdout(
            artifact,
            development.samples,
            holdout.samples,
        )
    except (OSError, TypeError, ValueError) as error:
        raise SystemExit(
            f"Final holdout evaluation failed: {type(error).__name__}"
        ) from None

    print("ThreatFusion AI frozen final-holdout evaluation")
    print(f"  Model: {artifact.metadata.model_name}")
    print(
        "  Development benign snapshot date: "
        f"{development.metadata.benign_snapshot_date}"
    )
    print(
        "  Holdout benign snapshot date: "
        f"{holdout.metadata.benign_snapshot_date}"
    )
    print("Holdout preparation:")
    print(f"  Input samples: {evaluation.input_count}")
    print(f"  Removed development overlap: {evaluation.overlap_removed}")
    print(f"  Retained samples: {evaluation.retained_count}")
    print(f"  Retained malicious: {evaluation.malicious_count}")
    print(f"  Retained benign: {evaluation.benign_count}")
    print("Frozen operating points:")
    _print_metrics("high", evaluation.high)
    _print_metrics("medium", evaluation.medium)
    _print_metrics("low", evaluation.low)

    print("Malicious recall by retained source:")
    for source in evaluation.source_recalls:
        print(
            f"  {source.source}: total={source.total} "
            f"high={source.high_recall:.4f} "
            f"medium={source.medium_recall:.4f} "
            f"low={source.low_recall:.4f}"
        )

    print(
        "Interpretation: thresholds were frozen before this holdout. "
        "No retraining or threshold tuning was performed."
    )
    print(
        "This is a fresh-collection disjoint holdout, not a strict IOC "
        "first-seen time split."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
