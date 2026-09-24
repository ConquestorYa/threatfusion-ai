from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_high_recall import run_high_recall_experiment
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate high-recall malicious-domain candidates"
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    return parser


def _print_metrics(prefix: str, metrics) -> None:
    print(
        f"  {prefix}: threshold={metrics.threshold:.6f} "
        f"precision={metrics.precision:.4f} recall={metrics.recall:.4f} "
        f"f1={metrics.f1:.4f} fpr={metrics.false_positive_rate:.4f} "
        f"TN={metrics.true_negative} FP={metrics.false_positive} "
        f"FN={metrics.false_negative} TP={metrics.true_positive}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        print("Loading local snapshot...", flush=True)
        snapshot = read_domain_snapshot(args.snapshot_dir)
        print(
            f"Loaded {len(snapshot.samples)} samples. "
            "Training and evaluating high-recall candidates...",
            flush=True,
        )
        result = run_high_recall_experiment(snapshot.samples)
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"High-recall evaluation failed: {type(error).__name__}"
        ) from None

    print("ThreatFusion AI high-recall ML evaluation")
    print(f"Snapshot directory: {args.snapshot_dir}")
    print("Split:")
    print(f"  Train: {len(result.split.train)}")
    print(f"  Validation: {len(result.split.validation)}")
    print(f"  Test: {len(result.split.test)}")
    print("Balanced Logistic Regression at default threshold:")
    _print_metrics("test", result.default_test)
    print("Validation-selected recall targets:")
    for evaluation in result.target_evaluations:
        print(f"Target recall >= {evaluation.target_recall:.2f}")
        _print_metrics("validation", evaluation.validation)
        _print_metrics("test", evaluation.test)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
