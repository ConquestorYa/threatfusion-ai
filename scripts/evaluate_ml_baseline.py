from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_baseline import run_baseline_experiment
from threatfusion.ml_snapshot_io import read_domain_snapshot


def _test_size(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "must be a number strictly between 0 and 1"
        ) from error
    if not 0 < parsed < 1:
        raise argparse.ArgumentTypeError("must be strictly between 0 and 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the baseline malicious-domain classifier"
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--test-size", type=_test_size, default=0.20)
    parser.add_argument("--random-state", type=int, default=42)
    return parser


def _print_report(
    snapshot_dir: Path,
    test_size: float,
    random_state: int,
    result,
) -> None:
    metrics = result.metrics
    print("ThreatFusion AI baseline ML evaluation")
    print("Configuration:")
    print(f"  Snapshot directory: {snapshot_dir}")
    print(f"  Test size: {test_size}")
    print(f"  Random state: {random_state}")
    print("Dataset split:")
    print(f"  Train samples: {metrics.train_count}")
    print(f"  Test samples: {metrics.test_count}")
    print(f"  Train malicious: {metrics.train_malicious_count}")
    print(f"  Train benign: {metrics.train_benign_count}")
    print(f"  Test malicious: {metrics.test_malicious_count}")
    print(f"  Test benign: {metrics.test_benign_count}")
    print("Confusion matrix counts:")
    print(f"  TN: {metrics.true_negative}")
    print(f"  FP: {metrics.false_positive}")
    print(f"  FN: {metrics.false_negative}")
    print(f"  TP: {metrics.true_positive}")
    print("Metrics:")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall: {metrics.recall:.4f}")
    print(f"  F1: {metrics.f1:.4f}")
    print(f"  False-positive rate: {metrics.false_positive_rate:.4f}")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        snapshot = read_domain_snapshot(args.snapshot_dir)
        result = run_baseline_experiment(
            snapshot.samples,
            test_size=args.test_size,
            random_state=args.random_state,
        )
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"Baseline evaluation failed: {type(error).__name__}"
        ) from None

    _print_report(
        args.snapshot_dir,
        args.test_size,
        args.random_state,
        result,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
