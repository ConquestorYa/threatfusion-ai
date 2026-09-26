from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_fpr_comparison import run_fpr_budget_comparison
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare malicious-domain models under FPR budgets"
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument(
        "--fpr-budgets",
        type=float,
        nargs="+",
        default=[0.001, 0.01, 0.05, 0.10],
        metavar="RATE",
        help=(
            "Validation FPR budgets as rates, e.g. "
            "--fpr-budgets 0.001 0.005 0.01 for 0.1%%, 0.5%%, 1%%"
        ),
    )
    return parser


def _print_metrics(prefix: str, metrics) -> None:
    print(
        f"    {prefix}: threshold={metrics.threshold:.6f} "
        f"precision={metrics.precision:.4f} recall={metrics.recall:.4f} "
        f"f1={metrics.f1:.4f} fpr={metrics.false_positive_rate:.4f} "
        f"TN={metrics.true_negative} FP={metrics.false_positive} "
        f"FN={metrics.false_negative} TP={metrics.true_positive}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    print("Loading local snapshot...", flush=True)
    try:
        snapshot = read_domain_snapshot(args.snapshot_dir)
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"FPR-budget comparison failed: {type(error).__name__}"
        ) from None

    print(f"Loaded {len(snapshot.samples)} samples.", flush=True)

    def progress(name: str) -> None:
        print(f"Training candidate: {name}", flush=True)

    budgets = tuple(args.fpr_budgets)
    if not budgets or any(not 0 <= budget <= 1 for budget in budgets):
        raise SystemExit("FPR budgets must be rates between 0 and 1")

    try:
        result = run_fpr_budget_comparison(
            snapshot.samples,
            fpr_budgets=budgets,
            progress_callback=progress,
        )
    except ValueError as error:
        raise SystemExit(
            f"FPR-budget comparison failed: {type(error).__name__}"
        ) from None

    print("ThreatFusion AI FPR-budget model comparison")
    print(f"Snapshot directory: {args.snapshot_dir}")
    print("Shared development split:")
    print(f"  Train: {len(result.split.train)}")
    print(f"  Validation: {len(result.split.validation)}")
    print(f"  Test: {len(result.split.test)}")

    for candidate in result.candidates:
        print(f"Candidate: {candidate.name}")
        for evaluation in candidate.budget_evaluations:
            budget_percent = evaluation.max_false_positive_rate * 100
            print(f"  Validation FPR budget <= {budget_percent:.1f}%")
            _print_metrics("validation", evaluation.validation)
            _print_metrics("test", evaluation.test)

    print(
        "Note: this is development evaluation. "
        "Final claims require a fresh/source-aware/time-aware holdout."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
