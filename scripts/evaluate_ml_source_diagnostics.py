from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_fpr_comparison import run_fpr_budget_comparison
from threatfusion.ml_snapshot_io import read_domain_snapshot
from threatfusion.ml_source_diagnostics import build_source_diagnostic_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Report malicious-domain recall by retained CTI source"
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    print("Loading local snapshot...", flush=True)
    try:
        snapshot = read_domain_snapshot(args.snapshot_dir)
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"Source diagnostics failed: {type(error).__name__}"
        ) from None

    print(f"Loaded {len(snapshot.samples)} samples.", flush=True)

    def progress(name: str) -> None:
        print(f"Training candidate: {name}", flush=True)

    try:
        comparison = run_fpr_budget_comparison(
            snapshot.samples,
            progress_callback=progress,
        )
        report = build_source_diagnostic_report(comparison)
    except ValueError as error:
        raise SystemExit(
            f"Source diagnostics failed: {type(error).__name__}"
        ) from None

    print("ThreatFusion AI source-wise malicious recall diagnostics")
    print("Development test only; source results are diagnostic, not final claims.")

    for candidate in report.candidates:
        print(f"Candidate: {candidate.name}")
        for budget in candidate.budgets:
            print(
                "  Validation FPR budget "
                f"<= {budget.max_false_positive_rate * 100:.1f}% "
                f"(threshold={budget.threshold:.6f})"
            )
            for source in budget.sources:
                print(
                    f"    {source.source}: total={source.total} "
                    f"detected={source.detected} missed={source.missed} "
                    f"recall={source.recall:.4f}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
