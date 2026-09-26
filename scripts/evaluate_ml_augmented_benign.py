from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.dns import parse_dns_csv_with_diagnostics
from threatfusion.ml_augmented_development import (
    calculate_benign_source_fpr,
    prepare_augmented_development_samples,
)
from threatfusion.ml_fpr_comparison import run_fpr_budget_comparison
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compare ML candidates after adding confirmed-benign long-tail "
            "development domains"
        )
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--benign-dns-csv", type=Path, required=True)
    parser.add_argument(
        "--confirm-benign-label",
        action="store_true",
        help=(
            "Acknowledge that the added corpus is intentionally treated as "
            "benign development data"
        ),
    )
    parser.add_argument(
        "--benign-source",
        default="CESNET",
        help="Source label for added benign development domains",
    )
    parser.add_argument(
        "--fpr-budgets",
        type=float,
        nargs="+",
        default=[0.001, 0.005, 0.01],
        metavar="RATE",
    )
    return parser


def _positive_scores(model, samples):
    probabilities = model.predict_proba([sample.domain for sample in samples])
    classes = list(model.classes_)
    positive_index = classes.index(1)
    return [float(row[positive_index]) for row in probabilities]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.confirm_benign_label:
        raise SystemExit(
            "Augmented development evaluation refused: pass "
            "--confirm-benign-label only when the added corpus is intentionally "
            "being used as benign development data."
        )

    budgets = tuple(args.fpr_budgets)
    if not budgets or any(not 0 <= budget <= 1 for budget in budgets):
        raise SystemExit("FPR budgets must be rates between 0 and 1")

    try:
        snapshot = read_domain_snapshot(args.snapshot_dir)
        parsed = parse_dns_csv_with_diagnostics(
            args.benign_dns_csv.read_text(encoding="utf-8")
        )
        preparation = prepare_augmented_development_samples(
            snapshot.samples,
            parsed.events,
            source=args.benign_source,
        )
    except (OSError, TypeError, ValueError) as error:
        raise SystemExit(
            "Augmented development preparation failed: "
            f"{type(error).__name__}: {error}"
        ) from None

    print("ThreatFusion AI long-tail benign augmented development evaluation")
    print(f"  Base snapshot samples: {len(snapshot.samples)}")
    print(f"  Benign input events: {preparation.input_event_count}")
    print(
        "  Public benign candidate events: "
        f"{preparation.public_candidate_event_count}"
    )
    print(f"  Unique benign candidates: {preparation.unique_candidate_count}")
    print(
        "  Removed overlap with base snapshot: "
        f"{preparation.overlap_with_base_removed}"
    )
    print(f"  Added benign domains: {preparation.added_benign_count}")
    print(f"  Augmented total samples: {len(preparation.samples)}")

    def progress(name: str) -> None:
        print(f"Training candidate: {name}", flush=True)

    try:
        comparison = run_fpr_budget_comparison(
            preparation.samples,
            fpr_budgets=budgets,
            progress_callback=progress,
        )
    except ValueError as error:
        raise SystemExit(
            f"Augmented development comparison failed: {type(error).__name__}: {error}"
        ) from None

    test_samples = comparison.split.test
    print("Shared augmented development split:")
    print(f"  Train: {len(comparison.split.train)}")
    print(f"  Validation: {len(comparison.split.validation)}")
    print(f"  Test: {len(test_samples)}")

    for candidate in comparison.candidates:
        print(f"Candidate: {candidate.name}")
        scores = _positive_scores(candidate.model, test_samples)

        for evaluation in candidate.budget_evaluations:
            threshold = evaluation.validation.threshold
            predictions = [
                1 if score >= threshold else 0
                for score in scores
            ]
            source_fpr = calculate_benign_source_fpr(
                test_samples,
                predictions,
            )
            test = evaluation.test
            print(
                "  Validation FPR budget "
                f"<= {evaluation.max_false_positive_rate * 100:.1f}% "
                f"(threshold={threshold:.6f})"
            )
            print(
                f"    overall test: recall={test.recall:.4f} "
                f"fpr={test.false_positive_rate:.4f} "
                f"FP={test.false_positive} TP={test.true_positive}"
            )
            for source in source_fpr:
                print(
                    f"    benign source {source.source}: "
                    f"FP={source.false_positive}/{source.total} "
                    f"fpr={source.false_positive_rate:.4f}"
                )

    print(
        "Note: this corpus has already been inspected and is development "
        "evidence. These results are not a final holdout claim."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
