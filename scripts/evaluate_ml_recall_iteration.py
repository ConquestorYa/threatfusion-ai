from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.ml_augmented_development import calculate_benign_source_fpr
from threatfusion.ml_recall_iteration import run_simple_recall_iteration
from threatfusion.ml_snapshot_io import read_domain_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run one bounded Logistic Regression recall iteration on a local "
            "development snapshot"
        )
    )
    parser.add_argument("--snapshot-dir", type=Path, required=True)
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


def _malicious_source_recall(samples, predictions):
    totals: dict[str, int] = {}
    detected: dict[str, int] = {}
    for sample, prediction in zip(samples, predictions, strict=True):
        if sample.label != 1:
            continue
        totals[sample.source] = totals.get(sample.source, 0) + 1
        if prediction == 1:
            detected[sample.source] = detected.get(sample.source, 0) + 1

    return tuple(
        (
            source,
            totals[source],
            detected.get(source, 0),
            detected.get(source, 0) / totals[source],
        )
        for source in sorted(totals)
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    budgets = tuple(args.fpr_budgets)
    if not budgets or any(not 0 <= budget <= 1 for budget in budgets):
        raise SystemExit("FPR budgets must be rates between 0 and 1")

    try:
        snapshot = read_domain_snapshot(args.snapshot_dir)
        split, candidates = run_simple_recall_iteration(
            snapshot.samples,
            fpr_budgets=budgets,
        )
    except (OSError, TypeError, ValueError) as error:
        raise SystemExit(
            f"Recall iteration failed: {type(error).__name__}: {error}"
        ) from None

    print("ThreatFusion AI simple recall iteration")
    print(f"  Snapshot samples: {len(snapshot.samples)}")
    print(f"  Train: {len(split.train)}")
    print(f"  Validation: {len(split.validation)}")
    print(f"  Test: {len(split.test)}")
    print("  Candidate family: same 2-6 char TF-IDF + balanced Logistic Regression")
    print("  Only Logistic Regression C changes: 0.5 / 1 / 2 / 4")

    for candidate in candidates:
        print(f"Candidate: {candidate.name}")
        scores = _positive_scores(candidate.model, split.test)
        for result in candidate.budget_evaluations:
            threshold = result.validation.threshold
            predictions = [1 if score >= threshold else 0 for score in scores]
            test = result.test

            print(
                "  Validation FPR budget "
                f"<= {result.max_false_positive_rate * 100:.1f}% "
                f"(threshold={threshold:.6f})"
            )
            print(
                f"    overall test: recall={test.recall:.4f} "
                f"fpr={test.false_positive_rate:.4f} "
                f"FP={test.false_positive} TP={test.true_positive}"
            )
            for source in calculate_benign_source_fpr(
                split.test,
                predictions,
            ):
                print(
                    f"    benign source {source.source}: "
                    f"FP={source.false_positive}/{source.total} "
                    f"fpr={source.false_positive_rate:.4f}"
                )
            for source, total, detected, recall in _malicious_source_recall(
                split.test,
                predictions,
            ):
                print(
                    f"    malicious source {source}: "
                    f"TP={detected}/{total} recall={recall:.4f}"
                )

    print(
        "Note: this is a bounded development experiment. Do not promote a "
        "candidate from this output without freezing it before a new untouched "
        "holdout."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
