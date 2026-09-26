from __future__ import annotations

from collections.abc import Sequence

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .ml_dataset import DomainSample
from .ml_fpr_comparison import CandidateEvaluation, evaluate_candidate
from .ml_high_recall import TrainValidationTestSplit, split_train_validation_test


def build_recall_iteration_candidates(
    random_state: int = 42,
) -> dict[str, Pipeline]:
    """Build one small family of explainable LR candidates.

    Only regularization strength changes. The representation, class balancing,
    and training algorithm remain the same as the current selected model.
    """
    candidates: dict[str, Pipeline] = {}
    for c_value in (0.5, 1.0, 2.0, 4.0):
        name = f"lr_char_2_6_balanced_c{c_value:g}"
        candidates[name] = Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        analyzer="char",
                        ngram_range=(2, 6),
                        lowercase=False,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "classifier",
                    LogisticRegression(
                        C=c_value,
                        class_weight="balanced",
                        max_iter=1000,
                        random_state=random_state,
                    ),
                ),
            ]
        )
    return candidates


def run_simple_recall_iteration(
    samples: Sequence[DomainSample],
    *,
    fpr_budgets: Sequence[float] = (0.001, 0.005, 0.01),
    test_size: float = 0.20,
    validation_size: float = 0.20,
    random_state: int = 42,
) -> tuple[TrainValidationTestSplit, tuple[CandidateEvaluation, ...]]:
    """Compare a bounded LR regularization sweep on one shared split."""
    split = split_train_validation_test(
        samples,
        test_size=test_size,
        validation_size=validation_size,
        random_state=random_state,
    )
    candidates = build_recall_iteration_candidates(random_state=random_state)

    results = tuple(
        evaluate_candidate(
            name,
            model,
            split,
            fpr_budgets=fpr_budgets,
        )
        for name, model in candidates.items()
    )
    return split, results
