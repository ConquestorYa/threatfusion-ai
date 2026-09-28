from __future__ import annotations

from collections.abc import Sequence

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import StandardScaler

from .ml_dataset import DomainSample
from .ml_fpr_comparison import CandidateEvaluation, evaluate_candidate
from .ml_high_recall import TrainValidationTestSplit, split_train_validation_test
from .ml_lexical_features import DomainLexicalFeatures
from .ml_recall_iteration import build_recall_iteration_candidates


def _enhanced_pipeline(
    *,
    c_value: float,
    random_state: int,
) -> Pipeline:
    return Pipeline(
        steps=[
            (
                "features",
                FeatureUnion(
                    transformer_list=[
                        (
                            "char_tfidf",
                            TfidfVectorizer(
                                analyzer="char",
                                ngram_range=(2, 6),
                                lowercase=False,
                                sublinear_tf=True,
                            ),
                        ),
                        (
                            "lexical",
                            Pipeline(
                                steps=[
                                    ("extract", DomainLexicalFeatures()),
                                    ("scale", StandardScaler()),
                                ]
                            ),
                        ),
                    ]
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


def build_feature_iteration_candidates(
    random_state: int = 42,
) -> dict[str, Pipeline]:
    """Compare frozen-family C=4 against a small lexical-feature extension."""
    baseline = build_recall_iteration_candidates(random_state=random_state)[
        "lr_char_2_6_balanced_c4"
    ]
    candidates = {"lr_char_2_6_balanced_c4": baseline}
    for c_value in (1.0, 2.0, 4.0):
        candidates[f"lr_char_2_6_plus_lexical_c{c_value:g}"] = (
            _enhanced_pipeline(
                c_value=c_value,
                random_state=random_state,
            )
        )
    return candidates


def run_feature_iteration(
    samples: Sequence[DomainSample],
    *,
    fpr_budgets: Sequence[float] = (0.001, 0.005, 0.01),
    test_size: float = 0.20,
    validation_size: float = 0.20,
    random_state: int = 42,
) -> tuple[TrainValidationTestSplit, tuple[CandidateEvaluation, ...]]:
    """Evaluate all feature candidates on one shared development split."""
    split = split_train_validation_test(
        samples,
        test_size=test_size,
        validation_size=validation_size,
        random_state=random_state,
    )
    candidates = build_feature_iteration_candidates(random_state=random_state)
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
