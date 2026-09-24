from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.pipeline import Pipeline

from .ml_dataset import DomainSample
from .ml_high_recall import (
    ThresholdMetrics,
    TrainValidationTestSplit,
    calculate_threshold_metrics,
    split_train_validation_test,
)


@dataclass(frozen=True)
class FPRBudgetEvaluation:
    max_false_positive_rate: float
    validation: ThresholdMetrics
    test: ThresholdMetrics


@dataclass(frozen=True)
class CandidateEvaluation:
    name: str
    model: Pipeline
    budget_evaluations: tuple[FPRBudgetEvaluation, ...]


@dataclass(frozen=True)
class FPRBudgetComparison:
    split: TrainValidationTestSplit
    candidates: tuple[CandidateEvaluation, ...]


def build_candidate_pipelines(random_state: int = 42) -> dict[str, Pipeline]:
    """Build the small predefined set of explainable ML candidates."""
    return {
        "lr_char_3_5_balanced": Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        analyzer="char",
                        ngram_range=(3, 5),
                        lowercase=False,
                    ),
                ),
                (
                    "classifier",
                    LogisticRegression(
                        class_weight="balanced",
                        max_iter=1000,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "lr_char_2_6_sublinear_balanced": Pipeline(
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
                        class_weight="balanced",
                        max_iter=1000,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
        "sgd_char_3_5_balanced": Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        analyzer="char",
                        ngram_range=(3, 5),
                        lowercase=False,
                    ),
                ),
                (
                    "classifier",
                    SGDClassifier(
                        loss="log_loss",
                        class_weight="balanced",
                        max_iter=2000,
                        random_state=random_state,
                    ),
                ),
            ]
        ),
    }


def _metrics_from_counts(
    *,
    threshold: float,
    true_positive: int,
    false_positive: int,
    positive_count: int,
    negative_count: int,
) -> ThresholdMetrics:
    false_negative = positive_count - true_positive
    true_negative = negative_count - false_positive

    predicted_positive = true_positive + false_positive
    precision = true_positive / predicted_positive if predicted_positive else 0.0
    recall = true_positive / positive_count
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    false_positive_rate = false_positive / negative_count

    return ThresholdMetrics(
        threshold=float(threshold),
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        true_positive=true_positive,
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        false_positive_rate=float(false_positive_rate),
    )


def select_threshold_for_fpr_budget(
    labels: Sequence[int],
    probabilities: Sequence[float],
    *,
    max_false_positive_rate: float,
) -> ThresholdMetrics:
    """Maximize validation recall while staying within an FPR budget."""
    if not 0 <= max_false_positive_rate <= 1:
        raise ValueError("max_false_positive_rate must be between 0 and 1")
    if len(labels) != len(probabilities):
        raise ValueError("labels and probabilities must have the same length")
    if not probabilities:
        raise ValueError("cannot select a threshold from empty inputs")
    if set(labels) != {0, 1}:
        raise ValueError("threshold selection requires both binary labels")

    pairs: list[tuple[float, int]] = []
    for probability, label in zip(probabilities, labels, strict=True):
        value = float(probability)
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError("probabilities must be finite values between 0 and 1")
        pairs.append((value, label))

    pairs.sort(key=lambda item: item[0], reverse=True)
    positive_count = sum(label == 1 for label in labels)
    negative_count = len(labels) - positive_count
    thresholds = sorted(
        {0.0, 1.0, *(probability for probability, _ in pairs)},
        reverse=True,
    )

    true_positive = 0
    false_positive = 0
    pair_index = 0
    feasible: list[ThresholdMetrics] = []

    for threshold in thresholds:
        while pair_index < len(pairs) and pairs[pair_index][0] >= threshold:
            _, label = pairs[pair_index]
            if label == 1:
                true_positive += 1
            else:
                false_positive += 1
            pair_index += 1

        metrics = _metrics_from_counts(
            threshold=threshold,
            true_positive=true_positive,
            false_positive=false_positive,
            positive_count=positive_count,
            negative_count=negative_count,
        )
        if metrics.false_positive_rate <= max_false_positive_rate + 1e-12:
            feasible.append(metrics)

    if not feasible:
        raise ValueError("no threshold satisfies the requested false-positive budget")

    return max(
        feasible,
        key=lambda metrics: (
            metrics.recall,
            -metrics.false_positive_rate,
            metrics.precision,
            metrics.threshold,
        ),
    )


def _positive_probabilities(model: Pipeline, samples: list[DomainSample]) -> list[float]:
    probabilities = model.predict_proba([sample.domain for sample in samples])
    classes = list(model.classes_)
    positive_index = classes.index(1)
    return [float(row[positive_index]) for row in probabilities]


def evaluate_candidate(
    name: str,
    model: Pipeline,
    split: TrainValidationTestSplit,
    *,
    fpr_budgets: Sequence[float] = (0.001, 0.01, 0.05, 0.10),
) -> CandidateEvaluation:
    """Fit one candidate on train, select thresholds on validation, test them."""
    model.fit(
        [sample.domain for sample in split.train],
        [sample.label for sample in split.train],
    )

    validation_labels = [sample.label for sample in split.validation]
    validation_probabilities = _positive_probabilities(model, split.validation)
    test_labels = [sample.label for sample in split.test]
    test_probabilities = _positive_probabilities(model, split.test)

    evaluations: list[FPRBudgetEvaluation] = []
    for budget in fpr_budgets:
        validation_metrics = select_threshold_for_fpr_budget(
            validation_labels,
            validation_probabilities,
            max_false_positive_rate=float(budget),
        )
        test_metrics = calculate_threshold_metrics(
            test_labels,
            test_probabilities,
            threshold=validation_metrics.threshold,
        )
        evaluations.append(
            FPRBudgetEvaluation(
                max_false_positive_rate=float(budget),
                validation=validation_metrics,
                test=test_metrics,
            )
        )

    return CandidateEvaluation(
        name=name,
        model=model,
        budget_evaluations=tuple(evaluations),
    )


def run_fpr_budget_comparison(
    samples: Sequence[DomainSample],
    *,
    fpr_budgets: Sequence[float] = (0.001, 0.01, 0.05, 0.10),
    test_size: float = 0.20,
    validation_size: float = 0.20,
    random_state: int = 42,
    progress_callback: Callable[[str], None] | None = None,
) -> FPRBudgetComparison:
    """Evaluate all predefined candidates on one shared development split."""
    split = split_train_validation_test(
        samples,
        test_size=test_size,
        validation_size=validation_size,
        random_state=random_state,
    )
    candidates = build_candidate_pipelines(random_state=random_state)

    results: list[CandidateEvaluation] = []
    for name, model in candidates.items():
        if progress_callback is not None:
            progress_callback(name)
        results.append(
            evaluate_candidate(
                name,
                model,
                split,
                fpr_budgets=fpr_budgets,
            )
        )

    return FPRBudgetComparison(
        split=split,
        candidates=tuple(results),
    )
