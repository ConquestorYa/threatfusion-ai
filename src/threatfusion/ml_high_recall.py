from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from .ml_dataset import DomainSample
from .ml_split import split_domain_dataset


@dataclass(frozen=True)
class TrainValidationTestSplit:
    train: list[DomainSample]
    validation: list[DomainSample]
    test: list[DomainSample]


@dataclass(frozen=True)
class ThresholdMetrics:
    threshold: float
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


@dataclass(frozen=True)
class RecallTargetEvaluation:
    target_recall: float
    validation: ThresholdMetrics
    test: ThresholdMetrics


@dataclass(frozen=True)
class HighRecallExperiment:
    model: Pipeline
    split: TrainValidationTestSplit
    default_test: ThresholdMetrics
    target_evaluations: tuple[RecallTargetEvaluation, ...]


def build_high_recall_pipeline(random_state: int = 42) -> Pipeline:
    """Build the balanced Logistic Regression candidate."""
    return Pipeline(
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
    )


def split_train_validation_test(
    samples: Iterable[DomainSample],
    *,
    test_size: float = 0.20,
    validation_size: float = 0.20,
    random_state: int = 42,
) -> TrainValidationTestSplit:
    """Create deterministic train/validation/test splits without overlap."""
    if not 0 < validation_size < 1:
        raise ValueError("validation_size must be strictly between 0 and 1")
    if not 0 < test_size < 1:
        raise ValueError("test_size must be strictly between 0 and 1")
    if validation_size + test_size >= 1:
        raise ValueError("validation_size + test_size must be less than 1")

    outer = split_domain_dataset(
        samples,
        test_size=test_size,
        random_state=random_state,
    )
    validation_fraction_of_development = validation_size / (1.0 - test_size)
    inner = split_domain_dataset(
        outer.train,
        test_size=validation_fraction_of_development,
        random_state=random_state + 1,
    )
    return TrainValidationTestSplit(
        train=inner.train,
        validation=inner.test,
        test=outer.test,
    )


def calculate_threshold_metrics(
    labels: Sequence[int],
    probabilities: Sequence[float],
    *,
    threshold: float,
) -> ThresholdMetrics:
    """Calculate binary classification metrics at one fixed threshold."""
    if len(labels) != len(probabilities):
        raise ValueError("labels and probabilities must have the same length")
    if not labels:
        raise ValueError("cannot calculate metrics for empty inputs")
    if set(labels) != {0, 1}:
        raise ValueError("metrics require both binary labels")
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")

    predictions = [1 if probability >= threshold else 0 for probability in probabilities]
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(value) for value in matrix.ravel()
    )
    benign_count = true_negative + false_positive
    false_positive_rate = false_positive / benign_count if benign_count else 0.0

    return ThresholdMetrics(
        threshold=float(threshold),
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        true_positive=true_positive,
        precision=float(precision_score(labels, predictions, zero_division=0)),
        recall=float(recall_score(labels, predictions, zero_division=0)),
        f1=float(f1_score(labels, predictions, zero_division=0)),
        false_positive_rate=float(false_positive_rate),
    )


def select_threshold_for_recall(
    labels: Sequence[int],
    probabilities: Sequence[float],
    *,
    target_recall: float,
) -> ThresholdMetrics:
    """Choose a validation threshold with minimum FPR for a recall target."""
    if not 0 < target_recall <= 1:
        raise ValueError("target_recall must be greater than 0 and at most 1")
    if len(labels) != len(probabilities):
        raise ValueError("labels and probabilities must have the same length")
    if not probabilities:
        raise ValueError("cannot select a threshold from empty inputs")

    candidates = sorted({0.0, 1.0, *(float(value) for value in probabilities)}, reverse=True)
    feasible = [
        calculate_threshold_metrics(labels, probabilities, threshold=threshold)
        for threshold in candidates
    ]
    feasible = [
        metrics
        for metrics in feasible
        if metrics.recall + 1e-12 >= target_recall
    ]
    if not feasible:
        raise ValueError("no threshold satisfies the requested recall target")

    return min(
        feasible,
        key=lambda metrics: (
            metrics.false_positive_rate,
            -metrics.precision,
            -metrics.recall,
            -metrics.threshold,
        ),
    )


def _positive_probabilities(model: Pipeline, samples: list[DomainSample]) -> list[float]:
    probabilities = model.predict_proba([sample.domain for sample in samples])
    classes = list(model.classes_)
    positive_index = classes.index(1)
    return [float(row[positive_index]) for row in probabilities]


def run_high_recall_experiment(
    samples: Iterable[DomainSample],
    *,
    recall_targets: Sequence[float] = (0.80, 0.90, 0.95, 0.99),
    test_size: float = 0.20,
    validation_size: float = 0.20,
    random_state: int = 42,
) -> HighRecallExperiment:
    """Train on train only, tune thresholds on validation, test once."""
    split = split_train_validation_test(
        samples,
        test_size=test_size,
        validation_size=validation_size,
        random_state=random_state,
    )

    model = build_high_recall_pipeline(random_state=random_state)
    model.fit(
        [sample.domain for sample in split.train],
        [sample.label for sample in split.train],
    )

    validation_labels = [sample.label for sample in split.validation]
    validation_probabilities = _positive_probabilities(model, split.validation)
    test_labels = [sample.label for sample in split.test]
    test_probabilities = _positive_probabilities(model, split.test)

    default_test = calculate_threshold_metrics(
        test_labels,
        test_probabilities,
        threshold=0.5,
    )

    evaluations: list[RecallTargetEvaluation] = []
    for target in recall_targets:
        validation_metrics = select_threshold_for_recall(
            validation_labels,
            validation_probabilities,
            target_recall=float(target),
        )
        test_metrics = calculate_threshold_metrics(
            test_labels,
            test_probabilities,
            threshold=validation_metrics.threshold,
        )
        evaluations.append(
            RecallTargetEvaluation(
                target_recall=float(target),
                validation=validation_metrics,
                test=test_metrics,
            )
        )

    return HighRecallExperiment(
        model=model,
        split=split,
        default_test=default_test,
        target_evaluations=tuple(evaluations),
    )
