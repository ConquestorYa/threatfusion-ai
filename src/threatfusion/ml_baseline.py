from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline

from .ml_dataset import DomainSample
from .ml_split import DomainDatasetSplit, split_domain_dataset


@dataclass(frozen=True)
class BaselineMetrics:
    train_count: int
    test_count: int
    train_malicious_count: int
    train_benign_count: int
    test_malicious_count: int
    test_benign_count: int
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


@dataclass(frozen=True)
class BaselineExperiment:
    model: Pipeline
    split: DomainDatasetSplit
    metrics: BaselineMetrics


def build_baseline_pipeline(random_state: int = 42) -> Pipeline:
    """Build the first explainable/reproducible malicious-domain baseline."""
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
                    max_iter=1000,
                    random_state=random_state,
                ),
            ),
        ]
    )


def _count_label(samples: list[DomainSample], label: int) -> int:
    return sum(sample.label == label for sample in samples)


def run_baseline_experiment(
    samples: Iterable[DomainSample],
    *,
    test_size: float = 0.20,
    random_state: int = 42,
) -> BaselineExperiment:
    """Train and evaluate the baseline on the existing development split.

    The TF-IDF vectorizer is fitted only after the train/test split, so test
    domains do not influence the learned vocabulary or IDF statistics.
    """
    split = split_domain_dataset(
        samples,
        test_size=test_size,
        random_state=random_state,
    )

    train_domains = [sample.domain for sample in split.train]
    train_labels = [sample.label for sample in split.train]
    test_domains = [sample.domain for sample in split.test]
    test_labels = [sample.label for sample in split.test]

    model = build_baseline_pipeline(random_state=random_state)
    model.fit(train_domains, train_labels)
    predictions = model.predict(test_domains)

    matrix = confusion_matrix(test_labels, predictions, labels=[0, 1])
    true_negative, false_positive, false_negative, true_positive = (
        int(value) for value in matrix.ravel()
    )

    benign_test_count = true_negative + false_positive
    false_positive_rate = (
        false_positive / benign_test_count if benign_test_count else 0.0
    )

    metrics = BaselineMetrics(
        train_count=len(split.train),
        test_count=len(split.test),
        train_malicious_count=_count_label(split.train, 1),
        train_benign_count=_count_label(split.train, 0),
        test_malicious_count=_count_label(split.test, 1),
        test_benign_count=_count_label(split.test, 0),
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        true_positive=true_positive,
        precision=float(precision_score(test_labels, predictions, zero_division=0)),
        recall=float(recall_score(test_labels, predictions, zero_division=0)),
        f1=float(f1_score(test_labels, predictions, zero_division=0)),
        false_positive_rate=float(false_positive_rate),
    )

    return BaselineExperiment(model=model, split=split, metrics=metrics)
