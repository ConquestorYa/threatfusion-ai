from __future__ import annotations

from dataclasses import dataclass

from .ml_dataset import DomainSample
from .ml_fpr_comparison import FPRBudgetComparison


@dataclass(frozen=True)
class SourceRecall:
    source: str
    total: int
    detected: int
    missed: int
    recall: float


@dataclass(frozen=True)
class SourceBudgetDiagnostic:
    max_false_positive_rate: float
    threshold: float
    sources: tuple[SourceRecall, ...]


@dataclass(frozen=True)
class CandidateSourceDiagnostic:
    name: str
    budgets: tuple[SourceBudgetDiagnostic, ...]


@dataclass(frozen=True)
class SourceDiagnosticReport:
    candidates: tuple[CandidateSourceDiagnostic, ...]


def calculate_source_recall(
    samples: list[DomainSample],
    predictions: list[int],
) -> tuple[SourceRecall, ...]:
    """Calculate malicious recall separately for each retained sample source."""
    if len(samples) != len(predictions):
        raise ValueError("samples and predictions must have the same length")
    if any(prediction not in {0, 1} for prediction in predictions):
        raise ValueError("predictions must contain only 0 or 1")

    totals: dict[str, int] = {}
    detected: dict[str, int] = {}

    for sample, prediction in zip(samples, predictions, strict=True):
        if sample.label != 1:
            continue
        totals[sample.source] = totals.get(sample.source, 0) + 1
        if prediction == 1:
            detected[sample.source] = detected.get(sample.source, 0) + 1

    return tuple(
        SourceRecall(
            source=source,
            total=totals[source],
            detected=detected.get(source, 0),
            missed=totals[source] - detected.get(source, 0),
            recall=detected.get(source, 0) / totals[source],
        )
        for source in sorted(totals)
    )


def _positive_probabilities(model, samples: list[DomainSample]) -> list[float]:
    probabilities = model.predict_proba([sample.domain for sample in samples])
    classes = list(model.classes_)
    positive_index = classes.index(1)
    return [float(row[positive_index]) for row in probabilities]


def build_source_diagnostic_report(
    comparison: FPRBudgetComparison,
) -> SourceDiagnosticReport:
    """Break development-test malicious recall down by retained CTI source."""
    test_samples = comparison.split.test
    candidate_reports: list[CandidateSourceDiagnostic] = []

    for candidate in comparison.candidates:
        probabilities = _positive_probabilities(candidate.model, test_samples)
        budget_reports: list[SourceBudgetDiagnostic] = []

        for evaluation in candidate.budget_evaluations:
            threshold = evaluation.validation.threshold
            predictions = [
                1 if probability >= threshold else 0
                for probability in probabilities
            ]
            budget_reports.append(
                SourceBudgetDiagnostic(
                    max_false_positive_rate=evaluation.max_false_positive_rate,
                    threshold=threshold,
                    sources=calculate_source_recall(test_samples, predictions),
                )
            )

        candidate_reports.append(
            CandidateSourceDiagnostic(
                name=candidate.name,
                budgets=tuple(budget_reports),
            )
        )

    return SourceDiagnosticReport(candidates=tuple(candidate_reports))
