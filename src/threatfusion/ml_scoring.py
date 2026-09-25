from __future__ import annotations

import re
from dataclasses import dataclass

from .ml_dataset import normalize_domain_candidate


@dataclass(frozen=True)
class MLScoringEligibility:
    eligible: bool
    normalized_domain: str | None
    reason: str | None


_LABEL_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_NON_PUBLIC_SUFFIXES = (
    ".arpa",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
)


def evaluate_ml_scoring_eligibility(value: str) -> MLScoringEligibility:
    """Decide whether a DNS query is suitable for the public-domain ML model.

    Known-IOC matching and DNS behavior analysis remain independent of this
    decision. The gate only prevents the domain-string classifier from scoring
    names that are clearly outside its public Internet-domain training scope.
    """
    normalized = normalize_domain_candidate(value)
    if normalized is None:
        return MLScoringEligibility(False, None, "invalid_domain")

    try:
        ascii_domain = normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return MLScoringEligibility(False, normalized, "invalid_domain")

    labels = ascii_domain.split(".")
    if len(labels) < 2:
        return MLScoringEligibility(False, normalized, "single_label")

    lowered = ascii_domain.casefold()
    if lowered.endswith(_NON_PUBLIC_SUFFIXES):
        return MLScoringEligibility(False, normalized, "non_public_suffix")

    if any(label.startswith("_") for label in labels):
        return MLScoringEligibility(False, normalized, "service_discovery")

    if len(ascii_domain) > 253 or any(
        not label or not _LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        return MLScoringEligibility(False, normalized, "invalid_public_domain")

    return MLScoringEligibility(True, normalized, None)
