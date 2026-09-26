from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import (
    HybridVerdict,
    MLThresholds,
    assess_dns_domains,
)


THRESHOLDS = MLThresholds(
    high_confidence=0.80,
    medium_confidence=0.60,
    low_confidence=0.50,
)


def test_high_ml_without_independent_signal_is_review() -> None:
    events = [DNSEvent(query_name="popular.example")]

    result = assess_dns_domains(
        events,
        (),
        ml_scores={"popular.example": 0.95},
        ml_thresholds=THRESHOLDS,
    )[0]

    assert result.verdict is HybridVerdict.REVIEW
    assert "ml_high_confidence" in result.reasons
    assert "ml_high_uncorroborated" in result.reasons


def test_high_ml_with_strong_dns_context_is_high_risk() -> None:
    events = [
        DNSEvent(
            query_name="suspicious.example",
            response_code="NXDOMAIN",
        )
    ]

    result = assess_dns_domains(
        events,
        (),
        ml_scores={"suspicious.example": 0.95},
        ml_thresholds=THRESHOLDS,
    )[0]

    assert result.verdict is HybridVerdict.HIGH_RISK
    assert "nxdomain_heavy_responses" in result.reasons
    assert "ml_high_uncorroborated" not in result.reasons
