from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import MLThresholds
from threatfusion.ml_benign_telemetry import (
    build_benign_telemetry_report,
    evaluate_benign_telemetry,
    prepare_benign_telemetry,
    write_benign_telemetry_report,
)
from threatfusion.ml_dataset import DomainSample


class FakeProbabilityModel:
    classes_ = [0, 1]

    def __init__(self, scores: dict[str, float]) -> None:
        self.scores = scores

    def predict_proba(self, domains: list[str]) -> list[list[float]]:
        return [
            [1.0 - self.scores[domain], self.scores[domain]]
            for domain in domains
        ]


def artifact(scores: dict[str, float]):
    return SimpleNamespace(
        model=FakeProbabilityModel(scores),
        thresholds=MLThresholds(
            high_confidence=0.80,
            medium_confidence=0.60,
            low_confidence=0.50,
        ),
    )


def test_prepare_benign_telemetry_deduplicates_and_removes_development_overlap() -> None:
    development = [
        DomainSample("seen.example", 0, "Tranco"),
        DomainSample("legacy-single-label", 1, "ThreatFox"),
    ]
    events = [
        DNSEvent(query_name="Seen.Example."),
        DNSEvent(query_name="new-one.example"),
        DNSEvent(query_name="NEW-ONE.EXAMPLE."),
        DNSEvent(query_name="printer.local"),
        DNSEvent(query_name="not a valid domain"),
    ]

    prepared = prepare_benign_telemetry(events, development)

    assert prepared.input_event_count == 5
    assert prepared.public_candidate_event_count == 3
    assert prepared.unique_candidate_count == 2
    assert prepared.development_overlap_removed == 1
    assert prepared.retained_domains == ("new-one.example",)


def test_prepare_benign_telemetry_requires_retained_public_domains() -> None:
    with pytest.raises(ValueError, match="no retained public domains"):
        prepare_benign_telemetry(
            [DNSEvent(query_name="seen.example")],
            [DomainSample("seen.example", 0, "Tranco")],
        )


def test_evaluate_benign_telemetry_uses_frozen_thresholds() -> None:
    model = artifact(
        {
            "good-one.example": 0.90,
            "good-two.example": 0.65,
            "good-three.example": 0.20,
        }
    )
    events = [
        DNSEvent(query_name="good-one.example"),
        DNSEvent(query_name="good-two.example"),
        DNSEvent(query_name="good-three.example"),
    ]

    result = evaluate_benign_telemetry(model, [], events)

    assert result.high.threshold == pytest.approx(0.80)
    assert result.high.false_positive_count == 1
    assert result.high.false_positive_rate == pytest.approx(1 / 3)
    assert result.medium.false_positive_count == 2
    assert result.medium.false_positive_rate == pytest.approx(2 / 3)
    assert result.low.false_positive_count == 2
    assert result.low.false_positive_rate == pytest.approx(2 / 3)

    interval = result.high.false_positive_rate_ci
    assert 0.0 <= interval.lower < result.high.false_positive_rate
    assert result.high.false_positive_rate < interval.upper <= 1.0


def test_aggregate_report_contains_no_domain_rows(tmp_path) -> None:
    model = artifact(
        {
            "private-good-one.example": 0.90,
            "private-good-two.example": 0.20,
        }
    )
    result = evaluate_benign_telemetry(
        model,
        [],
        [
            DNSEvent(query_name="private-good-one.example"),
            DNSEvent(query_name="private-good-two.example"),
        ],
    )
    report = build_benign_telemetry_report(
        result,
        model_name="test-model",
        artifact_checksum="a" * 64,
        input_format="generic_dns_csv",
    )

    path = write_benign_telemetry_report(
        report,
        tmp_path / "evaluation" / "benign_dns.json",
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    serialized = json.dumps(payload)

    assert payload["protocol"] == "confirmed_benign_dns_telemetry"
    assert payload["label_basis"] == "operator_confirmed_benign"
    assert payload["retained_benign_count"] == 2
    assert "private-good-one.example" not in serialized
    assert "private-good-two.example" not in serialized


def test_report_refuses_overwrite_by_default(tmp_path) -> None:
    model = artifact({"good.example": 0.10})
    result = evaluate_benign_telemetry(
        model,
        [],
        [DNSEvent(query_name="good.example")],
    )
    report = build_benign_telemetry_report(
        result,
        model_name="test-model",
        artifact_checksum="b" * 64,
        input_format="zeek_dns_log",
    )
    path = tmp_path / "benign_dns.json"

    write_benign_telemetry_report(report, path)

    with pytest.raises(FileExistsError, match="already exists"):
        write_benign_telemetry_report(report, path)
