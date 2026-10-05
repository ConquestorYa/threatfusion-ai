import hashlib
import json
from pathlib import Path

import pytest

from scripts.lab.evaluate_device_controls import SEEDS, controls, evaluate


def test_control_protocol_reproduces_inputs_and_records_coverage_expectations(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    result = evaluate(first)
    assert result["passed"] == result["cases"] == 24
    evaluate(second)
    assert (first / "manifest.json").read_bytes() == (second / "manifest.json").read_bytes()
    manifest = json.loads((first / "manifest.json").read_text())
    assert manifest["ml_enabled"] is False
    assert manifest["cti_mode"] == "reserved_synthetic_fixtures_only"
    for case in manifest["cases"]:
        assert hashlib.sha256((first / case["input"]).read_bytes()).hexdigest() == case["sha256"]
    original = (first / "summary.json").read_bytes()
    with pytest.raises(FileExistsError):
        evaluate(first)
    assert (first / "summary.json").read_bytes() == original


def test_evaluation_output_is_refused_inside_repository():
    with pytest.raises(ValueError, match="outside"):
        evaluate(Path(__file__).resolve().parents[1] / "data" / "refused-control-output")


def test_benign_and_simulated_periodic_controls_have_identical_inputs_except_domain():
    for seed in SEEDS:
        cases, _ = controls(seed)
        by_name = {case["name"]: case for case in cases}
        benign = by_name["legitimate_updates"]
        simulation = by_name["heartbeat_simulation"]
        assert benign["intent"] != simulation["intent"]
        assert benign["expected_priorities"] == simulation["expected_priorities"]
        assert [e.timestamp for e in benign["events"]] == [e.timestamp for e in simulation["events"]]
        assert [e.response_ip for e in benign["events"]] == [e.response_ip for e in simulation["events"]]
