import hashlib
import json

import pytest

from scripts.lab import cached_workload, periodic_scenario
from scripts.lab.evaluate_connection_controls import evaluate


def test_cached_workload_freezes_jitter_cache_and_persistence_plan(tmp_path, monkeypatch):
    monkeypatch.setattr(periodic_scenario.time, "time", lambda: 1791072000)
    manifest = cached_workload.plan()
    assert manifest == cached_workload.plan()
    assert manifest["protocol"] == "cached-http-controls-v1"
    assert manifest["dns_cache_ttl_seconds"] > manifest["represented_window_seconds"]
    assert manifest["http_persistence"] == {"browser": True, "updater": False, "heartbeat": False}
    assert manifest["event_counts"] == {"browser": 18, "updater": 30, "heartbeat": 30}
    assert len({(e["role"], e["domain"]) for e in manifest["events"]}) == 5
    assert all(e["path"].endswith(".txt") for e in manifest["events"])
    path = tmp_path / "manifest.json"
    cached_workload.write_plan(path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == path.with_suffix(".sha256").read_text().strip()
    with pytest.raises(FileExistsError):
        cached_workload.write_plan(path)


def test_connection_controls_measure_benign_review_load_without_accuracy_claim(tmp_path):
    output = tmp_path / "controls"
    result = evaluate(output)
    assert result["cases"] == 33
    assert result["benign_groups"] == 33 and result["benign_review_groups"] == 9
    assert result["simulated_groups"] == result["simulated_review_groups"] == 3
    assert "fpr" not in result and "recall" not in result
    manifest = json.loads((output / "manifest.json").read_text())
    for case in manifest["cases"]:
        assert hashlib.sha256((output / case["input"]).read_bytes()).hexdigest() == case["sha256"]
    original = (output / "summary.json").read_bytes()
    with pytest.raises(FileExistsError):
        evaluate(output)
    assert (output / "summary.json").read_bytes() == original
