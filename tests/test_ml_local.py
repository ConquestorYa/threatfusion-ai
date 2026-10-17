from __future__ import annotations

import json
import os

import numpy as np
import pytest

from threatfusion import ml_behavior as mb
from threatfusion import ml_local

DAY = 86400


def _beacon(day, responder="1.1.1.1", period=600, size=300):
    return [mb.Connection(day * DAY + 60 + i * period, "192.0.2.10", responder, 443, "tcp", 0.2, size, size * 2, "SF")
            for i in range(20)]


def _pack(rows=200, seed=1):
    rng = np.random.default_rng(seed)
    malicious = rng.normal(0.8, 0.1, (rows, len(mb.FEATURES)))
    normal = rng.normal(0.2, 0.1, (rows, len(mb.FEATURES)))
    dev = rng.normal(0.2, 0.1, (40, len(mb.FEATURES)))
    return {"x": np.vstack([malicious, normal, dev]).astype(np.float32),
            "y": np.array([1] * rows + [0] * rows + [0] * 40, dtype=np.int8),
            "unit": np.array([i % 5 for i in range(rows)] + [5 + i % 3 for i in range(rows)] + [9] * 40, dtype=np.int32),
            "part": np.array(["train"] * (2 * rows) + ["normal_dev"] * 40),
            "unit_day": np.array([-1] * (2 * rows) + [i % 4 for i in range(40)], dtype=np.int32)}


def test_one_non_overlapping_sample_per_day_even_when_the_window_is_short(tmp_path):
    days = ml_local.LocalDays({})
    nothing = lambda name: False  # noqa: E731
    # Five hours of records: too short for a sample.
    assert not days.update(_beacon(100, period=900), {}, nothing)
    # The collector's record cap kept only ten hours: still one sample.
    ten_hours = [c for c in _beacon(101, period=1800) if c.timestamp < 101 * DAY + 36000]
    assert days.update(ten_hours, {}, nothing) and list(days.days) == ["101"] and len(days.days["101"]) == 1
    # Later the same day, and the next morning: too close to the previous sample.
    assert not days.update(ten_hours + _beacon(101, responder="1.0.0.1", period=1800), {}, nothing)
    assert not days.update([mb.Connection(101 * DAY + 36000 + 4 * 3600 + i, "192.0.2.10", "1.1.1.1", 443, "tcp",
                                          0.1, 1, 1, "SF") for i in range(5)], {}, nothing)
    later = _beacon(102, period=1800)
    assert days.update(later, {}, nothing) and sorted(days.days) == ["101", "102"]
    for day in range(200, 200 + ml_local.KEEP_DAYS + 2):
        days.days[str(day)] = []
    days.update(_beacon(300, period=1800), {}, nothing)
    assert len(days.days) == ml_local.KEEP_DAYS and "101" not in days.days


def test_local_days_file_is_private_and_bad_files_start_over(tmp_path):
    path = tmp_path / "ml" / "local-days.json"
    days = ml_local.LocalDays({"5": [[0.0] * len(mb.FEATURES)]})
    days.save(path)
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert ml_local.LocalDays.load(path).days == days.days
    path.write_text(json.dumps({"schema": 1, "features": ["other"], "days": {"5": []}}))
    assert ml_local.LocalDays.load(path).days == {}
    path.write_text("not json")
    assert ml_local.LocalDays.load(path).days == {}


def test_alarm_line_keeps_every_benign_set_within_one_flag_per_day():
    benign = [([0.9, 0.8, 0.1, 0.1], ["a", "a", "b", "b"]), ([0.95, 0.2], ["c", "d"])]
    line = ml_local.alarm_line(benign)
    assert all(ml_local.flags_per_day(s, d, line) <= 1 for s, d in benign)
    assert line == pytest.approx(0.2)


def test_training_needs_three_days_and_learns_this_computer_as_normal(tmp_path):
    local = ml_local.LocalDays({"1": [[0.2] * len(mb.FEATURES)] * 5, "2": [[0.25] * len(mb.FEATURES)] * 5})
    with pytest.raises(ValueError):
        ml_local.train(_pack(), local, jobs=1)
    local.days["3"] = [[0.22] * len(mb.FEATURES)] * 5
    payload = ml_local.train(_pack(), local, jobs=1)
    model = mb.BehaviorModel(payload)
    assert payload["evaluation"]["local_days"] == 3 and payload["evaluation"]["newest_day"] == "3"
    assert model.score(dict(zip(mb.FEATURES, [0.8] * len(mb.FEATURES)))) >= model.threshold
    assert model.score(dict(zip(mb.FEATURES, [0.22] * len(mb.FEATURES)))) < model.threshold


def test_retraining_waits_for_a_newer_day(tmp_path, monkeypatch):
    pack = tmp_path / "pack.npz"
    np.savez_compressed(pack, **_pack())
    monkeypatch.setattr(ml_local, "PUBLIC_FEATURES", pack)
    local = ml_local.LocalDays({str(d): [[0.2] * len(mb.FEATURES)] for d in (1, 2)})
    assert not ml_local.due(tmp_path, local, now=0)
    local.days["3"] = [[0.2] * len(mb.FEATURES)]
    assert ml_local.due(tmp_path, local, now=0)
    ml_local.save_model(ml_local.train(ml_local.load_public_features(pack), local, jobs=1), tmp_path / ml_local.MODEL_FILE)
    modified = (tmp_path / ml_local.MODEL_FILE).stat().st_mtime
    assert not ml_local.due(tmp_path, local, now=modified + 2 * DAY)
    local.days["4"] = [[0.2] * len(mb.FEATURES)]
    assert not ml_local.due(tmp_path, local, now=modified + 60)
    assert ml_local.due(tmp_path, local, now=modified + 2 * DAY)
