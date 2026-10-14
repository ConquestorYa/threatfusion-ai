from __future__ import annotations

import os
import stat

from threatfusion import ml_behavior as mb
from threatfusion.baseline import LEARNING_DAYS, Baseline, destination_keys, simple_registrable

DAY = 86400


def _c(day, responder, device="10.0.0.2", offset=0):
    return mb.Connection(day * DAY + offset, device, responder, 443, "tcp", 0.1, 100, 100, "SF")


def test_destinations_are_new_only_after_the_learning_period():
    b = Baseline()
    names = {"1.1.1.1": {"www.example.com"}, "2.2.2.2": {"cdn.example.com"}}
    b.update([_c(d, "1.1.1.1") for d in range(LEARNING_DAYS)], names)
    keys = destination_keys("2.2.2.2", names["2.2.2.2"], simple_registrable)
    assert keys == {"d:example.com"}
    b.update([_c(LEARNING_DAYS, "2.2.2.2"), _c(LEARNING_DAYS, "3.3.3.3")], names)
    # Same registrable domain as a known one: not new. An unnamed fresh IP: new.
    assert not b.is_new("10.0.0.2", keys, LEARNING_DAYS)
    assert b.is_new("10.0.0.2", {"ip:3.3.3.3"}, LEARNING_DAYS)
    # During learning nothing is new.
    fresh = Baseline()
    fresh.update([_c(0, "4.4.4.4", device="10.0.0.9")], {})
    assert not fresh.is_new("10.0.0.9", {"ip:4.4.4.4"}, 0)


def test_memory_survives_address_changes_of_the_same_computer():
    b = Baseline()
    # Three days at home (one address), then the laptop joins another network (new address).
    b.update([_c(d, "1.1.1.1", device="192.168.1.20") for d in range(3)], {})
    b.update([_c(3, "1.1.1.1", device="10.40.7.88"), _c(3, "5.5.5.5", device="10.40.7.88")], {})
    assert not b.learning("10.40.7.88", 3)
    assert not b.is_new("10.40.7.88", {"ip:1.1.1.1"}, 3)
    assert b.is_new("10.40.7.88", {"ip:5.5.5.5"}, 3)


def test_updates_are_idempotent_and_skip_local_destinations():
    b = Baseline()
    rows = [_c(5, "1.1.1.1"), _c(5, "192.168.1.1"), _c(6, "1.1.1.1")]
    b.update(rows, {})
    b.update(rows, {})
    device = b.devices["10.0.0.2"]
    assert device["days"] == [5, 6] and device["seen"] == {"ip:1.1.1.1": [5, 6]}


def test_baseline_file_is_private_and_survives_bad_input(tmp_path):
    path = tmp_path / "ml" / "baseline.json"
    b = Baseline()
    b.update([_c(1, "1.1.1.1")], {})
    b.save(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert Baseline.load(path).devices == b.devices
    path.write_text("not json")
    assert Baseline.load(path).devices == {}
