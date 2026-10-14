from __future__ import annotations

import random

from threatfusion import ml_behavior as mb
from threatfusion import rhythm


def _beacon(period=300.0, jitter=0.0, count=60, size=200, seed=1, drop=0.0):
    rng = random.Random(seed)
    rows, t = [], 1_000_000.0
    for _ in range(count):
        if rng.random() >= drop:
            rows.append(mb.Connection(t, "10.0.0.2", "1.1.1.1", 443, "tcp", 0.2, size, 900, "SF"))
        t += period * (1 + rng.uniform(-jitter, jitter))
    return rows


def _browsing(count=60, seed=2):
    rng = random.Random(seed)
    rows, t = [], 1_000_000.0
    for _ in range(count):
        t += rng.expovariate(1 / 600) * rng.choice([0.05, 1, 1, 8])
        rows.append(mb.Connection(t, "10.0.0.2", "1.1.1.1", 443, "tcp", 3.0, rng.randint(400, 90000),
                                  rng.randint(1000, 900000), "SF"))
    return rows


def test_regular_beacons_score_high_and_browsing_low():
    steady = rhythm.score_rows(_beacon())
    assert steady[0] > 0.9 and steady[3] == 300.0
    assert rhythm.score_rows(_browsing())[0] < 0.6


def test_jitter_and_missed_beats_lower_the_score_gently():
    clean = rhythm.score_rows(_beacon())[0]
    jittered = rhythm.score_rows(_beacon(jitter=0.3))[0]
    gappy = rhythm.score_rows(_beacon(drop=0.2))[0]
    assert clean > jittered > rhythm.score_rows(_browsing())[0]
    assert gappy > 0.7


def test_regularity_handles_degenerate_input():
    assert rhythm.regularity([5.0]) == (0.0, 0.0)
    assert rhythm.regularity([0.0, 0.0, 0.0]) == (1.0, 0.0)
    assert rhythm.score_rows(_beacon(count=2)) == (0.0, 0.0, 0.0, 0.0)


def test_rhythms_group_internet_destinations_per_window():
    rows = _beacon() + [mb.Connection(1_000_000.0 + i, "10.0.0.2", "192.168.1.1", 443, "tcp", 0, 1, 1, "SF")
                        for i in range(10)]
    found, = rhythm.rhythms(rows)
    assert (found.responder, found.connections) == ("1.1.1.1", 60) and found.score > 0.9
