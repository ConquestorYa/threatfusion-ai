"""Beaconing (rhythm) score: how steadily a device calls one destination.

A transparent formula, not a trained model, so it needs no malware labels. It
follows the shape of RITA's beacon score: timing and size each get a
regularity score built from robust statistics (Bowley skew and median absolute
deviation), plus how much of the observed span the connections cover and how
small the payloads are. Robust statistics tolerate jitter and missed beats,
which plain mean/standard-deviation regularity does not.

One group is (device, destination IP, port, protocol) within a 24-hour window,
internet destinations only (`ml_behavior.scorable`).
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from statistics import median

from .ml_behavior import MIN_CONNECTIONS, WINDOW_SECONDS, Connection, scorable

SMALL_BYTES = 8192  # payloads at or under this count as fully "small"


@dataclass(frozen=True)
class Rhythm:
    originator: str
    responder: str
    port: int | None
    protocol: str
    window_end: float
    connections: int
    first_seen: float
    last_seen: float
    interval: float  # median gap between connections, seconds
    timing: float  # 0..1
    size: float  # 0..1
    score: float  # 0..1


def _quartiles(values: list[float]) -> tuple[float, float, float]:
    ordered = sorted(values)
    n = len(ordered)

    def at(q: float) -> float:
        position = q * (n - 1)
        low = math.floor(position)
        high = min(low + 1, n - 1)
        return ordered[low] + (ordered[high] - ordered[low]) * (position - low)

    return at(0.25), at(0.5), at(0.75)


def regularity(values: list[float]) -> tuple[float, float]:
    """(skew score, dispersion score), each 0..1; 1 = perfectly symmetric and tight."""
    if len(values) < 2:
        return 0.0, 0.0
    q1, q2, q3 = _quartiles(values)
    skew = 0.0 if q3 == q1 else (q3 + q1 - 2 * q2) / (q3 - q1)
    mad = median(abs(v - q2) for v in values)
    dispersion = max(0.0, 1.0 - mad / q2) if q2 > 0 else 0.0
    return 1.0 - abs(skew), dispersion


def score_rows(rows: list[Connection]) -> tuple[float, float, float, float]:
    """(score, timing, size, median interval) for one group's connections."""
    times = sorted({r.timestamp for r in rows})
    gaps = [b - a for a, b in zip(times, times[1:])]
    if len(gaps) < 2:
        return 0.0, 0.0, 0.0, 0.0
    gap = median(gaps)
    span = times[-1] - times[0]
    # Coverage: connections seen versus the number the median gap predicts.
    expected = span / gap + 1 if gap > 0 else len(times)
    coverage = min(1.0, len(times) / expected)
    timing = sum((*regularity(gaps), coverage)) / 3
    sizes = [float(r.out_bytes or 0) for r in rows]
    smallness = max(0.0, 1.0 - median(sizes) / SMALL_BYTES) if sizes else 0.0
    size = sum((*regularity(sizes), smallness)) / 3 if any(sizes) else smallness / 3
    return (timing + size) / 2, timing, size, gap


def rhythms(connections: list[Connection], *, windows: int = 2,
            window_seconds: int = WINDOW_SECONDS) -> list[Rhythm]:
    """Scored groups in consecutive windows ending at the newest connection."""
    usable = [c for c in connections if scorable(c.responder, c.port, c.protocol)]
    if not usable:
        return []
    end = max(c.timestamp for c in usable)
    buckets: dict[tuple, list[Connection]] = defaultdict(list)
    for c in usable:
        index = int((end - c.timestamp) // window_seconds)
        if index < windows:
            buckets[(index, c.originator, c.responder, c.port, c.protocol)].append(c)
    out = []
    for (index, originator, responder, port, protocol), rows in buckets.items():
        if len(rows) < MIN_CONNECTIONS:
            continue
        score, timing, size, gap = score_rows(rows)
        out.append(Rhythm(originator, responder, port, protocol, end - index * window_seconds, len(rows),
                          min(r.timestamp for r in rows), max(r.timestamp for r in rows), gap,
                          timing, size, score))
    return out
