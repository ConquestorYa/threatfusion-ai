"""Experimental connection-behavior model: how a device talks to one destination.

One group is (device, destination IP, port, protocol) within a 24-hour window.
Features describe timing regularity, sizes, durations, failures, the port and
whether the destination had a (popular) DNS name. No destination address, name
or time of day enters the model, so it cannot memorize a network.

The model is a random forest stored as plain JSON (no pickle) and scored here in
pure Python. It is trained locally (`scripts/lab`) and never shipped in Git: it
is derived from the user's own traffic. A score is a hint for review, never a
verdict, and it does not change the collector's review list.
"""
from __future__ import annotations

import ipaddress
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import median

from .connections import is_local_discovery

MODEL_KIND = "threatfusion-behavior-forest"
SCHEMA_VERSION = 1
WINDOW_SECONDS = 86400
MIN_CONNECTIONS = 4
MAX_MODEL_BYTES = 32 * 1024 * 1024
FAILED_STATES = frozenset({"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"})
WEB_PORTS = frozenset({80, 443, 8080, 8443})

FEATURES = (
    "log_connections", "log_span", "active_hours", "log_interval_median", "interval_cv",
    "interval_regular_share", "interval_mad_ratio", "log_out_bytes_median", "log_in_bytes_median",
    "out_bytes_cv", "in_bytes_cv", "out_bytes_mode_share", "log_duration_median", "duration_cv",
    "failed_share", "empty_share", "log_bytes_ratio", "port_web", "port_dns", "port_low",
    "protocol_udp", "has_name", "popular_name",
)


@dataclass(frozen=True)
class Connection:
    timestamp: float
    originator: str
    responder: str
    port: int | None
    protocol: str
    duration: float | None
    out_bytes: int | None
    in_bytes: int | None
    state: str | None


@dataclass(frozen=True)
class Group:
    originator: str
    responder: str
    port: int | None
    protocol: str
    window_end: float
    connections: int
    first_seen: float
    last_seen: float
    features: dict[str, float]


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return min(10.0, math.sqrt(variance) / mean)


def _log(value: float | None) -> float:
    return math.log1p(max(0.0, float(value or 0.0)))


def scorable(responder: str, port: int | None, protocol: str) -> bool:
    """Only internet destinations: global unicast, not local discovery chatter."""
    try:
        address = ipaddress.ip_address(responder)
    except ValueError:
        return False
    return address.is_global and not is_local_discovery(responder, port, protocol)


def group_features(rows: list[Connection], *, named: bool, popular: bool) -> dict[str, float]:
    rows = sorted(rows, key=lambda r: r.timestamp)
    times = [r.timestamp for r in rows]
    gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
    gap_median = median(gaps) if gaps else 0.0
    tolerance = max(2.0, 0.2 * gap_median)
    out_bytes = [float(r.out_bytes or 0) for r in rows]
    in_bytes = [float(r.in_bytes or 0) for r in rows]
    durations = [float(r.duration or 0) for r in rows]
    port, protocol = rows[0].port, rows[0].protocol
    mode_count = Counter(out_bytes).most_common(1)[0][1]
    return {
        "log_connections": _log(len(rows)),
        "log_span": _log(times[-1] - times[0]),
        "active_hours": len({int(t // 3600) for t in times}) / 24.0,
        "log_interval_median": _log(gap_median),
        "interval_cv": _cv(gaps),
        "interval_regular_share": (sum(abs(g - gap_median) <= tolerance for g in gaps) / len(gaps)) if gaps else 0.0,
        "interval_mad_ratio": (min(10.0, median(abs(g - gap_median) for g in gaps) / gap_median)
                               if gaps and gap_median > 0 else 0.0),
        "log_out_bytes_median": _log(median(out_bytes)),
        "log_in_bytes_median": _log(median(in_bytes)),
        "out_bytes_cv": _cv(out_bytes),
        "in_bytes_cv": _cv(in_bytes),
        "out_bytes_mode_share": mode_count / len(rows),
        "log_duration_median": _log(median(durations)),
        "duration_cv": _cv(durations),
        "failed_share": sum((r.state or "") in FAILED_STATES for r in rows) / len(rows),
        "empty_share": sum(not r.out_bytes and not r.in_bytes for r in rows) / len(rows),
        "log_bytes_ratio": max(-10.0, min(10.0, _log(median(out_bytes)) - _log(median(in_bytes)))),
        "port_web": float(port in WEB_PORTS),
        "port_dns": float(port in (53, 853)),
        "port_low": float(port is not None and port < 1024),
        "protocol_udp": float(protocol == "udp"),
        "has_name": float(named),
        "popular_name": float(popular),
    }


def build_groups(connections: list[Connection], names: dict[str, set[str]], is_popular_name, *,
                 windows: int = 2, window_seconds: int = WINDOW_SECONDS) -> list[Group]:
    """Groups in consecutive windows ending at the newest connection (newest first)."""
    usable = [c for c in connections if scorable(c.responder, c.port, c.protocol)]
    if not usable:
        return []
    end = max(c.timestamp for c in usable)
    buckets: dict[tuple, list[Connection]] = defaultdict(list)
    for c in usable:
        index = int((end - c.timestamp) // window_seconds)
        if index < windows:
            buckets[(index, c.originator, c.responder, c.port, c.protocol)].append(c)
    groups = []
    for (index, originator, responder, port, protocol), rows in buckets.items():
        if len(rows) < MIN_CONNECTIONS:
            continue
        responder_names = names.get(responder, set())
        features = group_features(rows, named=bool(responder_names),
                                  popular=any(is_popular_name(n) for n in responder_names))
        groups.append(Group(originator, responder, port, protocol, end - index * window_seconds, len(rows),
                            min(r.timestamp for r in rows), max(r.timestamp for r in rows), features))
    return groups


class BehaviorModel:
    """A JSON random forest; `score` is the mean malicious-class share of its trees."""

    def __init__(self, payload: dict):
        if payload.get("kind") != MODEL_KIND or payload.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Not a ThreatFusion behavior model")
        if tuple(payload.get("features", ())) != FEATURES:
            raise ValueError("Behavior model features do not match this version")
        self.trees = payload["trees"]
        self.threshold = float(payload["threshold"])
        self.evaluation = payload.get("evaluation", {})
        self.trained_at = payload.get("trained_at")
        self.model_id = payload.get("model_id")
        for tree in self.trees:
            sizes = {len(tree[k]) for k in ("left", "right", "feature", "threshold", "value")}
            if len(sizes) != 1:
                raise ValueError("Malformed behavior model tree")

    @classmethod
    def load(cls, path: Path) -> BehaviorModel:
        raw = Path(path).read_bytes()
        if len(raw) > MAX_MODEL_BYTES:
            raise ValueError("Behavior model file is too large")
        return cls(json.loads(raw))

    def score(self, features: dict[str, float]) -> float:
        vector = [float(features[name]) for name in FEATURES]
        total = 0.0
        for tree in self.trees:
            node = 0
            while tree["left"][node] >= 0:
                node = tree["left"][node] if vector[tree["feature"][node]] <= tree["threshold"][node] else tree["right"][node]
            total += tree["value"][node]
        return total / len(self.trees)


def forest_payload(forest, threshold: float, *, model_id: str, trained_at: str, evaluation: dict) -> dict:
    """Export a fitted scikit-learn RandomForestClassifier (classes 0/1) as plain JSON."""
    trees = []
    for estimator in forest.estimators_:
        tree = estimator.tree_
        values = tree.value[:, 0, :]
        shares = (values[:, 1] / values.sum(axis=1)).tolist()
        trees.append({"left": tree.children_left.tolist(), "right": tree.children_right.tolist(),
                      "feature": [max(0, int(f)) for f in tree.feature], "threshold": [float(t) for t in tree.threshold],
                      "value": [round(v, 6) for v in shares]})
    return {"kind": MODEL_KIND, "schema_version": SCHEMA_VERSION, "features": list(FEATURES),
            "model_id": model_id, "trained_at": trained_at, "threshold": threshold,
            "evaluation": evaluation, "trees": trees}


def reasons(features: dict[str, float]) -> list[str]:
    """Plain-language reason keys (translated in the UI); facts about the group, not the model."""
    found = []
    if features["interval_regular_share"] >= 0.6 and features["log_connections"] >= math.log1p(8):
        found.append("regular")
    if features["out_bytes_mode_share"] >= 0.6 and features["log_connections"] >= math.log1p(8):
        found.append("same_size")
    if features["active_hours"] >= 0.5:
        found.append("all_day")
    if not features["has_name"]:
        found.append("no_name")
    elif not features["popular_name"]:
        found.append("rare_name")
    if features["failed_share"] >= 0.5:
        found.append("failing")
    if not features["port_web"] and not features["port_dns"]:
        found.append("unusual_port")
    if features["log_out_bytes_median"] <= math.log1p(300) and features["log_connections"] >= math.log1p(8):
        found.append("small")
    return found
