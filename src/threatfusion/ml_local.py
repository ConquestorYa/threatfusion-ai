"""Behavior model trained on this computer: public malware features plus its own days.

Public research recordings teach what malware connections look like, but not what
a real computer's normal traffic looks like: a line set on lab normal recordings
flagged 2.25 times per day on a real laptop, and a line raised on one real day
then caught almost nothing (ml-behavior-public-v1). The measured recipe that
worked learned from the computer's own days (ml-behavior-dev-v2), so the forest is
trained here, never shipped:

- the installer ships numeric features of public recordings (`models/
  behavior-public-features.npz`: CTU-SME-11, Stratosphere MCFP and
  Malware-Traffic-Analysis.net; no addresses, names or times);
- about once a day the app keeps the connection groups of the collector's
  newest 24 h window (shorter when the collector's record cap trimmed it), never
  overlapping the previous sample (`<install>/ml/local-days.json`, 0600;
  features only, never uploaded);
- once LEARNING_DAYS days exist, the forest is trained on the public rows plus
  every local day except the newest (assumed normal), and its alarm line is the
  lowest score that flags at most one group per day on the newest local day and
  on public normal held-out host-days.

A computer that is already infected teaches the model that its malware is normal;
the threat-list checks and What to check are unaffected by this model.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .ml_behavior import FEATURES, WINDOW_SECONDS, Connection, build_groups, forest_payload

PUBLIC_FEATURES = Path(__file__).parent / "models" / "behavior-public-features.npz"
# How this recipe measured in the lab (ml-behavior-local-v1); shown on the Model evaluation page.
RECIPE_EVALUATION = Path(__file__).parent / "models" / "behavior-local-evaluation.json"
DAYS_FILE = Path("ml") / "local-days.json"
MODEL_FILE = Path("ml") / "behavior-model.json"
SCHEMA = 1
LEARNING_DAYS = 3
KEEP_DAYS = 14
MAX_GROUPS_PER_DAY = 5000
MIN_SPAN_SECONDS = 6 * 3600
MIN_GAP_SECONDS = 20 * 3600
LOCAL_WEIGHT = 3.0
FLAG_LIMIT_PER_DAY = 1.0
RETRAIN_SECONDS = 86400
FOREST = {"n_estimators": 150, "min_samples_leaf": 5, "max_depth": 24, "max_features": "sqrt"}
SEED = 20261014


def _day(timestamp: float) -> int:
    return int(timestamp // WINDOW_SECONDS)


def window_groups(connections: list[Connection], names: dict[str, set[str]],
                  popular: Callable[[str], bool], after: float) -> list[list[float]]:
    """Feature vectors of every group in the newest 24 h window, using only connections after `after`."""
    rows = [c for c in connections if c.timestamp > after]
    if not rows:
        return []
    return [[float(g.features[f]) for f in FEATURES] for g in build_groups(rows, names, popular, windows=1)]


@dataclass
class LocalDays:
    days: dict[str, list[list[float]]]
    newest: float = 0.0

    @classmethod
    def load(cls, path: Path) -> LocalDays:
        try:
            data = json.loads(Path(path).read_text())
            if data.get("schema") != SCHEMA or data.get("features") != list(FEATURES):
                return cls({})
            return cls({str(k): v for k, v in data["days"].items()}, float(data.get("newest", 0.0)))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return cls({})

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".local-days-")
        try:
            with os.fdopen(handle, "w") as output:
                json.dump({"schema": SCHEMA, "features": list(FEATURES), "days": self.days,
                           "newest": self.newest}, output, separators=(",", ":"))
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def update(self, connections: list[Connection], names: dict[str, set[str]],
               popular: Callable[[str], bool]) -> bool:
        """Keep one sample of the newest window per day; True when something changed.

        A sample needs at least MIN_SPAN_SECONDS of records after the previous
        sample, and MIN_GAP_SECONDS since it, so samples never overlap.
        """
        if not connections:
            return False
        newest = max(c.timestamp for c in connections)
        after = max(self.newest, newest - WINDOW_SECONDS)
        span = newest - max(after, min(c.timestamp for c in connections))
        changed = False
        if newest - self.newest >= MIN_GAP_SECONDS and span >= MIN_SPAN_SECONDS and str(_day(newest)) not in self.days:
            self.days[str(_day(newest))] = window_groups(connections, names, popular, after)[:MAX_GROUPS_PER_DAY]
            self.newest = newest
            changed = True
        for old in sorted(self.days, key=int)[:-KEEP_DAYS]:
            del self.days[old]
            changed = True
        return changed

    def ready(self) -> bool:
        return len(self.days) >= LEARNING_DAYS


def load_public_features(path: Path = PUBLIC_FEATURES) -> dict:
    """Public training rows: x, y, unit (weighting group), part ('train' or 'normal_dev'), unit_day."""
    import numpy as np
    with np.load(path, allow_pickle=False) as data:
        pack = {k: data[k] for k in ("x", "y", "unit", "part", "unit_day")}
    if pack["x"].shape[1] != len(FEATURES):
        raise ValueError("Public behavior features do not match this version")
    return pack


def _weights(units: list, labels):
    import numpy as np
    per_unit = Counter(zip(units, labels.tolist()))
    w = np.array([(LOCAL_WEIGHT if str(u).startswith("local:") else 1.0) / per_unit[(u, y)]
                  for u, y in zip(units, labels.tolist())])
    for label in (0, 1):
        mask = labels == label
        w[mask] *= len(labels) / 2 / w[mask].sum()
    return w


def flags_per_day(scores: Iterable[float], days: Iterable, threshold: float) -> float:
    counts: dict = {}
    for score, day in zip(scores, days):
        counts[day] = counts.get(day, 0) + (score >= threshold)
    return sum(counts.values()) / len(counts) if counts else 0.0


def alarm_line(benign_sets: list[tuple[list[float], list]], limit: float = FLAG_LIMIT_PER_DAY) -> float:
    """Lowest score whose mean flags per day is <= limit in every benign set."""
    best = 1.0 + 1e-9
    for t in sorted({float(s) for scores, _ in benign_sets for s in scores}, reverse=True):
        if any(flags_per_day(scores, days, t) > limit for scores, days in benign_sets):
            break
        best = t
    return best


def train(public: dict, local: LocalDays, *, jobs: int = -1) -> dict:
    """Fit the forest on public rows + all local days but the newest; returns a model payload."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    if not local.ready():
        raise ValueError("Not enough days of this computer's traffic yet")
    ordered = sorted(local.days, key=int)
    train_days, dev_day = ordered[:-1], ordered[-1]
    base = public["part"] == "train"
    local_x = [row for day in train_days for row in local.days[day]]
    local_units = [f"local:{day}" for day in train_days for _ in local.days[day]]
    x = np.vstack([public["x"][base], np.array(local_x, dtype=float).reshape(-1, len(FEATURES))])
    y = np.concatenate([public["y"][base].astype(int), np.zeros(len(local_x), dtype=int)])
    units = [str(u) for u in public["unit"][base]] + local_units
    forest = RandomForestClassifier(**FOREST, n_jobs=jobs, random_state=SEED)
    forest.fit(x, y, sample_weight=_weights(units, y))
    normal = public["part"] == "normal_dev"
    benign = [(forest.predict_proba(public["x"][normal])[:, 1].tolist(), public["unit_day"][normal].tolist())]
    if local.days[dev_day]:
        dev = np.array(local.days[dev_day], dtype=float)
        benign.append((forest.predict_proba(dev)[:, 1].tolist(), [dev_day] * len(dev)))
    threshold = alarm_line(benign)
    try:
        evaluation = json.loads(RECIPE_EVALUATION.read_text())
    except (OSError, ValueError):
        evaluation = {}
    evaluation |= {"local_days": len(ordered), "newest_day": dev_day, "local_groups": len(local_x),
                   "public_rows": int(base.sum()),
                   "importance": sorted(((f, round(float(v), 4)) for f, v in zip(FEATURES, forest.feature_importances_)),
                                        key=lambda item: -item[1])}
    return forest_payload(
        forest, threshold, model_id="on-device:rf_leaf5_d24",
        trained_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), evaluation=evaluation)


def save_model(payload: dict, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".behavior-model-")
    try:
        with os.fdopen(handle, "w") as output:
            json.dump(payload, output, separators=(",", ":"))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def due(install_dir: Path, local: LocalDays, now: float) -> bool:
    """Train when ready and there is no model yet, or the model is a day old and a newer day exists."""
    if not local.ready() or not PUBLIC_FEATURES.exists():
        return False
    path = Path(install_dir) / MODEL_FILE
    if not path.exists():
        return True
    try:
        trained = json.loads(path.read_text()).get("evaluation", {}).get("newest_day")
    except (OSError, ValueError, AttributeError):
        return True
    newest = max(local.days, key=int)
    return now - path.stat().st_mtime >= RETRAIN_SECONDS and trained != newest
