"""What is normal for this computer: which destinations each device has used before.

The app keeps a small private file of destinations per device (registrable
domain when a DNS name is known, the IP address otherwise) with the first and
last day each was seen. A destination is *new* when no key of it was seen
before the day it first appeared, once the device has a few earlier days of
history (the learning period). New destinations that keep being called are
worth a look; one-off new sites are normal browsing.

The file is derived from the user's own traffic: it stays in the install
directory (0600) and never leaves the computer. It is only updated while the
app reads the collector, so days the app did not run are not part of it.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .ml_behavior import Connection, scorable

SCHEMA = 1
LEARNING_DAYS = 3
MAX_KEYS_PER_DEVICE = 50_000
DAY = 86400


def day_of(timestamp: float) -> int:
    return int(timestamp // DAY)


def destination_keys(responder: str, names: Iterable[str], registrable: Callable[[str], str | None]) -> set[str]:
    keys = {f"d:{domain}" for domain in (registrable(n) for n in names) if domain}
    return keys or {f"ip:{responder}"}


def simple_registrable(name: str) -> str | None:
    """Fallback without the Public Suffix List: the last two labels."""
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else None


@dataclass
class Baseline:
    devices: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> Baseline:
        try:
            payload = json.loads(Path(path).read_text())
        except (OSError, ValueError):
            return cls()
        if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
            return cls()
        return cls(payload.get("devices") or {})

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".baseline-")
        try:
            with os.fdopen(handle, "w") as output:
                json.dump({"schema": SCHEMA, "devices": self.devices}, output, separators=(",", ":"))
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise

    def update(self, connections: Iterable[Connection], names: dict[str, set[str]],
               registrable: Callable[[str], str | None] = simple_registrable) -> None:
        """Record every internet destination per device and day; idempotent for the same records."""
        keys_cache: dict[str, set[str]] = {}
        for c in connections:
            if not c.originator or not scorable(c.responder, c.port, c.protocol):
                continue
            day = day_of(c.timestamp)
            device = self.devices.setdefault(c.originator, {"days": [], "seen": {}})
            if day not in device["days"]:
                device["days"] = sorted({*device["days"], day})
            if c.responder not in keys_cache:
                keys_cache[c.responder] = destination_keys(c.responder, names.get(c.responder, ()), registrable)
            for key in keys_cache[c.responder]:
                first, last = device["seen"].get(key, (day, day))
                device["seen"][key] = [min(first, day), max(last, day)]
        for device in self.devices.values():
            if len(device["seen"]) > MAX_KEYS_PER_DEVICE:
                newest = sorted(device["seen"].items(), key=lambda item: -item[1][1])[:MAX_KEYS_PER_DEVICE]
                device["seen"] = dict(newest)

    def history_days(self, device: str, before: int) -> int:
        return sum(day < before for day in self.devices.get(device, {}).get("days", ()))

    def learning(self, device: str, day: int) -> bool:
        return self.history_days(device, day) < LEARNING_DAYS

    def first_day(self, device: str, keys: set[str]) -> int | None:
        seen = self.devices.get(device, {}).get("seen", {})
        days = [seen[key][0] for key in keys if key in seen]
        return min(days) if days else None

    def is_new(self, device: str, keys: set[str], day: int) -> bool:
        """New on `day` (or later): no key was seen earlier, and the device is past its learning period."""
        first = self.first_day(device, keys)
        return first is not None and first >= day and not self.learning(device, first)
