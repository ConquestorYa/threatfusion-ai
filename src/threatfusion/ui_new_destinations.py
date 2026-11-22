"""'New for this computer' list: destinations never used before that keep calling at a steady rhythm.

Reads the collector's records read-only, remembers which destinations each
device used before (`baseline.py`, a private file in the install directory)
and lists groups of the last two 24-hour windows whose destination is new and
whose rhythm score (`rhythm.py`) is at or above RHYTHM_LINE. Development
measurement (baseline-burden-v1): 0.5 such destinations per normal device-day.
Nothing here changes the collector, its review list or threat-list results.
"""
from __future__ import annotations

import sqlite3
import time
from bisect import bisect_right
from pathlib import Path

from .baseline import Baseline, day_of, destination_keys, simple_registrable
from .i18n import tr
from .memo import cached
from .ml_behavior import WINDOW_SECONDS, scorable
from .rhythm import rhythms

BASELINE_FILE = Path("ml") / "baseline.json"
RHYTHM_LINE = 0.8
REFRESH_SECONDS = 300
MAX_SHOWN = 20
MAX_TIMES = 500

GUIDE = """**What is this?** ThreatFusion remembers which sites and addresses your devices have used before. This list shows destinations that are **new** and that it **keeps calling at a steady rhythm**, the way a program that "calls home" does. New apps and updaters can look the same.

**Learning:** ThreatFusion needs 3 earlier days of traffic before anything counts as new. The memory covers all devices it sees together, so a laptop that changes networks keeps its memory. The memory only grows while ThreatFusion is open, and it never leaves this computer.

**How was it tested?** On public research recordings (CTU-SME-11) and a few days of this computer's traffic: about 0.5 entries per normal device per day. It is a reason to look, not a malware verdict."""

GUIDE_TR = """**Bu nedir?** ThreatFusion cihazlarının daha önce hangi sitelerle ve adreslerle konuştuğunu hatırlar. Bu liste **yeni** olan ve cihazın **düzenli bir ritimle aramaya devam ettiği** hedefleri gösterir; "eve telefon eden" bir program böyle davranır. Yeni uygulamalar ve güncelleyiciler de aynı görünebilir.

**Öğrenme:** Bir şeyin yeni sayılması için en az 3 günlük trafik geçmişi gerekir. Hafıza gördüğü tüm cihazları birlikte kapsar; böylece ağ değiştiren bir dizüstü bilgisayar hafızasını kaybetmez. Bu hafıza yalnızca ThreatFusion açıkken büyür ve bilgisayardan hiç çıkmaz.

**Nasıl test edildi?** Herkese açık araştırma kayıtlarında (CTU-SME-11) ve bu bilgisayarın birkaç günlük trafiğinde: normal bir cihazda günde yaklaşık 0,5 kayıt. Bakmak için bir sebeptir, zararlı yazılım kararı değildir."""


def _guide() -> str:
    from .i18n import current_language
    return GUIDE_TR if current_language() == "tr" else GUIDE


@cached(max_entries=2)
def _registrable(db_path: str | None):
    if db_path:
        from .popular_domains import load_suffix_rules, registrable_domain
        try:
            rules = load_suffix_rules(Path(db_path))
        except sqlite3.Error:
            rules = frozenset()
        if rules:
            return lambda name: registrable_domain(name, rules)
    return simple_registrable


@cached(max_entries=2, ttl=REFRESH_SECONDS * 2)
def new_destinations(db_path: str, baseline_path: str, cti_db: str | None, bucket: int) -> dict:
    """{"rows": new rhythmic groups (strongest rhythm first), "learning": devices still learning, "devices": n}."""
    from .ui_behavior import read_collector_records
    connections, names = read_collector_records(Path(db_path))
    registrable = _registrable(cti_db)
    base = Baseline.load(Path(baseline_path))
    base.update(connections, names, registrable)
    try:
        base.save(Path(baseline_path))
    except OSError:
        pass  # Still show today's view; the memory catches up on the next save.
    times: dict[tuple, list[float]] = {}
    for c in connections:
        times.setdefault((c.originator, c.responder, c.port, c.protocol), []).append(c.timestamp)
    for values in times.values():
        values.sort()
    rows = []
    today = day_of(time.time())
    devices = {c.originator for c in connections if c.originator and scorable(c.responder, c.port, c.protocol)}
    learning = {device for device in devices if base.learning(device, today)}
    for group in rhythms(connections):
        day = day_of(group.first_seen)
        if base.learning(group.originator, day):
            continue
        listed = sorted(names.get(group.responder, ()))
        keys = destination_keys(group.responder, listed, registrable)
        if group.score < RHYTHM_LINE or not base.is_new(group.originator, keys, day):
            continue
        own = times.get((group.originator, group.responder, group.port, group.protocol), [])
        start = bisect_right(own, group.window_end - WINDOW_SECONDS)
        rows.append({"device": group.originator, "address": group.responder, "port": group.port,
                     "protocol": group.protocol, "name": listed[0] if listed else None, "names": listed,
                     "domain": registrable(listed[0]) if listed else None,
                     "connections": group.connections, "first": group.first_seen, "last": group.last_seen,
                     "interval": group.interval, "score": group.score,
                     "times": own[start:bisect_right(own, group.window_end)][-MAX_TIMES:]})
    best = {}
    for row in sorted(rows, key=lambda r: -r["score"]):
        best.setdefault((row["device"], row["address"], row["port"]), row)
    return {"rows": group_by_site(list(best.values())), "learning": sorted(learning), "devices": len(devices)}


def group_by_site(rows: list[dict]) -> list[dict]:
    """One card per device and site: addresses of the same registrable domain join the strongest row."""
    cards: dict[tuple, dict] = {}
    for row in sorted(rows, key=lambda r: -r["score"]):
        key = (row["device"], row["domain"]) if row.get("domain") else (row["device"], row["address"], row["port"])
        if key in cards:
            cards[key]["others"].append(f"{row['address']}:{row['port']}")
        else:
            cards[key] = {**row, "others": []}
    return list(cards.values())


def _title_domain(title: str, registrable) -> str | None:
    """Registrable domain of a review item's title ("name", "name:port"); None for addresses."""
    from ipaddress import ip_address
    head, _, tail = title.rpartition(":")
    name = head if head and tail.isdigit() else title
    try:
        ip_address(name)
        return None
    except ValueError:
        pass
    return registrable(name) if "." in name else None


def marked_sites(labels: dict, registrable) -> tuple[set[str], set[str]]:
    """Sites (registrable domains) the user marked as known and as suspicious, on any list."""
    known, suspicious = set(), set()
    for key, entry in labels.items():
        _, _, title = key.partition(":")
        domain = _title_domain(title, registrable)
        if domain and entry.get("label") == "known":
            known.add(domain)
        elif domain and entry.get("label") == "suspicious":
            suspicious.add(domain)
    return known, suspicious - known


def _item(row) -> dict:
    return {"kind": "new", "title": f"{row['name'] or row['address']}:{row['port']}"}


def _every(seconds: float) -> str:
    if seconds >= 3600:
        return tr("about every {n} h", n=round(seconds / 3600, 1))
    if seconds >= 60:
        return tr("about every {n} min", n=round(seconds / 60))
    return tr("about every {n} s", n=round(seconds))


