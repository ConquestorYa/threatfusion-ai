"""Popular-site context from the public Tranco list (no key, no user data sent).

A popular registrable domain is context, never a verdict: a CTI match on the
exact domain still wins, and attackers can abuse popular platforms.
"""
from __future__ import annotations

import csv
import io
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

import requests

from .collectors.tranco import TrancoCollector
from .normalization import normalize_domain_name

SOURCE = "Tranco"
LIST_ID_URL = "https://tranco-list.eu/top-1m-id"
TOP_N = 100_000
MIN_DOMAINS = 10_000
STALE_AFTER = timedelta(days=7)
REQUEST_TIMEOUT_SECONDS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS popular_domains (
    domain TEXT PRIMARY KEY,
    rank INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS popular_domains_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""
_LIST_ID = re.compile(r"^[A-Za-z0-9]{4,32}$")


def fetch_popular_domains(session: requests.Session | None = None) -> tuple[str, list[str]]:
    session = session or requests.Session()
    response = session.get(LIST_ID_URL, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False)
    response.raise_for_status()
    list_id = response.text.strip()
    if not _LIST_ID.fullmatch(list_id):
        raise ValueError("Tranco returned an invalid list identifier")
    collector = TrancoCollector(list_id, session=session)
    content = collector.fetch_csv()
    domains = []
    for row in csv.reader(io.StringIO(content)):
        if len(row) >= 2 and row[0].strip().isdigit() and row[1].strip():
            domains.append(row[1].strip())
            if len(domains) >= TOP_N:
                break
    return list_id, domains


def store_popular_domains(db_path: Path, list_id: str, domains: list[str], *, refreshed_at: datetime) -> int:
    ranked = {}
    for rank, value in enumerate(domains, 1):
        domain = normalize_domain_name(value)
        if domain and domain not in ranked:
            ranked[domain] = rank
    if len(ranked) < MIN_DOMAINS:
        raise ValueError("Tranco list is unexpectedly small; the previous list is kept")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("BEGIN;" + _SCHEMA)
        db.execute("DELETE FROM popular_domains")
        db.executemany("INSERT INTO popular_domains VALUES(?,?)", ranked.items())
        db.executemany("INSERT OR REPLACE INTO popular_domains_meta VALUES(?,?)", (
            ("list_id", list_id), ("refreshed_at", refreshed_at.isoformat()), ("count", str(len(ranked)))))
    return len(ranked)


def popular_list_is_stale(db_path: Path, *, now: datetime, stale_after: timedelta = STALE_AFTER) -> bool:
    try:
        with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as db:
            row = db.execute("SELECT value FROM popular_domains_meta WHERE key='refreshed_at'").fetchone()
    except sqlite3.Error:
        return True
    if not row:
        return True
    try:
        return now - datetime.fromisoformat(row[0]) >= stale_after
    except (TypeError, ValueError):
        return True


def load_popular_domains(db_path: Path) -> frozenset[str]:
    """No writes; an absent list means no popular-site context, not an error.

    Opened like the CTI loader: a read-only open of a WAL database would create
    its -wal/-shm files and make the cache reader see a change on every poll.
    """
    if not Path(db_path).exists():
        return frozenset()
    try:
        with closing(sqlite3.connect(db_path)) as db:
            return frozenset(row[0] for row in db.execute("SELECT domain FROM popular_domains"))
    except sqlite3.OperationalError as error:
        if "no such table" in str(error) or "unable to open" in str(error):
            return frozenset()
        raise


def is_popular(name: str, popular: frozenset[str]) -> bool:
    """The name or one of its parent domains (two labels or more) is listed."""
    if not popular or not isinstance(name, str):
        return False
    labels = name.strip().casefold().rstrip(".").split(".")
    return any(".".join(labels[i:]) in popular for i in range(max(len(labels) - 1, 0)))
