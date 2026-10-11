"""Popular-site context from public lists (no key, no user data sent).

The Tranco top 100,000 names popular registrable domains; the Public Suffix
List decides what is registrable, so user-owned subdomains of shared platforms
(dynamic DNS, user pages, tunnels: `name.example-dyndns.test`) are their own
registrable domains and are not popular. Popularity is context, never a
verdict: an exact CTI domain match still wins, and popular sites can be abused.
"""
from __future__ import annotations

import csv
import io
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import requests

from .collectors.tranco import TrancoCollector
from .normalization import normalize_domain_name

SOURCE = "Tranco"
LIST_ID_URL = "https://tranco-list.eu/top-1m-id"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
TOP_N = 100_000
MIN_DOMAINS = 10_000
MIN_SUFFIX_RULES = 5_000
MAX_PSL_BYTES = 4 * 1024 * 1024
STALE_AFTER = timedelta(days=7)
REQUEST_TIMEOUT_SECONDS = 30

_SCHEMA = """
CREATE TABLE IF NOT EXISTS popular_domains (
    domain TEXT PRIMARY KEY,
    rank INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS public_suffix_rules (
    rule TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS popular_domains_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""
_LIST_ID = re.compile(r"^[A-Za-z0-9]{4,32}$")


@dataclass(frozen=True)
class PopularSites:
    domains: frozenset[str] = frozenset()
    suffix_rules: frozenset[str] = frozenset()

    def __bool__(self) -> bool:
        # Without both lists there is no safe notion of "registrable".
        return bool(self.domains and self.suffix_rules)


EMPTY = PopularSites()


def parse_public_suffix_list(text: str) -> list[str]:
    rules = []
    for line in text.splitlines():
        rule = line.strip().split(" ", 1)[0].casefold()
        if rule and not rule.startswith("//"):
            rules.append(rule.encode("idna").decode() if not rule.isascii() and "*" not in rule
                         and not rule.startswith("!") else rule)
    return rules


def fetch_popular_domains(session: requests.Session | None = None) -> tuple[str, list[str], list[str]]:
    session = session or requests.Session()
    response = session.get(LIST_ID_URL, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False)
    response.raise_for_status()
    list_id = response.text.strip()
    if not _LIST_ID.fullmatch(list_id):
        raise ValueError("Tranco returned an invalid list identifier")
    content = TrancoCollector(list_id, session=session).fetch_csv()
    domains = []
    for row in csv.reader(io.StringIO(content)):
        if len(row) >= 2 and row[0].strip().isdigit() and row[1].strip():
            domains.append(row[1].strip())
            if len(domains) >= TOP_N:
                break
    psl = session.get(PSL_URL, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=False)
    psl.raise_for_status()
    if len(psl.content) > MAX_PSL_BYTES:
        raise ValueError("Public Suffix List exceeds the safe size")
    return list_id, domains, parse_public_suffix_list(psl.content.decode("utf-8"))


def store_popular_domains(db_path: Path, list_id: str, domains: list[str], suffix_rules: list[str], *,
                          refreshed_at: datetime) -> int:
    ranked = {}
    for rank, value in enumerate(domains, 1):
        domain = normalize_domain_name(value)
        if domain and domain not in ranked:
            ranked[domain] = rank
    rules = set(suffix_rules)
    if len(ranked) < MIN_DOMAINS or len(rules) < MIN_SUFFIX_RULES:
        raise ValueError("Popular-site lists are unexpectedly small; the previous lists are kept")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("BEGIN;" + _SCHEMA)
        db.execute("DELETE FROM popular_domains")
        db.execute("DELETE FROM public_suffix_rules")
        db.executemany("INSERT INTO popular_domains VALUES(?,?)", ranked.items())
        db.executemany("INSERT INTO public_suffix_rules VALUES(?)", ((rule,) for rule in sorted(rules)))
        db.executemany("INSERT OR REPLACE INTO popular_domains_meta VALUES(?,?)", (
            ("list_id", list_id), ("refreshed_at", refreshed_at.isoformat()), ("count", str(len(ranked)))))
    return len(ranked)


def popular_list_is_stale(db_path: Path, *, now: datetime, stale_after: timedelta = STALE_AFTER) -> bool:
    if not Path(db_path).exists():
        return True
    try:
        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute("SELECT value FROM popular_domains_meta WHERE key='refreshed_at'").fetchone()
    except sqlite3.Error:
        return True
    if not row:
        return True
    try:
        return now - datetime.fromisoformat(row[0]) >= stale_after
    except (TypeError, ValueError):
        return True


def load_popular_domains(db_path: Path) -> PopularSites:
    """No writes; absent lists mean no popular-site context, not an error.

    Opened like the CTI loader: a read-only open of a WAL database would create
    its -wal/-shm files and make the cache reader see a change on every poll.
    """
    if not Path(db_path).exists():
        return EMPTY
    try:
        with closing(sqlite3.connect(db_path)) as db:
            return PopularSites(
                frozenset(row[0] for row in db.execute("SELECT domain FROM popular_domains")),
                frozenset(row[0] for row in db.execute("SELECT rule FROM public_suffix_rules")),
            )
    except sqlite3.OperationalError as error:
        if "no such table" in str(error):
            return EMPTY
        raise


def registrable_domain(name: str, suffix_rules: frozenset[str]) -> str | None:
    """Public Suffix List algorithm (including the private section)."""
    labels = [label for label in name.strip().casefold().rstrip(".").split(".")]
    if len(labels) < 2 or not all(labels):
        return None
    suffix_length = 1  # implicit "*" rule
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if "!" + candidate in suffix_rules:
            suffix_length = len(labels) - index - 1
            break
        wildcard = ".".join(["*", *labels[index + 1:]]) if index + 1 < len(labels) else None
        if candidate in suffix_rules or (wildcard and wildcard in suffix_rules):
            suffix_length = max(suffix_length, len(labels) - index)
            break
    if suffix_length >= len(labels):
        return None
    return ".".join(labels[-(suffix_length + 1):])


def is_popular(name: str, popular: PopularSites) -> bool:
    if not popular or not isinstance(name, str):
        return False
    registrable = registrable_domain(name, popular.suffix_rules)
    return registrable is not None and registrable in popular.domains
