"""Who owns an IP address: network (AS) name and its registry country.

The public iptoasn.com table (public domain, no key) is downloaded weekly into
the local CTI cache; lookups are local and send nothing. The country is where
the network is registered, not where a server physically is, and the owner is
often a hosting or CDN company rather than the site itself. Context only.
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import requests

from .http_safety import read_bounded_response_bytes

SOURCE = "IP owners"
DATA_URL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
MIN_RANGES = 100_000
STALE_AFTER = timedelta(days=7)
REQUEST_TIMEOUT_SECONDS = 60

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_owner_ranges (
    range_start BLOB PRIMARY KEY,
    range_end BLOB NOT NULL,
    asn INTEGER NOT NULL,
    country TEXT NOT NULL,
    owner TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_owner_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class IPOwner:
    asn: int
    owner: str
    country: str  # ISO 3166 alpha-2 of the network's registration, "" when unknown

    @property
    def label(self) -> str:
        return f"{self.owner} · {self.country}" if self.country else self.owner


def _key(address: str) -> bytes | None:
    try:
        ip = ipaddress.ip_address(address.strip())
    except (ValueError, AttributeError):
        return None
    if ip.version == 4:
        ip = ipaddress.IPv6Address(b"\0" * 10 + b"\xff\xff" + ip.packed)
    return ip.packed


def _short_owner(description: str) -> str:
    # "GOOGLE - Google LLC" -> "Google LLC"; "CLOUDFLARENET" stays as is.
    text = " ".join(description.split())
    if " - " in text:
        head, tail = text.split(" - ", 1)
        if tail.strip():
            text = tail.strip()
    return text[:80]


def parse_ip2asn(lines) -> list[tuple[bytes, bytes, int, str, str]]:
    rows = []
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 5 or not parts[2].isdigit():
            continue
        asn = int(parts[2])
        start, end = _key(parts[0]), _key(parts[1])
        if asn == 0 or start is None or end is None or end < start or len(start) != len(end):
            continue  # "Not routed" ranges carry no owner
        country = parts[3].strip().upper()
        rows.append((start, end, asn, country if len(country) == 2 and country.isalpha() and country != "ZZ" else "",
                     _short_owner(parts[4])))
    return rows


def fetch_ip_owners(session: requests.Session | None = None) -> list[tuple[bytes, bytes, int, str, str]]:
    session = session or requests.Session()
    with session.get(DATA_URL, timeout=REQUEST_TIMEOUT_SECONDS, stream=True, allow_redirects=False) as response:
        response.raise_for_status()
        packed = read_bounded_response_bytes(response, max_bytes=MAX_DOWNLOAD_BYTES, label="IP owner table")
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw = stream.read(MAX_UNPACKED_BYTES + 1)
    if len(raw) > MAX_UNPACKED_BYTES:
        raise ValueError("IP owner table exceeds the safe size")
    return parse_ip2asn(raw.decode("utf-8", errors="replace").splitlines())


def store_ip_owners(db_path: Path, rows, *, refreshed_at: datetime) -> int:
    if len(rows) < MIN_RANGES:
        raise ValueError("IP owner table is unexpectedly small; the previous table is kept")
    with closing(sqlite3.connect(db_path)) as db, db:
        db.executescript("BEGIN;" + _SCHEMA)
        db.execute("DELETE FROM ip_owner_ranges")
        db.executemany("INSERT OR REPLACE INTO ip_owner_ranges VALUES(?,?,?,?,?)", rows)
        db.executemany("INSERT OR REPLACE INTO ip_owner_meta VALUES(?,?)",
                       (("refreshed_at", refreshed_at.isoformat()), ("count", str(len(rows)))))
    return len(rows)


def ip_owner_table_is_stale(db_path: Path, *, now: datetime) -> bool:
    try:
        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute("SELECT value FROM ip_owner_meta WHERE key='refreshed_at'").fetchone()
    except sqlite3.OperationalError:
        return True
    return row is None or now - datetime.fromisoformat(row[0]) >= STALE_AFTER


class IPOwnerReader:
    """Local lookups; one connection per reader, nothing is written."""

    def __init__(self, db_path: Path):
        self._db = None
        if Path(db_path).exists():
            db = sqlite3.connect(db_path, check_same_thread=False)
            try:
                db.execute("SELECT 1 FROM ip_owner_ranges LIMIT 1")
                self._db = db
            except sqlite3.OperationalError:
                db.close()
        self._cache: dict[str, IPOwner | None] = {}
        self._lock = threading.Lock()  # one reader may serve several UI sessions

    def __bool__(self) -> bool:
        return self._db is not None

    def lookup(self, address: str) -> IPOwner | None:
        if self._db is None or not isinstance(address, str):
            return None
        if address in self._cache:
            return self._cache[address]
        key, owner = _key(address), None
        if key is not None and ipaddress.ip_address(address.strip()).is_global:
            with self._lock:
                row = self._db.execute("SELECT range_end, asn, country, owner FROM ip_owner_ranges "
                                       "WHERE range_start <= ? ORDER BY range_start DESC LIMIT 1", (key,)).fetchone()
            if row and row[0] >= key:
                owner = IPOwner(row[1], row[3], row[2])
        if len(self._cache) < 50_000:
            self._cache[address] = owner
        return owner

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
