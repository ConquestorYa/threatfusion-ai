"""Local Linux consumer for completed Zeek connection/DNS logs and archives."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import signal
import sqlite3
import stat
import tempfile
import time
import zlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .connections import ConnectionRecord
from .cti_cache import load_ioc_records
from .dns import DNSEvent
from .dns_zeek import parse_zeek_dns_transactions
from .dns_collection import build_dns_snapshot, transaction_payload
from .expected_connections import MAX_RULE_BYTES, parse_expected_connections
from .network_telemetry import parse_zeek_conn_log_with_diagnostics
from .reporting import build_connection_report
from .runtime_analysis import analyze_dns_events

POLICY_ID = "closed-zeek-collector-v2"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_DNS_NAMES = 25_000
MAX_SCAN_ENTRIES = 8192
MAX_IMPORTS_PER_TICK = 64
LEDGER_SECONDS = 7 * 86400
MAX_LEDGER_FILES = 10_000


def _atomic(path: Path, content: str):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".collector-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
        if path.is_symlink():
            raise ValueError("Collector output cannot be a symlink")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _private_directory(path: Path):
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("Collector state must be an absolute private directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Collector state must be owned by you with mode 0700")


def _signature(info):
    return f"{info.st_dev}:{info.st_ino}:{info.st_size}:{info.st_mtime_ns}:{info.st_ctime_ns}"


def _candidates(root: Path):
    def failed_scan(error):
        raise error
    scanned = 0
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed_scan):
        scanned += len(dirs) + len(files)
        if scanned > MAX_SCAN_ENTRIES:
            raise ValueError("Collector directory exceeds the scan limit; select a smaller source")
        dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            if name.startswith(("conn.", "conn_", "conn-", "dns.", "dns_", "dns-")) and name.endswith((".log", ".log.gz")):
                yield Path(directory) / name


def _completed(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ValueError("Collector input must be a bounded regular log")
        if not path.name.endswith(".gz"):
            file.seek(max(0, before.st_size - 256))
            tail = file.read(256).rstrip().splitlines()
            if not tail or not tail[-1].startswith(b"#close\t"):
                return None
            file.seek(0)
        raw = file.read(MAX_FILE_BYTES + 1)
        after = os.fstat(file.fileno())
    if _signature(before) != _signature(after) or len(raw) > MAX_FILE_BYTES:
        raise ValueError("Collector input changed during reading")
    if path.name.endswith(".gz"):
        from io import BytesIO
        with gzip.GzipFile(fileobj=BytesIO(raw)) as archive:
            raw = archive.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("Expanded archive exceeds the collector byte limit")
    text = raw.decode("utf-8-sig")
    lines = text.rstrip().splitlines()
    if not lines or not lines[-1].startswith("#close\t"):
        return None
    return text, hashlib.sha256(raw).hexdigest(), _signature(after)


class ZeekCollector:
    """One source/sensor per state directory. Completed files are immutable input.

    Records and exact-content file checkpoints commit together. Reports are
    regenerated from state, so a crash after commit cannot lose its evidence.
    Retained evidence is bounded by event-time and ingestion-time windows.
    """

    def __init__(self, input_dir: Path, state_dir: Path, *, window_seconds=86400, max_records=MAX_RECORDS):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("The collector requires Linux/POSIX file protection")
        if type(window_seconds) is not int or not 1800 <= window_seconds <= 7 * 86400:
            raise ValueError("Collector window must be between 30 minutes and 7 days")
        if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise ValueError("Collector record limit must be between 1 and 100000")
        self.root = input_dir.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("Collector source must be a directory")
        _private_directory(state_dir)
        self.state = state_dir.resolve()
        if self.state.is_relative_to(self.root) or self.root.is_relative_to(self.state):
            raise ValueError("Source and private collector state must be separate directories")
        self.window = window_seconds
        self.max_records = max_records
        self.active_paths = set()
        self.lock_fd = None
        self.db = None
        try:
            import fcntl
            self.lock_fd = os.open(self.state / "collector.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            info = os.fstat(self.lock_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("Collector lock must be an owner-only regular file")
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.state / "collector.sqlite"
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            os.close(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("Collector database must be owner-only")
            self.db = sqlite3.connect(path, timeout=5)
            self.db.execute("PRAGMA auto_vacuum=FULL")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise ValueError("Unsupported collector state schema")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS records(hash TEXT PRIMARY KEY, timestamp REAL, ingested REAL NOT NULL, payload TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'conn', query_key TEXT);
                CREATE TABLE IF NOT EXISTS files(hash TEXT PRIMARY KEY, ingested REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS paths(path TEXT PRIMARY KEY, signature TEXT NOT NULL, hash TEXT NOT NULL, ingested REAL NOT NULL);
            """)
            binding = json.dumps({"root": str(self.root), "window": self.window, "max_records": self.max_records})
            previous = self.db.execute("SELECT value FROM meta WHERE key='binding'").fetchone()
            if previous and previous[0] != binding:
                raise ValueError("Collector state is bound to its original source and limits")
            with self.db:
                self.db.execute("INSERT OR IGNORE INTO meta VALUES('binding',?)", (binding,))
            if version == 1:
                # Keep a private pre-migration copy. Never overwrite an older
                # receipt or silently make DNS state readable to a v1 collector.
                descriptor, backup_name = tempfile.mkstemp(dir=self.state, prefix="collector.schema1-", suffix=".sqlite")
                os.close(descriptor)
                with sqlite3.connect(backup_name) as backup:
                    self.db.backup(backup)
                with self.db:
                    self.db.execute("ALTER TABLE records ADD COLUMN kind TEXT NOT NULL DEFAULT 'conn'")
                    self.db.execute("ALTER TABLE records ADD COLUMN query_key TEXT")
                    self.db.execute("PRAGMA user_version=2")
            else:
                self.db.execute("PRAGMA user_version=2")
        except Exception:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _prune(self, epoch):
        latest = self.db.execute("SELECT MAX(timestamp) FROM records").fetchone()[0]
        previous = self.db.execute("SELECT value FROM meta WHERE key='watermark'").fetchone()
        watermark = max(latest or float('-inf'), float(previous[0]) if previous else float('-inf'))
        trimmed = 0
        if watermark != float('-inf'):
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('watermark',?)", (str(watermark),))
            trimmed += self.db.execute("DELETE FROM records WHERE timestamp < ? OR ingested < ?",
                                      (watermark - self.window, epoch - self.window)).rowcount
        trimmed += self.db.execute("DELETE FROM records WHERE ingested < ?", (epoch - self.window,)).rowcount
        capacity = self.db.execute("DELETE FROM records WHERE hash IN (SELECT hash FROM records ORDER BY timestamp DESC, hash LIMIT -1 OFFSET ?)", (self.max_records,)).rowcount
        capacity += self.db.execute("""DELETE FROM records WHERE kind='dns' AND query_key NOT IN (
            SELECT query_key FROM records WHERE kind='dns' GROUP BY query_key
            ORDER BY MAX(timestamp) DESC, query_key LIMIT ?)""", (MAX_DNS_NAMES,)).rowcount
        if capacity:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES('capacity_loss_until',?)", (str(epoch + self.window),))
        for (path,) in self.db.execute("SELECT path FROM paths WHERE ingested < ?", (epoch - LEDGER_SECONDS,)).fetchall():
            if path not in self.active_paths:
                self.db.execute("DELETE FROM paths WHERE path=?", (path,))
        self.db.execute("DELETE FROM files WHERE ingested < ? AND hash NOT IN (SELECT hash FROM paths)", (epoch - LEDGER_SECONDS,))
        for table in ("files", "paths"):
            self.db.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY ingested DESC LIMIT -1 OFFSET ?)", (MAX_LEDGER_FILES,))
        return trimmed + capacity

    def tick(self, *, indicators=(), rules=(), now: datetime | None = None):
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Collector clock must be aware")
        epoch = now.timestamp()
        indicators = tuple(indicators)
        counts = {"imported_files": 0, "duplicate_files": 0, "unchanged_files": 0,
                  "open_files": 0, "rejected_files": 0, "new_records": 0, "trimmed_records": 0,
                  "new_dns_records": 0, "new_connection_records": 0}
        # Finish directory validation before committing any file from this scan.
        candidates = sorted(_candidates(self.root))
        self.active_paths = {str(path.relative_to(self.root)) for path in candidates}
        with self.db:
            counts["trimmed_records"] += self._prune(epoch)
        cursor = self.db.execute("SELECT value FROM meta WHERE key='scan_cursor'").fetchone()
        if cursor:
            later = [p for p in candidates if str(p.relative_to(self.root)) > cursor[0]]
            candidates = later + [p for p in candidates if str(p.relative_to(self.root)) <= cursor[0]]
        attempts = 0
        for path in candidates:
            relative = str(path.relative_to(self.root))
            try:
                signature = _signature(path.lstat())
                previous = self.db.execute("SELECT signature FROM paths WHERE path=?", (relative,)).fetchone()
                if previous and previous[0] == signature:
                    counts["unchanged_files"] += 1
                    continue
                if attempts >= MAX_IMPORTS_PER_TICK:
                    break
                attempts += 1
                with self.db:
                    self.db.execute("INSERT OR REPLACE INTO meta VALUES('scan_cursor',?)", (relative,))
                completed = _completed(path)
                if completed is None:
                    counts["open_files"] += 1
                    continue
                text, digest, signature = completed
                kind = "dns" if path.name.startswith(("dns.", "dns_", "dns-")) else "conn"
                if any(line.startswith("#path") and line[len("#path"):].strip() != kind for line in text.splitlines()):
                    raise ValueError("Collector log name and declared path disagree")
                if self.db.execute("SELECT 1 FROM files WHERE hash=?", (digest,)).fetchone():
                    with self.db:
                        self.db.execute("INSERT OR REPLACE INTO paths VALUES(?,?,?,?)", (relative, signature, digest, epoch))
                    counts["duplicate_files"] += 1
                    continue
                if kind == "dns":
                    records = parse_zeek_dns_transactions(text)
                    timestamps = [r.event.timestamp for r in records]
                else:
                    parsed = parse_zeek_conn_log_with_diagnostics(text)
                    if (parsed.diagnostics.skipped_missing_query_name or parsed.diagnostics.invalid_timestamps
                        or parsed.diagnostics.invalid_response_ips or parsed.diagnostics.invalid_connection_fields):
                        raise ValueError("Collector source contains invalid records")
                    records = parsed.connections
                    timestamps = [r.timestamp for r in records]
                if any(timestamp and timestamp.timestamp() > epoch + 300 for timestamp in timestamps):
                    raise ValueError("Collector source is ahead of the trusted clock")
                inserted = 0
                with self.db:
                    for record in records:
                        if kind == "dns":
                            text = transaction_payload(record)
                            timestamp = record.event.timestamp
                            query_key = record.event.query_name.strip().casefold().removesuffix(".")
                        else:
                            payload = asdict(record)
                            payload["timestamp"] = record.timestamp.isoformat() if record.timestamp else None
                            text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
                            timestamp, query_key = record.timestamp, None
                        # Existing connection hashes stay byte-identical across migration.
                        inserted += self.db.execute("INSERT OR IGNORE INTO records VALUES(?,?,?,?,?,?)", (
                            hashlib.sha256(text.encode()).hexdigest(), timestamp.timestamp() if timestamp else None,
                            epoch, text, kind, query_key,
                        )).rowcount
                    self.db.execute("INSERT INTO files VALUES(?,?)", (digest, epoch))
                    self.db.execute("INSERT OR REPLACE INTO paths VALUES(?,?,?,?)", (relative, signature, digest, epoch))
                    trimmed = self._prune(epoch)
                counts["new_records"] += inserted
                counts["new_dns_records" if kind == "dns" else "new_connection_records"] += inserted
                counts["trimmed_records"] += trimmed
                counts["imported_files"] += 1
            except (ValueError, OSError, UnicodeError, EOFError, zlib.error):
                counts["rejected_files"] += 1
        with self.db:
            counts["trimmed_records"] += self._prune(epoch)
        records = []
        for (payload,) in self.db.execute("SELECT payload FROM records WHERE kind='conn' ORDER BY timestamp, hash"):
            values = json.loads(payload)
            values["timestamp"] = datetime.fromisoformat(values["timestamp"]) if values["timestamp"] else None
            records.append(ConnectionRecord(**values))
        events = [DNSEvent(r.responder_ip, r.timestamp, r.originator_ip, response_ip=r.responder_ip) for r in records]
        result = analyze_dns_events(events, indicators, None, connections=records)
        dns_payloads = [r[0] for r in self.db.execute("SELECT payload FROM records WHERE kind='dns' ORDER BY timestamp, hash")]
        dns_snapshot = build_dns_snapshot(dns_payloads, indicators, generated_at=now)
        counts["retained_records"] = len(records)
        counts["retained_total_records"] = len(records) + len(dns_payloads)
        counts["retained_dns_records"] = len(dns_payloads)
        counts["analyzed_dns_events"] = dns_snapshot["coverage"]["analyzed_events"]
        counts["dns_review_groups"] = sum(row["Queue priority"] != "Observe" for row in dns_snapshot["report"]["findings"])
        counts["dns_omitted_groups"] = dns_snapshot["omitted_findings"]
        counts["review_groups"] = sum(f.priority == "review" for f in result.connection_findings)
        counts["attempt_review_groups"] = len(result.connection_attempts.findings)
        capacity = self.db.execute("SELECT value FROM meta WHERE key='capacity_loss_until'").fetchone()
        capacity_loss = bool(capacity and epoch < float(capacity[0]))
        status = {"schema_version": 1, "policy": POLICY_ID, "updated_at": now.isoformat(),
                  "window_seconds": self.window, "max_records": self.max_records, "counts": counts,
                  "ml_enabled": False, "cti_indicators": len(indicators), "capacity_coverage_loss": capacity_loss,
                  "limitations": ["Completed TSV connection and TCP/UDP DNS logs only; active files wait for #close.",
                                  "One source/sensor per private state; bounded event/ingestion window.",
                                  "UID deduplication/conflicts apply within retained evidence; dropped data is coverage loss.",
                                  "DNS transaction conflicts are excluded; raw identities remain private.",
                                  "Shared retention/capacity across log kinds; DNS queries do not prove connections or downloads.",
                                  "No live packet capture, feed updates or analyst efficacy claim."]}
        report = json.loads(build_connection_report(result, expected_rules=() if capacity_loss else rules, evaluated_at=now))
        report["collector"] = status
        report["dns"] = dns_snapshot
        if capacity_loss:
            report["limitations"].append("Collector capacity dropped evidence; expected-activity declarations are disabled for one ingestion window.")
        content = json.dumps(report, indent=2) + "\n"
        if len(content.encode()) > 64 * 1024 * 1024:
            raise ValueError("Collector report exceeds 64 MiB; use a smaller record window")
        _atomic(self.state / "connections.json", content)
        _atomic(self.state / "status.json", json.dumps(status, indent=2) + "\n")
        return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--db", type=Path, help="Your existing CTI cache; omitted means behavior only")
    parser.add_argument("--expected-connections", type=Path)
    parser.add_argument("--window-hours", type=int, default=24)
    parser.add_argument("--max-records", type=int, default=MAX_RECORDS)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--once", action="store_true", help="Process one scan then exit")
    args = parser.parse_args(argv)
    if not 1 <= args.poll_seconds <= 3600:
        parser.error("Polling interval must be between 1 and 3600 seconds")
    def stop(*args):
        raise KeyboardInterrupt
    previous_handler = signal.signal(signal.SIGTERM, stop)
    try:
        with ZeekCollector(args.input_dir, args.state_dir, window_seconds=args.window_hours * 3600, max_records=args.max_records) as collector:
            while True:
                rules = ()
                if args.expected_connections:
                    with args.expected_connections.open("rb") as file:
                        rules = parse_expected_connections(file.read(MAX_RULE_BYTES + 1))
                indicators = load_ioc_records(args.db) if args.db else []
                status = collector.tick(indicators=indicators, rules=rules)
                print(json.dumps(status["counts"]), flush=True)
                if args.once:
                    return 0
                time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError, sqlite3.Error):
        parser.exit(1, "Collector stopped: check private state, source limits and optional local files.\n")
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())
