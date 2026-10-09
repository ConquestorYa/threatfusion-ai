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
import sys
import tempfile
import time
import zlib
import errno
import uuid
import re
from bisect import bisect_right
from operator import attrgetter
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .connections import ConnectionRecord
from .models import IOCRecord
from .cti_cache import CTICacheReader
from .dns_zeek import parse_zeek_dns_transactions
from .dns_collection import build_dns_snapshot, transaction_payload
from .expected_connections import MAX_RULE_BYTES, parse_expected_connections
from .network_telemetry import parse_zeek_conn_log_with_diagnostics
from .reporting import connection_report_payload
from .runtime_analysis import analyze_connection_records
from .log_preparation import MANIFEST, STAGING, prepared_context
from .collector_reports import MAX_GROUPS, SLOTS, project_snapshot, snapshot_group_ids, write_archive, prune_archives
from .collector_identity import IDENTITY_FILE, identity_payload

POLICY_ID = "closed-zeek-collector-v2"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_DNS_NAMES = 25_000
MAX_SCAN_ENTRIES = 8192
MAX_IMPORTS_PER_TICK = 64
LEDGER_SECONDS = 7 * 86400
MAX_LEDGER_FILES = 10_000


_INDICATOR_LISTS = tuple(name for name, value in IOCRecord.__dataclass_fields__.items() if value.default_factory is list)
_INDICATOR_VALUES = attrgetter(*(name for name in IOCRecord.__dataclass_fields__ if name not in _INDICATOR_LISTS))


def _indicator_state(indicators):
    """Count plus an order-sensitive hash of every indicator field.

    Detects replaced and in-place changed records (including list tags) while
    keeping O(1) memory; a full field copy of a 600k-record cache cost ~130 MiB.
    """
    count = digest = 0
    for record in indicators:
        fields = _INDICATOR_VALUES(record), tuple(tuple(getattr(record, name)) for name in _INDICATOR_LISTS)
        digest = hash((digest, fields))
        count += 1
    return count, digest


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
        dirs[:] = sorted(d for d in dirs if not d.startswith(STAGING) and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            if name == MANIFEST or (name.startswith(("conn.", "conn_", "conn-", "dns.", "dns_", "dns-")) and name.endswith((".log", ".log.gz"))):
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
        self.analysis_cache = None
        self.cached_indicators = None
        self.preparation_cache = {}
        self.report_cache = None
        self.archive_signature = None
        self.completion_epochs = ()
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
            if version not in (0, 1, 2, 3):
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
            if version in (1, 2):
                # Keep a private pre-migration copy. Never overwrite an older
                # receipt or silently make DNS state readable to a v1 collector.
                descriptor, backup_name = tempfile.mkstemp(dir=self.state, prefix=f"collector.schema{version}-", suffix=".sqlite")
                os.close(descriptor)
                with sqlite3.connect(backup_name) as backup:
                    self.db.backup(backup)
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    if version == 1:
                        self.db.execute("ALTER TABLE records ADD COLUMN kind TEXT NOT NULL DEFAULT 'conn'")
                        self.db.execute("ALTER TABLE records ADD COLUMN query_key TEXT")
                    self.db.execute("PRAGMA user_version=3")
            else:
                self.db.execute("PRAGMA user_version=3")
            self.db.executescript("""
                CREATE INDEX IF NOT EXISTS records_timestamp ON records(timestamp DESC, hash);
                CREATE INDEX IF NOT EXISTS records_ingested ON records(ingested);
                CREATE INDEX IF NOT EXISTS records_dns_names ON records(kind, query_key, timestamp);
            """)
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

    def _owned_archive_slots(self):
        row = self.db.execute("SELECT value FROM meta WHERE key='report_archive_slots'").fetchone()
        slots = json.loads(row[0]) if row else {}
        if (not isinstance(slots, dict) or len(slots) > 2
            or any(slot not in SLOTS or not isinstance(hashes, list) or not 1 <= len(hashes) <= 2
                   or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)
                   for slot, hashes in slots.items())):
            raise ValueError("Invalid managed archive slots")
        return slots

    def _prune(self, epoch):
        latest = self.db.execute("SELECT MAX(timestamp) FROM records").fetchone()[0]
        previous = self.db.execute("SELECT value FROM meta WHERE key='watermark'").fetchone()
        watermark = max(latest if latest is not None else float('-inf'), float(previous[0]) if previous else float('-inf'))
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

    def tick(self, *, indicators=(), rules=(), now: datetime | None = None, cti_reload_deferred=False):
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Collector clock must be aware")
        epoch = now.timestamp()
        started = time.perf_counter()
        indicators = tuple(indicators)
        counts = {"imported_files": 0, "duplicate_files": 0, "unchanged_files": 0,
                  "open_files": 0, "rejected_files": 0, "new_records": 0, "trimmed_records": 0,
                  "new_dns_records": 0, "new_connection_records": 0}
        # Finish directory validation before committing any file from this scan.
        inventory = sorted(_candidates(self.root))
        manifests = [path for path in inventory if path.name == MANIFEST]
        candidates = [path for path in inventory if path.name != MANIFEST]
        prepared_hashes, preparation = prepared_context(manifests, candidates, self.preparation_cache)
        rejections = {"format_or_limits": 0, "access": 0, "archive": 0, "encoding": 0}
        remaining = 0
        self.active_paths = {str(path.relative_to(self.root)) for path in candidates}
        with self.db:
            counts["trimmed_records"] += self._prune(epoch)
        cursor = self.db.execute("SELECT value FROM meta WHERE key='scan_cursor'").fetchone()
        if cursor:
            later = [p for p in candidates if str(p.relative_to(self.root)) > cursor[0]]
            candidates = later + [p for p in candidates if str(p.relative_to(self.root)) <= cursor[0]]
        attempts = 0
        for index, path in enumerate(candidates):
            relative = str(path.relative_to(self.root))
            try:
                signature = _signature(path.lstat())
                previous = self.db.execute("SELECT signature,hash FROM paths WHERE path=?", (relative,)).fetchone()
                if previous and previous[0] == signature:
                    if path in prepared_hashes and previous[1] != prepared_hashes[path]:
                        raise ValueError("Prepared shard checkpoint differs from inventory")
                    counts["unchanged_files"] += 1
                    continue
                if attempts >= MAX_IMPORTS_PER_TICK:
                    remaining = len(candidates)-index
                    break
                attempts += 1
                with self.db:
                    self.db.execute("INSERT OR REPLACE INTO meta VALUES('scan_cursor',?)", (relative,))
                completed = _completed(path)
                if completed is None:
                    counts["open_files"] += 1
                    continue
                text, digest, signature = completed
                if path in prepared_hashes and digest != prepared_hashes[path]:
                    raise ValueError("Prepared shard content differs from inventory")
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
            except (ValueError, OSError, UnicodeError, EOFError, zlib.error) as error:
                counts["rejected_files"] += 1
                reason = ("archive" if isinstance(error, (gzip.BadGzipFile, EOFError, zlib.error))
                          else "encoding" if isinstance(error, UnicodeError)
                          else "access" if isinstance(error, OSError) else "format_or_limits")
                rejections[reason] += 1
        with self.db:
            counts["trimmed_records"] += self._prune(epoch)
        indicator_state = _indicator_state(indicators)
        recomputed = (self.analysis_cache is None or counts["new_records"] or counts["trimmed_records"]
                      or indicator_state != self.cached_indicators)
        if recomputed:
            # Imports are already committed. Failed analysis must force retry;
            # the previous published snapshot remains intact until success.
            self.analysis_cache = None
            records = []
            for (payload,) in self.db.execute("SELECT payload FROM records WHERE kind='conn' ORDER BY timestamp, hash"):
                values = json.loads(payload)
                values["timestamp"] = datetime.fromisoformat(values["timestamp"]) if values["timestamp"] else None
                records.append(ConnectionRecord(**values))
            result = analyze_connection_records(records, indicators)
            dns_payloads = [r[0] for r in self.db.execute("SELECT payload FROM records WHERE kind='dns' ORDER BY timestamp, hash")]
            dns_identity = []
            dns_snapshot = build_dns_snapshot(dns_payloads, indicators, generated_at=now, selection_identity=dns_identity)
            self.analysis_cache = result, dns_snapshot, len(records), len(dns_payloads), dns_identity
            self.cached_indicators = indicator_state
            completions = set()
            for finding in result.connection_findings:
                if finding.last_seen is not None and finding.max_duration_seconds is not None:
                    try:
                        completions.add((finding.last_seen + timedelta(seconds=finding.max_duration_seconds)).timestamp())
                    except (OverflowError, ValueError):
                        pass  # Unrepresentable ends cannot qualify as expected.
            self.completion_epochs = tuple(sorted(completions))
        result, dns_snapshot, conn_count, dns_count, dns_identity = self.analysis_cache
        counts["retained_records"] = conn_count
        counts["retained_total_records"] = conn_count + dns_count
        counts["retained_dns_records"] = dns_count
        counts["analyzed_dns_events"] = dns_snapshot["coverage"]["analyzed_events"]
        counts["dns_review_groups"] = sum(row["Queue priority"] != "Observe" for row in dns_snapshot["report"]["findings"])
        counts["dns_omitted_groups"] = dns_snapshot["omitted_findings"]
        counts["review_groups"] = sum(f.priority == "review" for f in result.connection_findings)
        counts["attempt_review_groups"] = len(result.connection_attempts.findings)
        capacity = self.db.execute("SELECT value FROM meta WHERE key='capacity_loss_until'").fetchone()
        capacity_loss = bool(capacity and epoch < float(capacity[0]))
        preparation["pending_files"] = sum(not self.db.execute("SELECT 1 FROM files WHERE hash=?", (digest,)).fetchone()
                                           for digest in prepared_hashes.values())
        with self.db:
            if counts["rejected_files"] or preparation["quarantined_rows"] or preparation["pending_files"]:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('input_loss_until',?)", (str(epoch + self.window),))
        loss = self.db.execute("SELECT value FROM meta WHERE key='input_loss_until'").fetchone()
        input_loss = bool(loss and epoch < float(loss[0]))
        status = {"schema_version": 1, "policy": POLICY_ID, "updated_at": now.isoformat(),
                  "window_seconds": self.window, "max_records": self.max_records, "counts": counts,
                  "ml_enabled": False, "cti_indicators": len(indicators), "capacity_coverage_loss": capacity_loss,
                  "input_coverage_loss": input_loss, "preparation": preparation,
                  "cti_reload_deferred": bool(cti_reload_deferred),
                  "limitations": ["Completed TSV connection and TCP/UDP DNS logs only; active files wait for #close.",
                                  "One source/sensor per private state; bounded event/ingestion window.",
                                  "UID deduplication/conflicts apply within retained evidence; dropped data is coverage loss.",
                                  "DNS transaction conflicts are excluded; raw identities remain private.",
                                  "Shared retention/capacity across log kinds; DNS queries do not prove connections or downloads.",
                                  "No live packet capture, feed updates or analyst efficacy claim."]}
        effective_rules = () if capacity_loss or input_loss else rules
        report_key = (id(result), id(dns_snapshot), tuple(effective_rules),
                      tuple(rule.valid_from <= now < rule.valid_until for rule in effective_rules),
                      bisect_right(self.completion_epochs, epoch) if effective_rules else 0, capacity_loss, input_loss)
        partial = len(result.connection_findings) > MAX_GROUPS
        if not partial:
            self.report_cache = None
            self.archive_signature = None
        reused = bool(partial and self.report_cache is not None and self.report_cache[0] == report_key)
        if reused:
            try:
                reused = _signature((self.state / self.report_cache[2]["file"]).lstat()) == self.archive_signature
            except FileNotFoundError:
                reused = False
        if reused:
            base_report, reference = self.report_cache[1:]
        else:
            base_report = connection_report_payload(result, expected_rules=effective_rules, generated_at=now, evaluated_at=now)
            reference = None
            if capacity_loss:
                base_report["limitations"].append("Collector capacity dropped evidence; expected-activity declarations are disabled for one ingestion window.")
            if input_loss:
                base_report["limitations"].append("Rejected, quarantined or pending prepared input leaves incomplete coverage; expected-activity declarations are disabled.")
        identity = json.dumps({"connections": [(f.originator_ip, f.responder_ip, f.responder_port, f.protocol) for f in result.connection_findings],
                               "dns": dns_identity, "snapshot_groups": snapshot_group_ids(base_report["findings"])}, separators=(",", ":"))
        # Private identity hash stays in SQLite. Export a random epoch, never an
        # unsalted endpoint hash. Preserve selections only while group mappings match.
        digest = hashlib.sha256(identity.encode()).hexdigest()
        old = self.db.execute("SELECT value FROM meta WHERE key='selection_identity'").fetchone()
        with self.db:
            if old is None or old[0] != digest:
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('selection_identity',?)", (digest,))
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('selection_revision',?)", (str(uuid.uuid4()),))
        status["selection_revision"] = self.db.execute("SELECT value FROM meta WHERE key='selection_revision'").fetchone()[0]
        status["scan"] = {"candidate_files": len(candidates), "attempted_files": attempts,
                          "remaining_candidates": remaining, "rejections": rejections,
                          "analysis_recomputed": bool(recomputed),
                          "report_recomputed": not reused, "archive_reused": reused,
                          "analysis_elapsed_seconds": round(time.perf_counter()-started, 6)}
        full = dict(base_report, collector=status, dns=dns_snapshot)
        if partial and reference is None:
            owned_slots = self._owned_archive_slots()
            def reserve(slot, hashes):
                if hashes is None:
                    owned_slots.pop(slot, None)
                else:
                    owned_slots[slot] = hashes
                with self.db:
                    self.db.execute("INSERT OR REPLACE INTO meta VALUES('report_archive_slots',?)", (json.dumps(owned_slots, sort_keys=True),))
            reference = write_archive(self.state, full, owned_slots, reserve)
            self.report_cache = report_key, base_report, reference
            self.archive_signature = _signature((self.state / reference["file"]).lstat())
        report = project_snapshot(full, reference)
        if partial:
            report["generated_at"] = now.isoformat()
            report["context_evaluated_at"] = now.isoformat()
        content = json.dumps(report, indent=2) + "\n"
        if len(content.encode()) > 64 * 1024 * 1024:
            raise ValueError("Collector report exceeds 64 MiB; use a smaller record window")
        _atomic(self.state / IDENTITY_FILE, json.dumps(identity_payload(result, dns_identity, status["selection_revision"])))
        _atomic(self.state / "connections.json", content)
        _atomic(self.state / "status.json", json.dumps(status, indent=2) + "\n")
        if not partial:
            owned = self._owned_archive_slots()
            if owned:
                remaining = prune_archives(self.state, owned)
                with self.db:
                    self.db.execute("INSERT OR REPLACE INTO meta VALUES('report_archive_slots',?)", (json.dumps(remaining, sort_keys=True),))
        return status


def _cti_busy(error):
    return getattr(error, "sqlite_errorcode", None) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)


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
    cti_reader = CTICacheReader(args.db) if args.db else None
    try:
        with ZeekCollector(args.input_dir, args.state_dir, window_seconds=args.window_hours * 3600, max_records=args.max_records) as collector:
            while True:
                rules = ()
                if args.expected_connections:
                    with args.expected_connections.open("rb") as file:
                        rules = parse_expected_connections(file.read(MAX_RULE_BYTES + 1))
                deferred = False
                try:
                    indicators = cti_reader.read() if cti_reader else []
                except sqlite3.OperationalError as error:
                    # A long CTI refresh/maintenance lock must not stop collection.
                    # Keep the last complete indicator view and retry next poll;
                    # never analyze as if the user's cache were empty.
                    if not _cti_busy(error):
                        raise
                    if cti_reader.records is None:
                        if args.once:
                            parser.exit(1, "Collector stopped: the CTI cache is busy. Retry after the CTI update finishes.\n")
                        print("CTI cache is busy; waiting before the first scan.", file=sys.stderr, flush=True)
                        time.sleep(args.poll_seconds)
                        continue
                    indicators, deferred = cti_reader.records, True
                status = collector.tick(indicators=indicators, rules=rules, cti_reload_deferred=deferred)
                print(json.dumps(status["counts"]), flush=True)
                if args.once:
                    return 0
                time.sleep(args.poll_seconds)
    except KeyboardInterrupt:
        return 0
    except OSError as error:
        if error.errno == errno.ENOSPC:
            parser.exit(1, "Collector stopped: local disk space is insufficient. Free space and restart collection.\n")
        parser.exit(1, "Collector stopped: check private state, source limits and optional local files.\n")
    except sqlite3.Error as error:
        if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
            parser.exit(1, "Collector stopped: local disk space is insufficient. Free space and restart collection.\n")
        parser.exit(1, "Collector stopped: check private state, source limits and optional local files.\n")
    except ValueError:
        parser.exit(1, "Collector stopped: check private state, source limits and optional local files.\n")
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    raise SystemExit(main())
