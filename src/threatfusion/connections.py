"""Typed passive Zeek connection evidence and conservative review context."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from statistics import mean, pstdev

POLICY_ID = "zeek-connection-context-v2"
LONG_SESSION_SECONDS = 3600
MIN_TIMESTAMPS = 20
MIN_SPAN_SECONDS = 1800
PERIODICITY_SCORE = 0.85


@dataclass(frozen=True)
class ConnectionRecord:
    uid: str | None
    timestamp: datetime | None
    originator_ip: str | None
    responder_ip: str
    originator_port: int | None
    responder_port: int | None
    protocol: str | None
    duration_seconds: float | None
    originator_bytes: int | None
    responder_bytes: int | None
    state: str | None
    missed_bytes: int | None


@dataclass(frozen=True)
class ConnectionFinding:
    originator_ip: str | None
    responder_ip: str
    responder_port: int | None
    protocol: str | None
    connection_count: int
    confirmed_session_count: int
    duplicate_rows: int
    conflicting_uids: int
    first_seen: datetime | None
    last_seen: datetime | None
    max_duration_seconds: float | None
    originator_bytes: int | None
    responder_bytes: int | None
    interval_seconds: float | None
    periodicity_score: float | None
    priority: str
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]
    payload_session_count: int = 0
    reset_session_count: int = 0
    partial_close_count: int = 0
    failed_attempt_count: int = 0


def connection_identity_index(records: tuple[ConnectionRecord, ...]):
    """Shared global identity semantics for findings, timelines and attempt review."""
    by_uid: dict[str, ConnectionRecord] = {}
    conflicts = set()
    duplicates = defaultdict(int)
    for record in records:
        if not record.uid:
            continue
        if record.uid in by_uid:
            if by_uid[record.uid] != record:
                conflicts.add(record.uid)
            else:
                duplicates[record.uid] += 1
        else:
            by_uid[record.uid] = record
    return by_uid, conflicts, duplicates


def analyze_connections(records: tuple[ConnectionRecord, ...]) -> tuple[ConnectionFinding, ...]:
    """Group observation direction, protocol and responder port; never infer domains.

    Repeated identical UIDs count once. Conflicting UIDs are excluded entirely,
    including across endpoints. No CTI/ML verdict is altered by this queue.
    """
    by_uid, conflicts, duplicates = connection_identity_index(records)
    groups = defaultdict(list)
    for record in records:
        key = (record.originator_ip, record.responder_ip, record.responder_port, record.protocol)
        groups[key].append(record)
    findings = []
    for (source, target, port, proto), rows in groups.items():
        selected = {r.uid: r for r in rows if r.uid and r.uid not in conflicts}
        unique = list(selected.values())
        coverage = []
        if any(not r.uid for r in rows):
            coverage.append("missing_connection_uid")
        if any(r.uid in conflicts for r in rows):
            coverage.append("conflicting_connection_uid")
        if not source or port is None or proto is None or any(r.originator_port is None for r in unique):
            coverage.append("incomplete_endpoint_metadata")
        timestamps = [r.timestamp for r in unique if r.timestamp is not None]
        if len(timestamps) != len(unique):
            coverage.append("missing_connection_timestamps")
        if any(t.tzinfo is None or t.utcoffset() is None for t in timestamps):
            coverage.append("ambiguous_connection_timezone")
            timestamps = []
        ordered = sorted(set(timestamps))
        first, last = (ordered[0], ordered[-1]) if ordered else (None, None)
        intervals = [(b - a).total_seconds() for a, b in zip(ordered, ordered[1:])]
        interval = mean(intervals) if intervals else None
        score = 1 / (1 + pstdev(intervals) / interval) if interval else None
        if len(ordered) < MIN_TIMESTAMPS or not first or (last - first).total_seconds() < MIN_SPAN_SECONDS:
            coverage.append("insufficient_connection_timing")
        confirmed = [r for r in unique if (
            r.protocol == "tcp" and r.state in {"SF", "S1"}
            and r.originator_bytes is not None and r.originator_bytes > 0
            and r.responder_bytes is not None and r.responder_bytes > 0
            and r.missed_bytes == 0
        )]
        if len(confirmed) != len(unique):
            coverage.append("unconfirmed_or_incomplete_sessions")
        payload_sessions = [r for r in unique if (
            r.protocol == "tcp" and r.state in {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}
            and r.originator_bytes is not None and r.originator_bytes > 0
            and r.responder_bytes is not None and r.responder_bytes > 0
            and r.missed_bytes == 0
        )]
        resets = sum(r.protocol == "tcp" and r.state in {"RSTO", "RSTR"} for r in unique)
        partial_closes = sum(r.protocol == "tcp" and r.state in {"S2", "S3"} for r in unique)
        failed = sum(r.protocol == "tcp" and r.state in {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"} for r in unique)
        if resets:
            coverage.append("reset_terminated_sessions")
        if partial_closes:
            coverage.append("partially_closed_sessions")
        if failed:
            coverage.append("failed_or_half_open_attempts")
        durations = [r.duration_seconds for r in unique if r.duration_seconds is not None]
        if len(durations) != len(unique):
            coverage.append("missing_connection_duration")
        reasons = []
        # Duration evidence can stand on its own even in a short/sparse capture.
        if source and port is not None and not any(
            value in coverage for value in ("missing_connection_uid", "conflicting_connection_uid")
        ) and any(r.duration_seconds is not None and r.duration_seconds >= LONG_SESSION_SECONDS
                  and (r.state in {"SF", "S1"} or r.originator_port is not None) for r in payload_sessions):
            reasons.append("long_bidirectional_tcp_session")
        if not coverage and score is not None and score >= PERIODICITY_SCORE:
            reasons.append("sustained_periodic_connections")
        elif (unique and len(payload_sessions) == len(unique)
              and not set(coverage) - {"unconfirmed_or_incomplete_sessions", "reset_terminated_sessions", "partially_closed_sessions"}
              and score is not None and score >= PERIODICITY_SCORE):
            reasons.append("sustained_periodic_payload_connections")
        def total(field):
            values = [getattr(r, field) for r in unique]
            return sum(values) if values and all(v is not None for v in values) else None
        findings.append(ConnectionFinding(
            source, target, port, proto, len(unique), len(confirmed),
            sum(duplicates[uid] for uid in selected),
            len({r.uid for r in rows if r.uid in conflicts}), first, last,
            max(durations) if durations else None,
            total("originator_bytes"), total("responder_bytes"), interval, score,
            "review" if reasons else "observe", tuple(reasons), tuple(coverage),
            len(payload_sessions), resets, partial_closes, failed,
        ))
    return tuple(sorted(findings, key=lambda f: (
        f.priority != "review", f.originator_ip or "", f.responder_ip,
        f.responder_port if f.responder_port is not None else -1, f.protocol or "",
    )))
