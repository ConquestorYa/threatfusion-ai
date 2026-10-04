"""Observed TCP failure diversity/concentration; review context, not compromise."""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import groupby

from .connections import ConnectionRecord, connection_identity_index

POLICY_ID = "tcp-attempt-review-v1"
WINDOW_SECONDS = 300
MIN_DISTINCT = 20
MIN_REPEATED_FAILURES = 30
MAX_FINDINGS = 500
FAILURE_STATES = frozenset({"S0", "REJ"})
COMPARABLE_STATES = frozenset(
    {
        "S0",
        "REJ",
        "SF",
        "S1",
        "S2",
        "S3",
        "RSTO",
        "RSTR",
        "RSTOS0",
        "RSTRH",
        "SH",
        "SHR",
    }
)


@dataclass(frozen=True)
class AttemptFinding:
    originator_ip: str
    responder_ip: str | None
    responder_port: int | None
    pattern: str
    first_seen: datetime
    last_seen: datetime
    failed_attempts: int
    unanswered_attempts: int
    rejected_attempts: int
    observed_records: int
    distinct_responders: int
    distinct_ports: int
    failure_fraction: float
    excluded_source_records: int


@dataclass(frozen=True)
class AttemptAnalysis:
    findings: tuple[AttemptFinding, ...] = ()
    eligible_records: int = 0
    excluded_tcp_records: int = 0
    unattributed_tcp_records: int = 0
    duplicate_rows: int = 0
    conflicting_uids: int = 0
    omitted_findings: int = 0


def _aware(record):
    return record.timestamp is not None and record.timestamp.utcoffset() is not None


def _eligible(record):
    return (
        record.originator_ip is not None
        and record.responder_ip is not None
        and record.originator_port is not None
        and 1 <= record.originator_port <= 65535
        and record.responder_port is not None
        and 1 <= record.responder_port <= 65535
        and _aware(record)
        and record.missed_bytes == 0
        and record.state in COMPARABLE_STATES
        and (
            record.state not in FAILURE_STATES
            or not (record.originator_bytes or record.responder_bytes)
        )
    )


def _peak(rows, pattern, bad_times, unknown_time, excluded_count):
    window = deque()
    hosts, ports = Counter(), Counter()
    failed = 0
    states = Counter()
    best = None
    best_rank = None
    # Process equal timestamps together so the denominator cannot depend on input order.
    for timestamp, batch in groupby(
        sorted(rows, key=lambda r: r.timestamp), key=lambda r: r.timestamp
    ):
        end = timestamp.timestamp()
        for record in batch:
            window.append(record)
            if record.state in FAILURE_STATES:
                failed += 1
                states[record.state] += 1
                hosts[record.responder_ip] += 1
                ports[record.responder_port] += 1
        while window and window[0].timestamp.timestamp() < end - WINDOW_SECONDS:
            record = window.popleft()
            if record.state in FAILURE_STATES:
                failed -= 1
                states[record.state] -= 1
                for counter, value in (
                    (hosts, record.responder_ip),
                    (ports, record.responder_port),
                ):
                    counter[value] -= 1
                    if not counter[value]:
                        del counter[value]
        excluded = bisect_right(bad_times, end) - bisect_left(
            bad_times, end - WINDOW_SECONDS
        )
        qualifies = (
            len(ports) >= MIN_DISTINCT
            if pattern == "failed_port_diversity"
            else len(hosts) >= MIN_DISTINCT
            if pattern == "failed_host_diversity"
            else failed >= MIN_REPEATED_FAILURES
            and failed * 10 >= len(window) * 9
            and not unknown_time
            and not excluded
        )
        if not qualifies:
            continue
        rank = (failed, len(hosts) + len(ports), -end)
        if best_rank is None or rank > best_rank:
            best_rank = rank
            first = window[0]
            best = AttemptFinding(
                first.originator_ip,
                None if pattern == "failed_host_diversity" else first.responder_ip,
                None if pattern == "failed_port_diversity" else first.responder_port,
                pattern,
                first.timestamp.astimezone(timezone.utc),
                timestamp.astimezone(timezone.utc),
                failed,
                states["S0"],
                states["REJ"],
                len(window),
                len(hosts),
                len(ports),
                failed / len(window),
                excluded_count,
            )
    return best


def analyze_attempts(records: tuple[ConnectionRecord, ...]) -> AttemptAnalysis:
    if len(records) > 100_000:
        raise ValueError("Attempt input exceeds the event analysis limit")
    by_uid, conflicts, duplicates = connection_identity_index(records)
    sources = defaultdict(list)
    bad_times = defaultdict(list)
    unknown_time = set()
    excluded_counts = Counter()
    eligible = excluded = unattributed = 0

    def reject(record):
        nonlocal excluded, unattributed
        if record.protocol != "tcp":
            return
        excluded += 1
        if record.originator_ip is None:
            unattributed += 1
            return
        source = record.originator_ip
        excluded_counts[source] += 1
        if _aware(record):
            bad_times[source].append(record.timestamp.timestamp())
        else:
            unknown_time.add(source)

    # Conflicts and missing UIDs do not become evidence or disappear from ratio coverage.
    for record in records:
        if not record.uid or record.uid in conflicts:
            reject(record)
    for uid, record in by_uid.items():
        if uid in conflicts or record.protocol != "tcp":
            continue
        if not _eligible(record):
            reject(record)
            continue
        eligible += 1
        sources[record.originator_ip].append(record)
    findings = []
    for source, rows in sources.items():
        bad = sorted(bad_times[source])
        for pattern in (
            "failed_port_diversity",
            "failed_host_diversity",
            "repeated_connection_failures",
        ):
            grouped = defaultdict(list)
            for record in rows:
                key = (
                    record.responder_ip
                    if pattern == "failed_port_diversity"
                    else record.responder_port
                    if pattern == "failed_host_diversity"
                    else (record.responder_ip, record.responder_port)
                )
                grouped[key].append(record)
            minimum = (
                MIN_REPEATED_FAILURES
                if pattern == "repeated_connection_failures"
                else MIN_DISTINCT
            )
            for group in grouped.values():
                if len(group) < minimum:
                    continue
                finding = _peak(
                    group, pattern, bad, source in unknown_time, excluded_counts[source]
                )
                if finding:
                    findings.append(finding)
    findings.sort(
        key=lambda f: (
            -f.failed_attempts,
            f.pattern,
            f.originator_ip,
            f.responder_ip or "",
            f.responder_port or 0,
            f.first_seen,
        )
    )
    return AttemptAnalysis(
        tuple(findings[:MAX_FINDINGS]),
        eligible,
        excluded,
        unattributed,
        sum(duplicates.values()),
        len(conflicts),
        max(0, len(findings) - MAX_FINDINGS),
    )


PATTERN_LABELS = {
    "failed_port_diversity": "Failed attempts across multiple ports",
    "failed_host_diversity": "Failed attempts across multiple responders",
    "repeated_connection_failures": "Repeated failures to one endpoint",
}


def attempt_report(analysis: AttemptAnalysis, connections, *, include_ips=False):
    hosts = sorted(
        {ip for f in connections for ip in (f.originator_ip, f.responder_ip) if ip}
    )
    aliases = {ip: f"Host {i:03d}" for i, ip in enumerate(hosts, 1)}

    def host(ip):
        if ip is None:
            return "Multiple responders"
        return ip if include_ips else aliases[ip]

    rows = [
        {
            "Originator": host(f.originator_ip),
            "Responder": host(f.responder_ip),
            "Responder port": f.responder_port,
            "Protocol": "tcp",
            "Queue priority": "Review",
            "Pattern": PATTERN_LABELS[f.pattern],
            "First observed": f.first_seen.isoformat(),
            "Last observed": f.last_seen.isoformat(),
            "Window (s)": WINDOW_SECONDS,
            "Failed attempts": f.failed_attempts,
            "Unanswered attempts": f.unanswered_attempts,
            "Rejected attempts": f.rejected_attempts,
            "Observed records": f.observed_records,
            "Distinct responders": f.distinct_responders,
            "Distinct ports": f.distinct_ports,
            "Failure fraction": f.failure_fraction,
            "Excluded source TCP records": f.excluded_source_records,
        }
        for f in analysis.findings
    ]
    return {
        "policy": POLICY_ID,
        "window_seconds": WINDOW_SECONDS,
        "max_findings": MAX_FINDINGS,
        "eligible_records": analysis.eligible_records,
        "excluded_tcp_records": analysis.excluded_tcp_records,
        "unattributed_tcp_records": analysis.unattributed_tcp_records,
        "duplicate_rows": analysis.duplicate_rows,
        "conflicting_uids": analysis.conflicting_uids,
        "omitted_findings": analysis.omitted_findings,
        "findings": rows,
        "limitations": [
            "Observed S0/REJ failure patterns are review work, not proof of scanning intent or compromise.",
            "Legitimate inventory scans, blocked services and outages can also match.",
            "Failure fractions use retained comparable records; incomplete source-window evidence blocks retry review.",
            "Expected declarations do not suppress attempt reviews; other CTI/ML verdicts are unchanged.",
        ],
    }


def validate_attempt_report(payload):
    def integer(value, maximum=100_000):
        return type(value) is int and 0 <= value <= maximum

    if (
        not isinstance(payload, dict)
        or payload.get("policy") != POLICY_ID
        or payload.get("window_seconds") != WINDOW_SECONDS
        or payload.get("max_findings") != MAX_FINDINGS
        or not isinstance(payload.get("findings"), list)
        or len(payload["findings"]) > MAX_FINDINGS
    ):
        raise ValueError("Invalid attempt report")
    for key in (
        "eligible_records",
        "excluded_tcp_records",
        "unattributed_tcp_records",
        "duplicate_rows",
        "conflicting_uids",
        "omitted_findings",
    ):
        if not integer(payload.get(key)):
            raise ValueError("Invalid attempt diagnostics")
    for row in payload["findings"]:
        if not isinstance(row, dict):
            raise ValueError("Invalid attempt finding")
        for key in ("Originator", "Responder"):
            if not isinstance(row.get(key), str) or not 1 <= len(row[key]) <= 64:
                raise ValueError("Invalid attempt endpoint")
        if (
            row.get("Pattern") not in PATTERN_LABELS.values()
            or row.get("Queue priority") != "Review"
            or row.get("Protocol") != "tcp"
            or row.get("Window (s)") != WINDOW_SECONDS
            or (
                row.get("Responder port") is not None
                and (
                    not integer(row["Responder port"], 65535)
                    or not row["Responder port"]
                )
            )
        ):
            raise ValueError("Invalid attempt pattern")
        for key in (
            "Failed attempts",
            "Unanswered attempts",
            "Rejected attempts",
            "Observed records",
            "Distinct responders",
            "Distinct ports",
            "Excluded source TCP records",
        ):
            if not integer(row.get(key)):
                raise ValueError("Invalid attempt counts")
        failed, total = row["Failed attempts"], row["Observed records"]
        fraction = row.get("Failure fraction")
        if (
            not 1 <= failed <= total <= payload["eligible_records"]
            or row["Unanswered attempts"] + row["Rejected attempts"] != failed
            or not 1 <= row["Distinct responders"] <= failed
            or not 1 <= row["Distinct ports"] <= failed
            or type(fraction) not in (int, float)
            or fraction != failed / total
        ):
            raise ValueError("Attempt counts do not reconcile")
        try:
            first, last = (
                datetime.fromisoformat(row[k])
                for k in ("First observed", "Last observed")
            )
            if (
                first.utcoffset() is None
                or last.utcoffset() is None
                or not 0 <= (last - first).total_seconds() <= WINDOW_SECONDS
            ):
                raise ValueError("Invalid attempt clock")
        except (TypeError, KeyError):
            raise ValueError("Invalid attempt clock") from None
