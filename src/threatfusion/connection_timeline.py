"""Bounded connection-start aggregates for investigation, never detection."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from math import ceil, floor

from .connections import ConnectionFinding, ConnectionRecord, connection_identity_index

POLICY_ID = "connection-start-timeline-v1"
MAX_GROUPS = 200
MAX_BUCKETS = 48
BASE_SECONDS = 300
STATES = frozenset({"S0", "S1", "SF", "S2", "S3", "REJ", "RSTO", "RSTR",
                    "RSTOS0", "RSTRH", "SH", "SHR", "OTH"})


@dataclass(frozen=True)
class ConnectionTimeline:
    group: int
    bucket_seconds: int
    untimed_connections: int
    buckets: tuple[dict[str, object], ...]


def build_timelines(records: tuple[ConnectionRecord, ...], findings: tuple[ConnectionFinding, ...]):
    """Same global UID conflict exclusion as the detector; no raw rows retained.

    The first 200 detector-sorted groups (Review first) receive at most 48 UTC
    buckets. Counts/bytes describe connections *starting* in each bucket, not
    activity throughout long sessions. Unknown bytes never become known zero.
    """
    selected = {(f.originator_ip, f.responder_ip, f.responder_port, f.protocol): index
                for index, f in enumerate(findings[:MAX_GROUPS], 1)}
    by_uid, conflicts, _ = connection_identity_index(records)
    groups = defaultdict(list)
    for uid, record in by_uid.items():
        key = (record.originator_ip, record.responder_ip, record.responder_port, record.protocol)
        if uid not in conflicts and key in selected:
            groups[selected[key]].append(record)
    timelines = []
    for index in selected.values():
        rows = groups[index]
        timed = [r for r in rows if r.timestamp is not None and r.timestamp.tzinfo is not None
                 and r.timestamp.utcoffset() is not None]
        untimed = len(rows) - len(timed)
        times = [r.timestamp.timestamp() for r in timed]
        start = floor(min(times) / BASE_SECONDS) * BASE_SECONDS if times else 0
        width = max(BASE_SECONDS, ceil((max(times) - start) / (MAX_BUCKETS - 1) / BASE_SECONDS)
                    * BASE_SECONDS) if times else BASE_SECONDS
        bins = defaultdict(list)
        for record in timed:
            bins[floor((record.timestamp.timestamp() - start) / width)].append(record)
        buckets = []
        # Include empty gaps so charts cannot join distant samples as continuous activity.
        for number in range(max(bins) + 1 if bins else 0):
            rows = bins[number]
            states = defaultdict(int)
            for record in rows:
                states[record.state if record.state in STATES else "unknown"] += 1
            bucket = {"start_utc": datetime.fromtimestamp(start + number * width, timezone.utc).isoformat(),
                      "connections": len(rows), "states": dict(sorted(states.items()))}
            for field in ("originator_bytes", "responder_bytes"):
                values = [getattr(r, field) for r in rows]
                bucket[field] = sum(v for v in values if v is not None)
                bucket[f"{field}_unknown"] = sum(v is None for v in values)
            buckets.append(bucket)
        timelines.append(ConnectionTimeline(index, width, untimed, tuple(buckets)))
    return tuple(timelines)


def timeline_report(timelines: tuple[ConnectionTimeline, ...], group_count: int):
    return {"policy": POLICY_ID, "max_groups": MAX_GROUPS, "max_buckets": MAX_BUCKETS,
            "groups_omitted": max(0, group_count - len(timelines)),
            "groups": [asdict(timeline) for timeline in timelines]}


def validate_timeline_report(payload, findings):
    """Reject malformed/unbounded optional timeline data before UI processing."""
    def integer(value, maximum):
        return type(value) is int and 0 <= value <= maximum
    if (not isinstance(payload, dict) or payload.get("policy") != POLICY_ID
        or payload.get("max_groups") != MAX_GROUPS or payload.get("max_buckets") != MAX_BUCKETS
        or not isinstance(payload.get("groups"), list) or len(payload["groups"]) > MAX_GROUPS
        or not integer(payload.get("groups_omitted"), len(findings))
        or payload.get("groups_omitted") != len(findings) - len(payload["groups"])):
        raise ValueError("Invalid timeline envelope")
    seen = set()
    represented = 0
    for item in payload["groups"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid connection timeline")
        group = item.get("group")
        width = item.get("bucket_seconds")
        buckets = item.get("buckets")
        untimed = item.get("untimed_connections")
        if (not integer(group, len(findings)) or group < 1 or group in seen
            or not integer(width, 3652059 * 86400) or width < BASE_SECONDS or width % BASE_SECONDS
            or not isinstance(buckets, list) or len(buckets) > MAX_BUCKETS
            or not integer(untimed, 100_000)):
            raise ValueError("Invalid timeline bounds")
        seen.add(group)
        row = findings[group - 1]
        if type(row.get("Group")) is not int or row["Group"] != group:
            raise ValueError("Invalid timeline group reference")
        total = untimed
        previous = None
        for bucket in buckets:
            if not isinstance(bucket, dict) or not isinstance(bucket.get("start_utc"), str):
                raise ValueError("Invalid timeline bucket")
            timestamp = datetime.fromisoformat(bucket["start_utc"])
            if (timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0
                or (previous is not None and (timestamp - previous).total_seconds() != width)):
                raise ValueError("Invalid timeline clock")
            previous = timestamp
            count = bucket.get("connections")
            states = bucket.get("states")
            if (not integer(count, 100_000) or not isinstance(states, dict)
                or set(states) - STATES - {"unknown"}
                or any(not integer(value, count) for value in states.values())
                or sum(states.values()) != count):
                raise ValueError("Invalid timeline counts")
            total += count
            for field in ("originator_bytes", "responder_bytes"):
                unknown = bucket.get(f"{field}_unknown")
                if (not integer(unknown, count)
                    or not integer(bucket.get(field), (count - unknown) * (2**63 - 1))):
                    raise ValueError("Invalid timeline bytes")
        if not integer(row.get("Connections"), 100_000) or total != row["Connections"]:
            raise ValueError("Timeline does not reconcile with findings")
        represented += total
    if represented > 100_000:
        raise ValueError("Timeline exceeds the input limit")
