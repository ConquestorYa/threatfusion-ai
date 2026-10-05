"""Bounded query-time charts for client/domain investigation, never detection."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from math import ceil, floor

from .device_triage import _client_key
from .models import IOCType
from .normalization import normalize_ioc_value

POLICY_ID = "dns-device-timeline-v1"
MAX_GROUPS = 200
MAX_BUCKETS = 48
BASE_SECONDS = 60
CODES = frozenset({"NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "other", "unanswered"})


def response_category(code):
    value = str(code).upper() if code is not None else None
    return {"0": "NOERROR", "3": "NXDOMAIN", "2": "SERVFAIL", "5": "REFUSED"}.get(
        value,
        value if value in CODES else "unanswered" if value is None else "other",
    )


def build_dns_timelines(events, findings):
    selected = {
        (f.client_ip, f.assessment.domain): index
        for index, f in enumerate(findings, 1)
        if f.client_ip is not None and "ip_target_not_dns_query" not in f.limitations
    }
    selected = dict(list(selected.items())[:MAX_GROUPS])
    grouped = defaultdict(list)
    for event in events:
        key = (
            _client_key(event.client_ip),
            normalize_ioc_value(event.query_name, IOCType.DOMAIN),
        )
        if key in selected:
            grouped[selected[key]].append(event)
    groups = []
    for index in selected.values():
        rows = grouped[index]
        timed = [
            r
            for r in rows
            if r.timestamp is not None
            and r.timestamp.tzinfo is not None
            and r.timestamp.utcoffset() is not None
        ]
        times = [r.timestamp.timestamp() for r in timed]
        start = floor(min(times) / BASE_SECONDS) * BASE_SECONDS if times else 0
        width = (
            max(
                BASE_SECONDS,
                ceil((max(times) - start) / (MAX_BUCKETS - 1) / BASE_SECONDS)
                * BASE_SECONDS,
            )
            if times
            else BASE_SECONDS
        )
        bins = defaultdict(list)
        for event in timed:
            bins[floor((event.timestamp.timestamp() - start) / width)].append(event)
        buckets = []
        for number in range(max(bins) + 1 if bins else 0):
            responses = defaultdict(int)
            for event in bins[number]:
                responses[response_category(event.response_code)] += 1
            buckets.append(
                {
                    "start_utc": datetime.fromtimestamp(
                        start + number * width, timezone.utc
                    ).isoformat(),
                    "queries": len(bins[number]),
                    "responses": dict(sorted(responses.items())),
                }
            )
        groups.append(
            {
                "group": index,
                "bucket_seconds": width,
                "untimed_queries": len(rows) - len(timed),
                "buckets": buckets,
            }
        )
    return {
        "policy": POLICY_ID,
        "max_groups": MAX_GROUPS,
        "max_buckets": MAX_BUCKETS,
        "groups_omitted": len(findings) - len(groups),
        "groups": groups,
    }


def validate_dns_timelines(payload, findings):
    def integer(value, maximum=100_000):
        return type(value) is int and 0 <= value <= maximum

    if (
        not isinstance(payload, dict)
        or payload.get("policy") != POLICY_ID
        or payload.get("max_groups") != MAX_GROUPS
        or payload.get("max_buckets") != MAX_BUCKETS
        or not isinstance(payload.get("groups"), list)
        or len(payload["groups"]) > MAX_GROUPS
        or not integer(payload.get("groups_omitted"))
        or payload["groups_omitted"] != len(findings) - len(payload["groups"])
    ):
        raise ValueError("Invalid DNS timeline envelope")
    seen = set()
    for item in payload["groups"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid DNS timeline")
        index, width, untimed, buckets = (
            item.get(key)
            for key in ("group", "bucket_seconds", "untimed_queries", "buckets")
        )
        if (
            not integer(index, len(findings))
            or index < 1
            or index in seen
            or not integer(width, 3652059 * 86400)
            or width < BASE_SECONDS
            or width % BASE_SECONDS
            or not integer(untimed)
            or not isinstance(buckets, list)
            or len(buckets) > MAX_BUCKETS
        ):
            raise ValueError("Invalid DNS timeline bounds")
        seen.add(index)
        row = findings[index - 1]
        if (
            type(row.get("Group")) is not int
            or row["Group"] != index
            or row.get("Device") == "Unattributed"
        ):
            raise ValueError("Invalid DNS timeline reference")
        total, previous = untimed, None
        for bucket in buckets:
            if not isinstance(bucket, dict) or not isinstance(
                bucket.get("start_utc"), str
            ):
                raise ValueError("Invalid DNS timeline bucket")
            timestamp = datetime.fromisoformat(bucket["start_utc"])
            count, responses = bucket.get("queries"), bucket.get("responses")
            if (
                timestamp.utcoffset() is None
                or timestamp.utcoffset().total_seconds() != 0
                or (
                    previous is not None
                    and (timestamp - previous).total_seconds() != width
                )
                or not integer(count)
                or not isinstance(responses, dict)
                or set(responses) - CODES
                or any(not integer(value, count) for value in responses.values())
                or sum(responses.values()) != count
            ):
                raise ValueError("Invalid DNS timeline reconciliation")
            previous = timestamp
            total += count
        if total != row.get("Telemetry events"):
            raise ValueError("DNS timeline does not match retained query count")
