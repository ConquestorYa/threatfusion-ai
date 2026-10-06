"""Bounded, expiring analyst declarations; never change detection evidence."""
from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .runtime_analysis import RuntimeAnalysisResult

POLICY_ID = "expected-connection-context-v1"
MAX_RULE_BYTES = 65_536
MAX_RULES = 128


@dataclass(frozen=True)
class ExpectedConnectionRule:
    id: str
    originator_ip: str
    responder_ip: str
    responder_port: int
    protocol: str
    valid_from: datetime
    valid_until: datetime
    max_connections: int
    max_duration_seconds: float
    max_originator_bytes: int
    max_responder_bytes: int


@dataclass(frozen=True)
class ConnectionContext:
    status: str
    expected: bool
    cti_matched: bool
    matched_rule_ids: tuple[str, ...]
    reason: str


def _time(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Expected timezone-aware ISO timestamp")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("Expected timezone-aware ISO timestamp") from None
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("Expected timezone-aware ISO timestamp")
    try:
        return result.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError("Timestamp exceeds supported UTC range") from None


def _ip(value: object) -> str:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise ValueError("Expected an exact IP address; wildcards and networks are forbidden")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("Expected an exact IP address; wildcards and networks are forbidden") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are forbidden")
        result[key] = value
    return result


def parse_expected_connections(content: bytes) -> tuple[ExpectedConnectionRule, ...]:
    """Fail closed on unknown fields, broad rules, nonfinite numbers and ambiguity.

    IDs are local analyst references, not verified software identities. No rule
    file, ID, endpoint or free-text label is persisted by this module.
    """
    if len(content) > MAX_RULE_BYTES:
        raise ValueError("Expected-connection file exceeds 64 KiB")
    try:
        data = json.loads(content, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Invalid expected-connection JSON") from None
    if not isinstance(data, dict) or set(data) != {"schema_version", "rules"}:
        raise ValueError("Expected schema_version and rules only")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise ValueError("Unsupported expected-connection schema")
    if not isinstance(data["rules"], list) or len(data["rules"]) > MAX_RULES:
        raise ValueError("Expected at most 128 rules")
    fields = set(ExpectedConnectionRule.__dataclass_fields__)
    rules = []
    ids = set()
    for row in data["rules"]:
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError("Rule fields must exactly match the documented schema")
        identity = row["id"]
        if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity) or identity in ids:
            raise ValueError("Rule IDs must be unique ASCII identifiers")
        ids.add(identity)
        if row["protocol"] != "tcp":
            raise ValueError("Expected activity currently supports TCP only")
        start, end = _time(row["valid_from"]), _time(row["valid_until"])
        if not start < end or end - start > timedelta(days=30):
            raise ValueError("Rule validity must be positive and at most 30 days")
        for field, lower, upper in (
            ("responder_port", 1, 65535), ("max_connections", 1, 100_000),
            ("max_originator_bytes", 1, 2**63 - 1), ("max_responder_bytes", 1, 2**63 - 1),
        ):
            if type(row[field]) is not int or not lower <= row[field] <= upper:
                raise ValueError("Rule integer limit is invalid")
        duration = row["max_duration_seconds"]
        if type(duration) not in (int, float) or not 0 < duration <= 30 * 86400 or not math.isfinite(duration):
            raise ValueError("Rule duration limit is invalid")
        rules.append(ExpectedConnectionRule(
            identity, _ip(row["originator_ip"]), _ip(row["responder_ip"]),
            row["responder_port"], "tcp", start, end, row["max_connections"],
            duration, row["max_originator_bytes"], row["max_responder_bytes"],
        ))
    return tuple(rules)


def connection_contexts(
    result: RuntimeAnalysisResult, rules: tuple[ExpectedConnectionRule, ...] = (),
    *, evaluated_at: datetime | None = None,
) -> tuple[ConnectionContext, ...]:
    now = evaluated_at or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("Context evaluation requires an aware timestamp")
    active = {}
    for rule in rules:
        if rule.valid_from <= now < rule.valid_until:
            key = (rule.originator_ip, rule.responder_ip, rule.responder_port, rule.protocol)
            active.setdefault(key, []).append(rule)
    # Existing CTI response-IP/network matches are scoped to observed client and
    # destination. No shared-IP domain attribution or originator-IP lookup added.
    cti_pairs = set()
    for match in result.matches:
        if match.match_type not in {"response_ip", "response_ip_network"}:
            continue
        try:
            target = _ip(match.matched_ip or match.event.response_ip)
        except ValueError:
            continue
        try:
            source = _ip(match.event.client_ip)
        except ValueError:
            source = None
        cti_pairs.add((source, target))
    contexts = []
    for finding in result.connection_findings:
        candidates = active.get((finding.originator_ip, finding.responder_ip,
                                 finding.responder_port, finding.protocol), ())
        complete = (
            finding.connection_count > 0
            and finding.confirmed_session_count == finding.connection_count
            and not set(finding.limitations) - {"insufficient_connection_timing"}
            and finding.first_seen is not None and finding.last_seen is not None
            and finding.max_duration_seconds is not None
            and finding.originator_bytes is not None and finding.responder_bytes is not None
        )
        matched = []
        if complete:
            # Conservative latest start + maximum duration bounds all sessions.
            try:
                end = finding.last_seen + timedelta(seconds=finding.max_duration_seconds)
            except OverflowError:
                end = None
            for rule in candidates:
                if (end is not None and rule.valid_from <= finding.first_seen and end <= now and end < rule.valid_until
                    and finding.connection_count <= rule.max_connections
                    and finding.max_duration_seconds <= rule.max_duration_seconds
                    and finding.originator_bytes <= rule.max_originator_bytes
                    and finding.responder_bytes <= rule.max_responder_bytes):
                    matched.append(rule.id)
        cti = (finding.originator_ip, finding.responder_ip) in cti_pairs
        expected = bool(matched) and not cti
        status = "cti_conflict" if cti else "declared_expected" if expected else finding.priority
        reason = ("cti_overrides_declaration" if cti else "analyst_declaration_only" if expected
                  else "incomplete_evidence" if candidates and not complete
                  else "outside_declared_limits" if candidates else "no_active_exact_rule")
        contexts.append(ConnectionContext(status, expected, cti, tuple(sorted(matched)), reason))
    return tuple(contexts)
