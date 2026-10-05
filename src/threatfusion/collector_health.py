"""Bounded operational status; paths and exception text never enter snapshots."""

from __future__ import annotations

import math
import uuid

REJECTIONS = frozenset({"format_or_limits", "access", "archive", "encoding"})


def validate_collector_health(status):
    revision = status.get("selection_revision")
    if revision is not None:
        if (
            not isinstance(revision, str)
            or len(revision) != 36
            or str(uuid.UUID(revision)) != revision
        ):
            raise ValueError("Invalid collector selection revision")
    scan = status.get("scan")
    if scan is None:
        return

    def count(value, maximum):
        return type(value) is int and 0 <= value <= maximum

    if (
        not isinstance(scan, dict)
        or not count(scan.get("candidate_files"), 8192)
        or not count(scan.get("attempted_files"), min(64, scan["candidate_files"]))
        or not count(scan.get("remaining_candidates"), scan["candidate_files"])
        or scan["attempted_files"] + scan["remaining_candidates"]
        > scan["candidate_files"]
        or type(scan.get("analysis_recomputed")) is not bool
    ):
        raise ValueError("Invalid collector scan")
    duration = scan.get("analysis_elapsed_seconds")
    if (
        type(duration) not in (int, float)
        or not math.isfinite(duration)
        or not 0 <= duration <= 86400
    ):
        raise ValueError("Invalid collector scan time")
    reasons = scan.get("rejections")
    if (
        not isinstance(reasons, dict)
        or set(reasons) != REJECTIONS
        or any(not count(value, scan["attempted_files"]) for value in reasons.values())
        or sum(reasons.values()) != status["counts"]["rejected_files"]
    ):
        raise ValueError("Invalid collector rejection counts")
