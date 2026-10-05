"""Bounded operational status; paths and exception text never enter snapshots."""

from __future__ import annotations

import math
import uuid

REJECTIONS = frozenset({"format_or_limits", "access", "archive", "encoding"})


def validate_collector_health(status):
    if "input_coverage_loss" in status and type(status["input_coverage_loss"]) is not bool:
        raise ValueError("Invalid input coverage state")
    prepared = status.get("preparation")
    if prepared is not None:
        def bounded(value, maximum=4_096_000_000):
            return type(value) is int and 0 <= value <= maximum
        if (not isinstance(prepared, dict) or set(prepared) != {"bundles", "source_rows", "accepted_rows", "quarantined_rows", "shard_files", "pending_files", "quarantine_reasons"}
            or any(not bounded(prepared[k]) for k in prepared if k != "quarantine_reasons")
            or prepared["bundles"] > 8192 or prepared["shard_files"] > 8192
            or prepared["pending_files"] > prepared["shard_files"]
            or prepared["source_rows"] != prepared["accepted_rows"] + prepared["quarantined_rows"]
            or not isinstance(prepared["quarantine_reasons"], dict)
            or set(prepared["quarantine_reasons"]) != {"missing_query", "missing_query_type"}
            or any(not bounded(v) for v in prepared["quarantine_reasons"].values())
            or sum(prepared["quarantine_reasons"].values()) != prepared["quarantined_rows"]):
            raise ValueError("Invalid prepared input coverage")
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
