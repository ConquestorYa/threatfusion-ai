"""Private full retained reports and explicitly bounded connection snapshots."""
from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime
from pathlib import Path

from .log_preparation import publish

MAX_GROUPS = 1000
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
SLOTS = frozenset({"connections.full-a.json.gz", "connections.full-b.json.gz"})


def review_counts(rows):
    """Count all retained groups before presentation filters; CTI overrides context."""
    return {
        "Original TCP reviews": sum(r.get("Queue priority") == "Review" for r in rows),
        "Declared expected reviews": sum(r.get("Queue priority") == "Review" and r.get("Declared expected") is True
                                         and r.get("CTI match") is not True for r in rows),
        "Unexplained / CTI groups": sum((r.get("Queue priority") == "Review" and r.get("Declared expected") is not True)
                                        or r.get("CTI match") is True for r in rows),
        "TCP CTI groups": sum(r.get("CTI match") is True for r in rows),
    }


def _signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def read_private(path, bound):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        before = os.fstat(file.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_mode & 0o077 or before.st_size > bound):
            raise ValueError("Report requires a bounded private regular file")
        raw = file.read(bound + 1)
        if len(raw) > bound or _signature(before) != _signature(os.fstat(file.fileno())):
            raise ValueError("Report changed during reading")
    return raw


def validate_reference(reference):
    fields = {"schema_version", "file", "sha256", "compressed_bytes", "expanded_bytes", "groups", "generated_at"}
    if (not isinstance(reference, dict) or set(reference) != fields or type(reference.get("schema_version")) is not int
        or reference["schema_version"] != 1 or not isinstance(reference.get("file"), str) or reference["file"] not in SLOTS
        or not isinstance(reference.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", reference["sha256"])
        or type(reference.get("groups")) is not int or not 1 <= reference["groups"] <= 100_000
        or type(reference.get("compressed_bytes")) is not int or not 1 <= reference["compressed_bytes"] <= MAX_ARCHIVE_BYTES
        or type(reference.get("expanded_bytes")) is not int or not 1 <= reference["expanded_bytes"] <= MAX_EXPANDED_BYTES
        or not isinstance(reference.get("generated_at"), str) or len(reference["generated_at"]) > 40):
        raise ValueError("Invalid full-report reference")
    timestamp = datetime.fromisoformat(reference["generated_at"])
    if timestamp.utcoffset() is None:
        raise ValueError("Archive requires an aware timestamp")


def read_archive(state, reference):
    """Verify snapshot's exact generation before passing bytes to a download."""
    validate_reference(reference)
    info = state.lstat()
    if (not state.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("Archive requires a private state directory")
    raw = read_private(state / reference["file"], MAX_ARCHIVE_BYTES)
    if len(raw) != reference["compressed_bytes"] or hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError("Archive generation differs from snapshot")
    return raw


def archive_slot(state):
    try:
        snapshot = json.loads(read_private(state / "connections.json", MAX_SNAPSHOT_BYTES))
    except FileNotFoundError:
        return "connections.full-a.json.gz"
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Previous snapshot could not be verified") from None
    reference = snapshot.get("full_report") if isinstance(snapshot, dict) else None
    if reference is not None:
        validate_reference(reference)
    return "connections.full-b.json.gz" if reference and reference["file"] == "connections.full-a.json.gz" else "connections.full-a.json.gz"


def write_archive(state, payload, owned_slots, reserve):
    """Alternate two reserved slots, publishing archive before snapshot pointer.

    The slot is selected from the published snapshot, rather than a database
    cursor that could be ahead/behind after interruption. Unrelated files are
    never adopted or replaced. Call reserve before creating a new managed slot.
    """
    slot = archive_slot(state)
    destination = state / slot
    previous = None
    previous_hashes = owned_slots.get(slot)
    current_digest = None
    if destination.exists() or destination.is_symlink():
        if previous_hashes is None:
            raise ValueError("Full-report slot contains unrelated data")
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Full-report slot must remain private")
        previous = _signature(info)
        current_digest = hashlib.sha256(read_private(destination, MAX_ARCHIVE_BYTES)).hexdigest()
        if current_digest not in previous_hashes:
            raise ValueError("Full-report slot content differs from managed ownership")
    descriptor, temporary = tempfile.mkstemp(dir=state, prefix=".collector-archive-")
    expanded = 0
    published = reserved = False
    try:
        with os.fdopen(descriptor, "wb") as file:
            with gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0, compresslevel=6) as archive:
                encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))
                buffer = bytearray()
                for part in encoder.iterencode(payload):
                    raw = part.encode("utf-8")
                    expanded += len(raw)
                    if expanded > MAX_EXPANDED_BYTES:
                        raise ValueError("Full report exceeds its expanded byte limit")
                    buffer.extend(raw)
                    if len(buffer) >= 65536:
                        archive.write(buffer)
                        buffer.clear()
                        if file.tell() > MAX_ARCHIVE_BYTES:
                            raise ValueError("Full report exceeds its compressed byte limit")
                archive.write(buffer)
                archive.write(b"\n")
                expanded += 1
            if expanded > MAX_EXPANDED_BYTES or file.tell() > MAX_ARCHIVE_BYTES:
                raise ValueError("Full report exceeds its byte limit")
            file.flush()
            os.fsync(file.fileno())
        raw = read_private(Path(temporary), MAX_ARCHIVE_BYTES)
        reference = {"schema_version": 1, "file": slot, "sha256": hashlib.sha256(raw).hexdigest(),
                     "compressed_bytes": len(raw), "expanded_bytes": expanded, "groups": len(payload["findings"]),
                     "generated_at": payload["generated_at"]}
        validate_reference(reference)
        # A killed writer can leave either the old or new owned generation.
        # Only their exact digests qualify; a concurrent user file is not adopted.
        reserve(slot, sorted({reference["sha256"]} | ({current_digest} if current_digest else set())))
        reserved = True
        if previous is None:
            publish(Path(temporary), destination)
        else:
            if _signature(destination.lstat()) != previous:
                raise ValueError("Archive destination changed")
            os.replace(temporary, destination)
        published = True
        reserve(slot, [reference["sha256"]])
        return reference
    except BaseException:
        if reserved and not published:
            reserve(slot, previous_hashes)
        raise
    finally:
        Path(temporary).unlink(missing_ok=True)


def snapshot_group_ids(rows):
    if len(rows) <= MAX_GROUPS:
        return tuple(row["Group"] for row in rows)
    ranked = sorted(rows, key=lambda r: (r["CTI match"] is not True, r["Queue priority"] != "Review",
                                         r["Declared expected"] is True, r["Group"]))[:MAX_GROUPS]
    return tuple(sorted(row["Group"] for row in ranked))


def prune_archives(state, owned_slots):
    """Remove only intact owned generations after a small/empty snapshot publishes."""
    remaining = dict(owned_slots)
    for slot, hashes in owned_slots.items():
        path = state / slot
        try:
            before = path.lstat()
            raw = read_private(path, MAX_ARCHIVE_BYTES)
            if hashlib.sha256(raw).hexdigest() not in hashes or _signature(before) != _signature(path.lstat()):
                continue  # Preserve changed user data; never follow a link.
            path.unlink()
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            continue
        remaining.pop(slot, None)
    return remaining


def project_snapshot(full, reference):
    rows = full["findings"]
    if len(rows) <= MAX_GROUPS:
        return full
    validate_reference(reference)
    selected = [rows[number - 1] for number in snapshot_group_ids(rows)]
    mapping = {row["Group"]: number for number, row in enumerate(selected, 1)}
    snapshot = dict(full)
    snapshot["findings"] = [dict(row, Group=mapping[row["Group"]], **{"Full report group": row["Group"]}) for row in selected]
    timelines = copy.deepcopy(full["timelines"])
    timelines["groups"] = [group for group in timelines["groups"] if group["group"] in mapping]
    for group in timelines["groups"]:
        group["group"] = mapping[group["group"]]
    timelines["groups_omitted"] = len(selected) - len(timelines["groups"])
    snapshot["timelines"] = timelines
    totals, visible = review_counts(rows), review_counts(selected)
    snapshot["connection_coverage"] = {
        "max_snapshot_groups": MAX_GROUPS, "total_groups": len(rows), "snapshot_groups": len(selected),
        "omitted_groups": len(rows) - len(selected), "review_counts": totals,
        "omitted_review_groups": totals["Original TCP reviews"] - visible["Original TCP reviews"],
        "omitted_cti_groups": totals["TCP CTI groups"] - visible["TCP CTI groups"],
        "omitted_unexplained_groups": totals["Unexplained / CTI groups"] - visible["Unexplained / CTI groups"],
    }
    snapshot["full_report"] = reference
    snapshot["limitations"] = [*full["limitations"], "Connection snapshot is bounded; full private gzip report retains every group within retained evidence."]
    return snapshot


def validate_projection(payload):
    coverage, reference = payload.get("connection_coverage"), payload.get("full_report")
    if coverage is None and reference is None:
        return
    validate_reference(reference)
    keys = {"max_snapshot_groups", "total_groups", "snapshot_groups", "omitted_groups", "review_counts",
            "omitted_review_groups", "omitted_cti_groups", "omitted_unexplained_groups"}
    if (not isinstance(coverage, dict) or set(coverage) != keys
        or any(type(coverage[k]) is not int or not 0 <= coverage[k] <= 100_000 for k in keys - {"review_counts"})
        or coverage["max_snapshot_groups"] != MAX_GROUPS or coverage["total_groups"] <= MAX_GROUPS
        or coverage["snapshot_groups"] != len(payload["findings"]) or coverage["snapshot_groups"] != MAX_GROUPS
        or coverage["total_groups"] != reference["groups"]
        or coverage["total_groups"] > payload["collector"]["counts"]["retained_records"]
        or coverage["omitted_groups"] != coverage["total_groups"] - coverage["snapshot_groups"]
        or not isinstance(coverage["review_counts"], dict) or set(coverage["review_counts"]) != set(review_counts(()))):
        raise ValueError("Invalid bounded connection coverage")
    totals, visible = coverage["review_counts"], review_counts(payload["findings"])
    for key in totals:
        if type(totals[key]) is not int or not visible[key] <= totals[key] <= coverage["total_groups"]:
            raise ValueError("Invalid full retained summary")
    for omitted, key in (("omitted_review_groups", "Original TCP reviews"), ("omitted_cti_groups", "TCP CTI groups"),
                         ("omitted_unexplained_groups", "Unexplained / CTI groups")):
        if coverage[omitted] != totals[key] - visible[key] or coverage[omitted] > coverage["omitted_groups"]:
            raise ValueError("Invalid omitted connection counts")
    if (totals["Declared expected reviews"] > totals["Original TCP reviews"]
        or not max(totals["TCP CTI groups"], totals["Original TCP reviews"] - totals["Declared expected reviews"])
        <= totals["Unexplained / CTI groups"] <= min(coverage["total_groups"], totals["TCP CTI groups"] + totals["Original TCP reviews"] - totals["Declared expected reviews"])):
        raise ValueError("Invalid overlapping full-summary counts")
    groups = []
    for number, row in enumerate(payload["findings"], 1):
        original = row.get("Full report group")
        if type(row.get("Group")) is not int or row["Group"] != number or type(original) is not int or not 1 <= original <= coverage["total_groups"]:
            raise ValueError("Invalid full-report group reference")
        groups.append(original)
    if groups != sorted(set(groups)):
        raise ValueError("Invalid snapshot group mapping")
    if payload["collector"]["counts"]["review_groups"] != totals["Original TCP reviews"]:
        raise ValueError("Original review counts differ from full summary")
