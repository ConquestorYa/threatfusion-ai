"""Linux-only, atomic private preparation of completed bounded Zeek TSV logs."""
from __future__ import annotations

import argparse
import base64
import ctypes
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import zlib
from pathlib import Path

from .dns_zeek import parse_zeek_dns_transactions
from .network_telemetry import parse_zeek_conn_log_with_diagnostics

MAX_SOURCE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_ROWS = 500_000
MAX_LINE_BYTES = 256 * 1024
MAX_SHARD_BYTES = 8 * 1024 * 1024
MAX_SHARD_ROWS = 25_000
MAX_SHARDS = 64
MAX_QUARANTINE_BYTES = 64 * 1024 * 1024
MANIFEST = ".threatfusion-prepared.json"
STAGING = ".threatfusion-staging-"
REASONS = {"missing_query", "missing_query_type"}


def signature(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def publish(stage, destination):
    # Linux atomic no-replace: a concurrently created destination also survives.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise OSError("Atomic no-replace publication requires Linux renameat2")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, "Prepared destination could not be published without replacement")


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())


def prepare_file(input_path: Path, output_dir: Path, *, quarantine_incomplete_dns=False):
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Log preparation requires Linux/POSIX file protection")
    if not output_dir.is_absolute() or output_dir.is_symlink() or output_dir.exists():
        raise ValueError("Use a new absolute private output directory")
    destination = output_dir.parent.resolve(strict=True) / output_dir.name
    def git_repository(parent):
        marker = parent / ".git"
        return marker.is_file() or (marker.is_dir() and (marker / "HEAD").is_file() and (marker / "objects").is_dir())
    if any(git_repository(parent) for parent in destination.parents):
        raise ValueError("Prepared telemetry must stay outside Git repositories")
    descriptor = os.open(input_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stage = None
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE_BYTES:
                raise ValueError("Input must be a bounded regular completed log")
            stage = Path(tempfile.mkdtemp(prefix=STAGING, dir=destination.parent))
            stream = gzip.GzipFile(fileobj=source) if input_path.name.endswith(".gz") else source
            source_digest = hashlib.sha256()
            total_bytes = total_rows = accepted = quarantined = quarantine_bytes = 0
            reasons = {key: 0 for key in sorted(REASONS)}
            headers, fields, kind, footer = bytearray(), None, None, None
            shards, current, rows, cells = [], bytearray(), 0, 0

            def flush():
                nonlocal current, rows, cells
                if not rows:
                    return
                text = (headers + current).decode("utf-8-sig")
                if kind == "conn":
                    parsed = parse_zeek_conn_log_with_diagnostics(text)
                    diag = parsed.diagnostics
                    if (len(parsed.connections) != rows or diag.skipped_missing_query_name or diag.invalid_timestamps
                        or diag.invalid_response_ips or diag.invalid_connection_fields):
                        raise ValueError("Connection shard contains invalid metadata")
                elif len(parse_zeek_dns_transactions(text)) != rows:
                    raise ValueError("DNS shard row conservation failed")
                if len(shards) >= MAX_SHARDS:
                    raise ValueError("Preparation exceeds shard budget")
                name = f"{kind}.prepared-{len(shards) + 1:06d}.log"
                private_write(stage / name, headers + current)
                shards.append({"name": name, "rows": rows})
                current, rows, cells = bytearray(), 0, 0

            with (stage / "quarantine.jsonl").open("xb") as quarantine:
                os.chmod(stage / "quarantine.jsonl", 0o600)
                line_number = 0
                while raw := stream.readline(MAX_LINE_BYTES + 1):
                    line_number += 1
                    total_bytes += len(raw)
                    if len(raw) > MAX_LINE_BYTES or total_bytes > MAX_SOURCE_BYTES:
                        raise ValueError("Expanded log or line exceeds preparation budget")
                    source_digest.update(raw)
                    line = raw.decode("utf-8-sig" if line_number == 1 else "utf-8").rstrip("\r\n")
                    if not line.strip():
                        continue
                    if footer is not None:
                        raise ValueError("Log contains content after its close marker")
                    if line.startswith("#close\t"):
                        if len(raw) > 4096:
                            raise ValueError("Close marker exceeds safe bound")
                        footer = raw.rstrip(b"\r\n") + b"\n"
                        continue
                    if line.startswith("#"):
                        if total_rows:
                            raise ValueError("Log directives changed after data began")
                        if line.startswith("#separator") and line.strip() != "#separator \\x09":
                            raise ValueError("Preparation supports standard tab-separated Zeek logs")
                        if line.startswith("#path\t"):
                            kind = line.split("\t", 1)[1]
                            if kind not in ("conn", "dns"):
                                raise ValueError("Preparation requires conn or dns path")
                        if line.startswith("#fields\t"):
                            fields = line.split("\t")[1:]
                            if not fields or len(fields) > 512 or len(set(fields)) != len(fields):
                                raise ValueError("Preparation requires bounded unique fields")
                        headers.extend(raw if raw.endswith(b"\n") else raw + b"\n")
                        if len(headers) > MAX_LINE_BYTES:
                            raise ValueError("Log headers exceed preparation budget")
                        continue
                    if kind is None or fields is None:
                        raise ValueError("Log needs path and fields before data")
                    values = line.split("\t")
                    if len(values) != len(fields):
                        raise ValueError("Log row width differs from declared fields")
                    total_rows += 1
                    if total_rows > MAX_SOURCE_ROWS:
                        raise ValueError("Log exceeds preparation row budget")
                    row = dict(zip(fields, values, strict=True))
                    reason = None
                    if kind == "dns":
                        def missing(value):
                            return value is None or value.strip() in ("", "-", "(empty)")
                        if missing(row.get("query")):
                            reason = "missing_query"
                        elif missing(row.get("qtype_name")) and missing(row.get("qtype")):
                            reason = "missing_query_type"
                    if reason:
                        if not quarantine_incomplete_dns:
                            raise ValueError("Incomplete DNS identity/type; explicit quarantine option required")
                        # Validate every other identity/metadata field. Temporary
                        # placeholders never reach shards, state or analysis.
                        check = dict(row)
                        if missing(check.get("query")):
                            check["query"] = "preparation.invalid"
                        if missing(check.get("qtype_name")) and missing(check.get("qtype")):
                            if "qtype_name" in fields:
                                check["qtype_name"] = "A"
                            elif "qtype" in fields:
                                check["qtype"] = "1"
                        check_text = headers.decode("utf-8-sig") + "\t".join(check[f] for f in fields) + "\n"
                        parse_zeek_dns_transactions(check_text)
                        item = json.dumps({"line": line_number, "reason": reason, "row_base64": base64.b64encode(raw).decode(),
                                           "sha256": hashlib.sha256(raw).hexdigest()}, separators=(",", ":")).encode() + b"\n"
                        quarantine_bytes += len(item)
                        if quarantine_bytes > MAX_QUARANTINE_BYTES:
                            raise ValueError("Quarantine exceeds preparation budget")
                        quarantine.write(item)
                        quarantined += 1
                        reasons[reason] += 1
                        continue
                    if rows and (rows >= MAX_SHARD_ROWS or cells + len(fields) > 4_000_000
                                 or len(headers) + len(current) + len(raw) + 4096 > MAX_SHARD_BYTES):
                        flush()
                    current.extend(raw if raw.endswith(b"\n") else raw + b"\n")
                    rows += 1
                    cells += len(fields)
                    accepted += 1
                quarantine.flush()
                os.fsync(quarantine.fileno())
            if stream is not source:
                stream.close()  # EOF above verifies CRC and complete gzip members.
            if footer is None or kind is None or fields is None:
                raise ValueError("Only complete logs with close marker are prepared")
            if kind == "dns":
                parse_zeek_dns_transactions(headers.decode("utf-8-sig"))
            else:
                parse_zeek_conn_log_with_diagnostics(headers.decode("utf-8-sig"))
            if signature(before) != signature(os.fstat(source.fileno())) or signature(before) != signature(input_path.lstat()):
                raise ValueError("Source changed during preparation")
            flush()
            for shard in shards:
                path = stage / shard["name"]
                with path.open("ab") as file:
                    file.write(footer)
                    file.flush()
                    os.fsync(file.fileno())
                shard.update(bytes=path.stat().st_size, sha256=digest_file(path))
            manifest = {"schema_version": 1, "kind": kind, "source_sha256": source_digest.hexdigest(), "source_bytes": total_bytes,
                        "source_rows": total_rows, "accepted_rows": accepted, "quarantined_rows": quarantined,
                        "quarantine_reasons": reasons, "shards": shards,
                        "quarantine_sha256": digest_file(stage / "quarantine.jsonl"), "quarantine_bytes": quarantine_bytes}
            private_write(stage / MANIFEST, (json.dumps(manifest, indent=2) + "\n").encode())
            read_bundle(stage)
            publish(stage, destination)
            stage = None
            return {key: manifest[key] for key in ("kind", "source_rows", "accepted_rows", "quarantined_rows", "quarantine_reasons")} | {"shard_files": len(shards)}
    finally:
        if stage is not None:
            shutil.rmtree(stage)


def read_bundle(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Prepared bundle must be private and owned by you")
    fd = os.open(directory / MANIFEST, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_mode & 0o077 or before.st_size > 1024 * 1024:
            raise ValueError("Prepared manifest must be bounded and private")
        raw = file.read(1024 * 1024 + 1)
        if signature(before) != signature(os.fstat(file.fileno())):
            raise ValueError("Prepared manifest changed during reading")
    data = json.loads(raw)
    def count(value, bound):
        return type(value) is int and 0 <= value <= bound
    def digest(value):
        return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
    if (not isinstance(data, dict) or data.get("schema_version") != 1 or data.get("kind") not in ("conn", "dns")
        or not count(data.get("source_bytes"), MAX_SOURCE_BYTES) or not count(data.get("quarantine_bytes"), MAX_QUARANTINE_BYTES)
        or any(not count(data.get(k), MAX_SOURCE_ROWS) for k in ("source_rows", "accepted_rows", "quarantined_rows"))
        or data["source_rows"] != data["accepted_rows"] + data["quarantined_rows"]
        or not digest(data.get("source_sha256")) or not digest(data.get("quarantine_sha256"))
        or not isinstance(data.get("quarantine_reasons"), dict) or set(data["quarantine_reasons"]) != REASONS
        or any(not count(v, MAX_SOURCE_ROWS) for v in data["quarantine_reasons"].values())
        or sum(data["quarantine_reasons"].values()) != data["quarantined_rows"]
        or (data["kind"] == "conn" and data["quarantined_rows"])
        or not isinstance(data.get("shards"), list) or len(data["shards"]) > MAX_SHARDS):
        raise ValueError("Invalid prepared source accounting")
    names = set()
    for shard in data["shards"]:
        if (not isinstance(shard, dict) or not isinstance(shard.get("name"), str)
            or not re.fullmatch(data["kind"] + r"\.prepared-\d{6}\.log", shard["name"])
            or shard["name"] in names or not count(shard.get("rows"), MAX_SHARD_ROWS)
            or not shard["rows"] or not count(shard.get("bytes"), MAX_SHARD_BYTES) or not digest(shard.get("sha256"))):
            raise ValueError("Invalid prepared shard accounting")
        names.add(shard["name"])
    if sum(s["rows"] for s in data["shards"]) != data["accepted_rows"]:
        raise ValueError("Prepared shard row conservation failed")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--quarantine-incomplete-dns", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        print(json.dumps(prepare_file(args.input, args.output_dir, quarantine_incomplete_dns=args.quarantine_incomplete_dns)))
    except (ValueError, OSError, UnicodeError, EOFError, zlib.error):
        # Never echo input rows, exception content or paths containing telemetry.
        parser.exit(2, "Log preparation failed. Check completion, metadata, budgets and private output permissions.\n")


def prepared_context(manifests, candidates, cache):
    """Verify local prepared inventories; return only aggregate coverage to UI."""
    candidate_set = set(candidates)
    expected, summary = {}, {"bundles": len(manifests), "source_rows": 0, "accepted_rows": 0,
                             "quarantined_rows": 0, "shard_files": 0, "pending_files": 0,
                             "quarantine_reasons": {key: 0 for key in sorted(REASONS)}}
    for manifest in manifests:
        directory = manifest.parent
        data = read_bundle(directory)
        paths = {directory / s["name"] for s in data["shards"]}
        if {p for p in candidate_set if p.parent == directory} != paths:
            raise ValueError("Prepared inventory differs from available logs")
        quarantine = directory / "quarantine.jsonl"
        info = quarantine.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
            or info.st_size != data["quarantine_bytes"]):
            raise ValueError("Prepared quarantine must be an intact private regular file")
        key = signature(manifest.lstat()), signature(info), data["quarantine_sha256"]
        if cache.get(str(manifest)) != key:
            fd = os.open(quarantine, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as file:
                before = os.fstat(file.fileno())
                if signature(info) != signature(before):
                    raise ValueError("Quarantine changed before verification")
                digest = hashlib.sha256()
                verified_bytes = 0
                while chunk := file.read(1024 * 1024):
                    verified_bytes += len(chunk)
                    if verified_bytes > data["quarantine_bytes"]:
                        raise ValueError("Prepared quarantine exceeds its declared bound")
                    digest.update(chunk)
                if signature(before) != signature(os.fstat(file.fileno())) or digest.hexdigest() != data["quarantine_sha256"]:
                    raise ValueError("Prepared quarantine changed")
            cache[str(manifest)] = key
        for shard in data["shards"]:
            path = directory / shard["name"]
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_size != shard["bytes"]):
                raise ValueError("Prepared shard must be an intact private regular file")
            expected[path] = shard["sha256"]
        for name in ("source_rows", "accepted_rows", "quarantined_rows"):
            summary[name] += data[name]
        summary["shard_files"] += len(paths)
        for name, count in data["quarantine_reasons"].items():
            summary["quarantine_reasons"][name] += count
    if any(re.fullmatch(r"(?:conn|dns)\.prepared-\d{6}\.log", p.name) and p not in expected for p in candidates):
        raise ValueError("Prepared shard has no inventory")
    for key in set(cache) - {str(p) for p in manifests}:
        del cache[key]
    return expected, summary


if __name__ == "__main__":
    main()
