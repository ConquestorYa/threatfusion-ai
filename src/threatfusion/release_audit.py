from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class ReleaseAuditFinding:
    rule: str
    path: str
    object_id: str | None = None


_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        ),
    ),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai-api-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "threatfusion-service-secret",
        re.compile(
            r"(?i)\b(?:THREATFOX_AUTH_KEY|URLHAUS_AUTH_KEY|PHISHTANK_APP_KEY|RENDER_API_KEY)"
            r"\s*[:=]\s*[\"']?(?!\.\.\.|<|YOUR_)[A-Za-z0-9._-]{20,}"
        ),
    ),
    (
        "local-windows-user-path",
        re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+"),
    ),
    (
        "local-macos-user-path",
        re.compile(
            r"(?<![A-Za-z0-9_])/"
            + r"Users/[^/\s]+"
        ),
    ),
)

# This file intentionally constructs values that exercise the rules. Historical
# fixture blobs are excluded so the audit does not permanently fail on its own
# synthetic examples or earlier self-matching rule definitions. The current
# tracked tree still scans these files; only their intentionally noisy history
# is excluded. Production/source paths are not generally allowlisted.
_HISTORY_FIXTURE_PATHS = {
    "src/threatfusion/release_audit.py",
    "tests/test_release_audit.py",
}


def scan_release_text(
    text: str,
    *,
    path: str,
    object_id: str | None = None,
) -> tuple[ReleaseAuditFinding, ...]:
    """Return rule/path metadata without returning matching secret values."""
    findings: list[ReleaseAuditFinding] = []
    for rule, pattern in _PATTERNS:
        if pattern.search(text):
            findings.append(
                ReleaseAuditFinding(
                    rule=rule,
                    path=path,
                    object_id=object_id,
                )
            )
    return tuple(findings)


def scan_release_path(
    path: str,
    *,
    object_id: str | None = None,
) -> tuple[ReleaseAuditFinding, ...]:
    """Reject local data/model files even when their payload is binary."""
    normalized = path.casefold()
    parts = PurePosixPath(normalized).parts
    local_data = len(parts) >= 2 and parts[0] == "data" and parts[1] in {
        "snapshots", "models", "evaluation", "deployment", "demo",
    }
    filename = PurePosixPath(normalized).name
    database = any(
        filename.endswith(suffix) or suffix + "-" in filename
        for suffix in (".db", ".sqlite", ".sqlite3")
    )
    model = filename.endswith((".joblib", ".pkl", ".pickle"))
    if local_data or database or model:
        return (ReleaseAuditFinding("local-data-artifact", path, object_id),)
    return ()


def _git(
    repository: Path,
    *args: str,
    input_bytes: bytes | None = None,
) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        input=input_bytes,
        capture_output=True,
        check=True,
    )
    return result.stdout


def audit_tracked_tree(
    repository: Path,
) -> tuple[tuple[ReleaseAuditFinding, ...], int]:
    """Scan the current tracked tree for known secret/privacy patterns."""
    root = repository.resolve()
    names = _git(root, "ls-files", "-z").split(b"\0")
    findings: list[ReleaseAuditFinding] = []
    scanned = 0

    for raw_name in names:
        if not raw_name:
            continue
        relative = raw_name.decode("utf-8", errors="strict")
        findings.extend(scan_release_path(relative))
        path = root / relative
        try:
            payload = path.read_bytes()
        except OSError:
            continue
        if b"\0" in payload:
            continue
        scanned += 1
        text = payload.decode("utf-8", errors="replace")
        findings.extend(scan_release_text(text, path=relative))

    return tuple(findings), scanned


def _history_blob_index(repository: Path) -> list[tuple[str, str]]:
    raw = _git(repository, "rev-list", "--objects", "--all").decode(
        "utf-8",
        errors="replace",
    )
    object_paths: dict[str, str] = {}
    for line in raw.splitlines():
        if not line:
            continue
        sha, separator, path = line.partition(" ")
        object_paths.setdefault(sha, path if separator else "<git-object>")

    if not object_paths:
        return []

    shas = list(object_paths)
    check_input = ("\n".join(shas) + "\n").encode("ascii")
    checked = _git(
        repository,
        "cat-file",
        "--batch-check=%(objectname) %(objecttype)",
        input_bytes=check_input,
    ).decode("ascii", errors="replace")

    blobs: list[tuple[str, str]] = []
    for line in checked.splitlines():
        object_id, _, object_type = line.partition(" ")
        if object_type == "blob":
            blobs.append((object_id, object_paths.get(object_id, "<unknown>")))
    return blobs


def _history_artifact_findings(repository: Path) -> tuple[ReleaseAuditFinding, ...]:
    """Check every historical path, including aliases of the same blob."""
    records = iter(_git(
        repository, "log", "--all", "--raw", "-z", "--format=",
        "--no-abbrev", "--no-renames", "--diff-merges=separate",
    ).split(b"\0"))
    findings: dict[tuple[str, str], ReleaseAuditFinding] = {}
    for raw_header in records:
        header = raw_header.lstrip(b"\n")
        if not header:
            continue
        fields = header.split()
        if len(fields) != 5 or not fields[0].startswith(b":"):
            raise RuntimeError("unexpected Git history path record")
        raw_path = next(records, None)
        if raw_path is None:
            raise RuntimeError("Git history path record is incomplete")
        path = raw_path.decode("utf-8", errors="strict")
        sha = fields[2] if fields[4] == b"D" else fields[3]
        object_id = sha.decode("ascii")
        for finding in scan_release_path(path, object_id=object_id):
            findings[(path, object_id)] = finding
    return tuple(findings.values())


def audit_git_history(
    repository: Path,
) -> tuple[tuple[ReleaseAuditFinding, ...], int]:
    """Scan every unique Git blob without printing any matched value."""
    root = repository.resolve()
    blobs = _history_blob_index(root)
    if not blobs:
        return (), 0

    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("git cat-file batch pipes are unavailable")

    findings: list[ReleaseAuditFinding] = list(_history_artifact_findings(root))
    scanned = 0
    try:
        for object_id, path in blobs:
            process.stdin.write(f"{object_id}\n".encode("ascii"))
            process.stdin.flush()

            header = process.stdout.readline().decode("ascii", errors="replace")
            parts = header.strip().split()
            if len(parts) != 3 or parts[1] != "blob":
                raise RuntimeError("unexpected git cat-file batch response")

            size = int(parts[2])
            payload = process.stdout.read(size)
            process.stdout.read(1)
            if b"\0" in payload:
                continue

            scanned += 1
            if path in _HISTORY_FIXTURE_PATHS:
                continue
            text = payload.decode("utf-8", errors="replace")
            findings.extend(
                scan_release_text(
                    text,
                    path=path,
                    object_id=object_id,
                )
            )
    finally:
        if process.stdin is not None:
            process.stdin.close()
        process.wait(timeout=10)

    if process.returncode not in {0, None}:
        raise RuntimeError("git cat-file history scan failed")

    return tuple(findings), scanned
