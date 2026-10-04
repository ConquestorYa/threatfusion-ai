"""Freeze synthetic DNS collector inputs outside Git, then verify operational contracts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

NOW = datetime(2026, 10, 5, 3, tzinfo=timezone.utc)
FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "trans_id",
    "query",
    "qtype_name",
    "rcode_name",
    "answers",
)


def log(rows, *, closed=True):
    return (
        "#separator \\x09\n#path\tdns\n#fields\t"
        + "\t".join(FIELDS)
        + "\n"
        + "".join("\t".join(map(str, row)) + "\n" for row in rows)
        + ("#close\t2026-10-05-03-00-00\n" if closed else "")
    )


def cases(seed):
    base = int(NOW.timestamp()) - 4000

    def row(
        i,
        *,
        proto="udp",
        uid=None,
        ts=None,
        query="updates.test",
        code="NOERROR",
        answer="198.51.100.9",
    ):
        return [
            base + i * 100 if ts is None else ts,
            uid or f"C{seed}-{i}",
            "192.0.2.11",
            40000,
            "192.0.2.53",
            53,
            proto,
            i,
            query,
            "A",
            code,
            answer,
        ]

    same = row(0)
    changed = [*same]
    changed[8] = "different.test"
    invalid = row(0)
    invalid[7] = "-"
    return [
        {
            "name": "udp-periodic-benign",
            "rows": [row(i, uid=f"Cudp{seed}") for i in range(20)],
            "events": 20,
            "reviews": 1,
        },
        {
            "name": "tcp-periodic-benign",
            "rows": [row(i, proto="tcp", uid=f"Ctcp{seed}") for i in range(20)],
            "events": 20,
            "reviews": 1,
        },
        {
            "name": "coarse-time-different-uids",
            "rows": [row(i, ts=base) for i in range(2)],
            "events": 2,
            "reviews": 0,
        },
        {
            "name": "exact-row-copies",
            "rows": [same, same, same],
            "events": 1,
            "reviews": 0,
        },
        {
            "name": "conflicting-transaction",
            "rows": [same, changed],
            "events": 0,
            "reviews": 0,
            "conflicts": 1,
        },
        {
            "name": "transaction-id-wrap",
            "rows": [row(0), row(0, ts=base + 100)],
            "events": 2,
            "reviews": 0,
        },
        {
            "name": "response-codes-benign",
            "rows": [
                row(i, query=f"lookup-{seed}.test", code=code, answer="-")
                for i, code in enumerate(("NOERROR", "NXDOMAIN", "SERVFAIL"))
            ],
            "events": 3,
            "reviews": 0,
        },
        {
            "name": "unanswered",
            "rows": [row(0, code="-", answer="-")],
            "events": 1,
            "reviews": 0,
        },
        {
            "name": "missing-transaction-id",
            "rows": [invalid],
            "events": 0,
            "reviews": 0,
            "rejected": 1,
        },
        {
            "name": "future-clock",
            "rows": [row(0, ts=int(NOW.timestamp()) + 301)],
            "events": 0,
            "reviews": 0,
            "rejected": 1,
        },
        {
            "name": "active-file",
            "rows": [row(0)],
            "closed": False,
            "events": 0,
            "reviews": 0,
        },
    ]


def private_root(path):
    path = path.absolute()
    repo = Path(__file__).resolve().parents[2]
    if path.is_symlink():
        raise ValueError("Experiment root cannot be a symlink")
    path = path.resolve()
    if path.is_relative_to(repo):
        raise ValueError(
            "Use a private experiment directory outside the source repository"
        )
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("Experiment directory must be private and owned by you")
    return path


def write_new(path, value):
    with path.open("x") as file:
        file.write(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def create(root):
    hashes = {}
    for name, seed in (("development", 20261051), ("reserved", 20261151)):
        path = root / f"{name}.json"
        write_new(path, cases(seed))
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_new(
        root / "plan.json",
        {
            "policy": "closed-zeek-dns-collector-v1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scope": "Completed TSV TCP/UDP dns.log; existing DNS triage unchanged; private transactional checkpoints.",
            "identity": "UID + transaction ID + timestamp; differing full source rows at same key excluded; no endpoint inference.",
            "limits": "Shared 100k evidence, 25k DNS names, 1000 DNS findings/500 visible; existing time/file/scan bounds.",
            "controls": hashes,
            "next_live": "New isolated .test-only UDP/TCP success/NXDOMAIN/SERVFAIL and unanswered requests.",
            "claims_excluded": [
                "malware accuracy",
                "DNS tunneling detection",
                "independent benign FPR",
                "production readiness",
                "ML promotion",
            ],
        },
    )


def evaluate(root, phase, run_id):
    from threatfusion.telemetry_collector import ZeekCollector
    from threatfusion.ui_collector import read_snapshot

    if phase == "reserved":
        from scripts.lab.evaluate_dns_collector_live import verify_freeze

        verify_freeze(root)

    manifest = json.loads((root / "plan.json").read_text())
    path = root / f"{phase}.json"
    assert (
        hashlib.sha256(path.read_bytes()).hexdigest() == manifest["controls"][path.name]
    )
    results = []
    for case in json.loads(path.read_text()):
        folder = root / f"{phase}-{run_id}-{case['name']}"
        folder.mkdir(mode=0o700)
        source = folder / "input"
        source.mkdir(mode=0o700)
        content = log(case["rows"], closed=case.get("closed", True))
        (source / "dns.log").write_text(content)
        state = folder / "state"
        with ZeekCollector(source, state) as collector:
            status = collector.tick(now=NOW)
            snapshot = read_snapshot(state)
            counts = status["counts"]
            assert counts["analyzed_dns_events"] == case["events"], case["name"]
            assert counts["dns_review_groups"] == case["reviews"], case["name"]
            assert counts["rejected_files"] == case.get("rejected", 0), case["name"]
            assert snapshot["dns"]["coverage"]["conflicting_transactions"] == case.get(
                "conflicts", 0
            )
            (source / "dns.copy.log.gz").write_bytes(gzip.compress(content.encode()))
            repeat = collector.tick(now=NOW)
            assert repeat["counts"]["new_records"] == 0
        with ZeekCollector(source, state) as collector:
            restarted = collector.tick(now=NOW)
            assert restarted["counts"]["new_records"] == 0
            assert (
                read_snapshot(state)["dns"]["report"]["findings"]
                == snapshot["dns"]["report"]["findings"]
            )
        results.append({"case": case["name"], "passed": True, "counts": counts})
    write_new(
        root / f"{phase}-{run_id}.results.json",
        {"results": results, "passed": len(results), "total": len(results)},
    )
    print(json.dumps({"phase": phase, "passed": len(results), "total": len(results)}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "evaluate"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--phase", choices=("development", "reserved"), default="development"
    )
    parser.add_argument("--run-id", default="first")
    args = parser.parse_args()
    os.umask(0o077)
    if not args.run_id.isascii() or not args.run_id.replace("-", "").isalnum():
        parser.error("Run ID must contain ASCII letters/digits/hyphens")
    directory = private_root(args.root)
    create(directory) if args.action == "create" else evaluate(
        directory, args.phase, args.run_id
    )
