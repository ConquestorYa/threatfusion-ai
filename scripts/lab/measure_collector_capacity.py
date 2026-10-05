"""Private synthetic 120-file/120k mixed-record scan and capacity measurement."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new

CONN_FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "missed_bytes",
)
DNS_FIELDS = (
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


def worker(root):
    from threatfusion.telemetry_collector import ZeekCollector
    from threatfusion.ui_collector import read_snapshot

    scans = []
    with ZeekCollector(root / "input", root / "state") as collector:
        for _ in range(3):
            started = time.perf_counter()
            status = collector.tick()
            scans.append(
                {"wall_seconds": time.perf_counter() - started, "status": status}
            )
        assert collector.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert scans[0]["status"]["scan"]["attempted_files"] == 64
    assert scans[0]["status"]["scan"]["remaining_candidates"] == 56
    assert scans[0]["status"]["counts"]["retained_total_records"] == 64_000
    assert scans[1]["status"]["scan"]["attempted_files"] == 56
    assert scans[1]["status"]["counts"]["retained_total_records"] == 100_000
    assert scans[1]["status"]["counts"]["trimmed_records"] == 20_000
    assert scans[1]["status"]["capacity_coverage_loss"]
    assert scans[2]["status"]["counts"]["new_records"] == 0
    assert not scans[2]["status"]["scan"]["analysis_recomputed"]
    assert all(scan["status"]["counts"]["rejected_files"] == 0 for scan in scans)
    snapshot = read_snapshot(root / "state")
    assert sum(row["Connections"] for row in snapshot["findings"]) == 40_000
    assert snapshot["dns"]["coverage"]["analyzed_events"] == 60_000
    assert all(not row["Declared expected"] for row in snapshot["findings"])
    write_new(root / "worker-proof.json", {"scans": scans, "integrity": "ok"})


def measure(root):
    source = root / "input"
    source.mkdir(mode=0o700)
    epoch = int(datetime.now(timezone.utc).timestamp()) - 120
    write_new(
        root / "plan.json",
        {
            "files": 120,
            "records_per_file": 1000,
            "mixed_records": 120_000,
            "shared_capacity": 100_000,
            "scans": 3,
            "scope": "Synthetic bounded files, two reserved client IPs, 16 .test names; no network traffic.",
            "expected": "64 attempts then 56; 20k visible capacity pruning; idle cache reuse; no rejection/resurrection.",
        },
    )
    hashes = {}
    for kind, fields, offset in (("conn", CONN_FIELDS, 0), ("dns", DNS_FIELDS, 60)):
        for file_id in range(60):
            rows = []
            for row_id in range(1000):
                number = (offset + file_id) * 1000 + row_id
                row = [
                    epoch + offset + file_id + row_id / 1000,
                    f"Cload{number}",
                    f"192.0.2.{11 + row_id % 2}",
                    40000 + row_id,
                    "198.51.100.53",
                    443 if kind == "conn" else 53,
                    "tcp" if kind == "conn" else "udp",
                ]
                row += (
                    [1, 100, 200, "SF", 0]
                    if kind == "conn"
                    else [
                        row_id,
                        f"load{row_id % 16}.test",
                        "A",
                        "NOERROR",
                        "198.51.100.53",
                    ]
                )
                rows.append("\t".join(map(str, row)))
            path = source / f"{kind}.{file_id:03d}.log"
            content = (
                "#separator \\x09\n#path\t"
                + kind
                + "\n#fields\t"
                + "\t".join(fields)
                + "\n"
                + "\n".join(rows)
                + "\n#close\t2026-10-05-00-00-00\n"
            )
            path.write_text(content)
            hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_new(root / "input-hashes.json", hashes)
    sampled_rss, sampled_disk = [], []
    with (
        (root / "worker.stdout").open("x") as stdout,
        (root / "worker.stderr").open("x") as stderr,
    ):
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "scripts.lab.measure_collector_capacity",
                "--root",
                str(root),
                "--worker",
            ],
            stdout=stdout,
            stderr=stderr,
        )
        try:
            while process.poll() is None:
                for line in (
                    Path(f"/proc/{process.pid}/status").read_text().splitlines()
                ):
                    if line.startswith("VmRSS:"):
                        sampled_rss.append(int(line.split()[1]) * 1024)
                state = root / "state"
                sampled_disk.append(
                    sum(p.stat().st_size for p in state.glob("*") if p.is_file())
                )
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        if process.returncode:
            raise ValueError("Measurement failed; inspect private worker stderr")
    proof = json.loads((root / "worker-proof.json").read_text())
    proof.update(
        {
            "peak_sampled_rss_bytes": max(sampled_rss),
            "peak_sampled_state_bytes": max(sampled_disk),
            "rss_sample_interval_seconds": 0.05,
            "limitations": "Single synthetic backlog, includes process RSS; excludes fixture creation. Not production throughput or a guaranteed peak. Capacity pruning is disclosed data loss, not complete retention.",
        }
    )
    write_new(root / "proof.json", proof)
    print(
        json.dumps(
            {
                "wall_seconds": [
                    round(scan["wall_seconds"], 3) for scan in proof["scans"]
                ],
                "rss_bytes": proof["peak_sampled_rss_bytes"],
                "state_bytes": proof["peak_sampled_state_bytes"],
                "contracts_passed": True,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.root)
    worker(root) if args.worker else measure(root)
