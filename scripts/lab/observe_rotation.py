"""Private local SSH relay + real collector lifecycle/resource/latency observation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from scripts.lab.evaluate_dns_collector import private_root, write_new

REPO = Path(__file__).resolve().parents[2]
REMOTE = """import sys,json,base64,hashlib
from pathlib import Path
root=Path.home()/"threatfusion-lab"/sys.argv[1]
files=[]
for p in sorted((root/"zeek").glob("*.log")):
 if not p.name.startswith(("dns.","conn.")) or p.is_symlink(): continue
 before=p.stat()
 if before.st_size>16*1024*1024: raise ValueError("oversized lab log")
 raw=p.read_bytes()
 after=p.stat()
 if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns): continue
 closed=bool(raw.rstrip().splitlines() and raw.rstrip().splitlines()[-1].startswith(b"#close\\t"))
 files.append({"name":p.name,"sha":hashlib.sha256(raw).hexdigest(),"data":base64.b64encode(raw).decode(),"closed":closed,"mtime":after.st_mtime})
print(json.dumps({"files":files,"done":(root/"images.txt").exists()}))
"""


def main(args):
    os.umask(0o077)
    root = private_root(args.root)
    if not re.fullmatch(r"results/rotation-live-\d{8}T\d{6}Z", args.run):
        raise ValueError("Use the new lab run identifier")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+@127\.0\.0\.1", args.target):
        raise ValueError("This harness is limited to the local lab SSH forward")
    source, state, frozen = (root / name for name in ("input", "state", "frozen-src"))
    source.mkdir(mode=0o700)
    frozen.mkdir(mode=0o700)
    package = frozen / "threatfusion"
    package.mkdir(mode=0o700)
    hashes = {}
    for path in sorted((REPO / "src/threatfusion").glob("*.py")):
        shutil.copyfile(path, package / path.name)
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_new(
        root / "source-freeze.json",
        {
            "runtime_modules": hashes,
            "ssh_run": args.run,
            "duration_seconds": args.seconds,
            "poll_seconds": 10,
        },
    )
    command = [
        sys.executable,
        "-m",
        "threatfusion.telemetry_collector",
        "--input-dir",
        str(source),
        "--state-dir",
        str(state),
        "--poll-seconds",
        "10",
    ]
    env = dict(os.environ, PYTHONPATH=str(frozen))
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={args.known_hosts}",
        "-o",
        "ConnectTimeout=5",
        "-i",
        str(args.key),
        "-p",
        str(args.port),
        args.target,
        "python3 -c " + shlex.quote(REMOTE) + " " + shlex.quote(args.run),
    ]
    stdout = (root / "collector.stdout").open("x")
    stderr = (root / "collector.stderr").open("x")
    process = None

    def start():
        return subprocess.Popen(
            command, env=env, stdout=stdout, stderr=stderr, cwd=root
        )

    def stop(force=False):
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGKILL if force else signal.SIGTERM)
            process.wait(timeout=10)

    receipts, samples, events, mirrored = {}, [], [], {}
    started, next_copy, next_message = time.monotonic(), 0, 0
    schedule = [(240, "sigterm"), (480, "sigkill"), (720, "pause")]
    if args.seconds < 900:
        schedule = []
    pause_until = None
    completed = False
    collector_ticks = set()
    try:
        process = start()
        while time.monotonic() - started < args.seconds + 150:
            elapsed = time.monotonic() - started
            if schedule and elapsed >= schedule[0][0]:
                _, action = schedule.pop(0)
                stop(action == "sigkill")
                events.append({"action": action, "elapsed_seconds": elapsed})
                if action == "pause":
                    pause_until = elapsed + 45
                else:
                    process = start()
            if pause_until is not None and elapsed >= pause_until:
                process = start()
                events.append({"action": "resume", "elapsed_seconds": elapsed})
                pause_until = None
            if process.poll() is not None and pause_until is None:
                raise ValueError(
                    "Collector process stopped unexpectedly; inspect private stderr"
                )
            if elapsed >= next_copy:
                incoming = json.loads(subprocess.check_output(ssh, timeout=15))
                completed = incoming["done"]
                for item in incoming["files"]:
                    name = item["name"]
                    if not re.fullmatch(
                        r"(?:dns|conn)[.][A-Za-z0-9_.-]+", name
                    ) or not name.endswith(".log"):
                        raise ValueError("Unexpected lab log name")
                    if mirrored.get(name) == item["sha"]:
                        continue
                    raw = base64.b64decode(item["data"], validate=True)
                    if (
                        len(raw) > 16 * 1024 * 1024
                        or hashlib.sha256(raw).hexdigest() != item["sha"]
                    ):
                        raise ValueError("Relay checksum/size mismatch")
                    descriptor, tmp = tempfile.mkstemp(dir=source)
                    with os.fdopen(descriptor, "wb") as file:
                        file.write(raw)
                        file.flush()
                        os.fsync(file.fileno())
                    os.replace(tmp, source / name)
                    mirrored[name] = item["sha"]
                    if item["closed"]:
                        receipts.setdefault(
                            item["sha"],
                            {
                                "name": name,
                                "closed_proxy_epoch": item["mtime"],
                                "delivered_epoch": time.time(),
                            },
                        )
                next_copy = elapsed + 5
            snapshot_path = state / "connections.json"
            if snapshot_path.exists():
                report = json.loads(snapshot_path.read_text())
                status = report["collector"]
                timestamp = datetime.fromisoformat(status["updated_at"]).timestamp()
                collector_ticks.add(status["updated_at"])
                try:
                    with sqlite3.connect(
                        "file:" + quote(str(state / "collector.sqlite")) + "?mode=ro",
                        uri=True,
                        timeout=0.2,
                    ) as db:
                        ledger = dict(db.execute("SELECT hash,ingested FROM files"))
                    for digest, receipt in receipts.items():
                        if (
                            digest in ledger
                            and timestamp >= ledger[digest]
                            and "snapshot_seen_epoch" not in receipt
                        ):
                            receipt["snapshot_seen_epoch"] = time.time()
                except sqlite3.OperationalError:
                    pass
                rss = 0
                if process.poll() is None:
                    for line in (
                        Path(f"/proc/{process.pid}/status").read_text().splitlines()
                    ):
                        if line.startswith("VmRSS:"):
                            rss = int(line.split()[1]) * 1024
                disk = sum(p.stat().st_size for p in state.iterdir() if p.is_file())
                sample = {
                    "elapsed_seconds": elapsed,
                    "rss_bytes": rss,
                    "state_disk_bytes": disk,
                    "retained_records": status["counts"]["retained_total_records"],
                    "scan_seconds": status.get("scan", {}).get(
                        "analysis_elapsed_seconds"
                    ),
                    "snapshot_timestamp": status["updated_at"],
                }
                samples.append(sample)
                if elapsed >= next_message:
                    print(
                        json.dumps(
                            {
                                "elapsed_seconds": round(elapsed),
                                "closed_files": len(receipts),
                                "retained": sample["retained_records"],
                                "collector_running": process.poll() is None,
                            }
                        ),
                        flush=True,
                    )
                    next_message = elapsed + 30
                if (
                    completed
                    and receipts
                    and all("snapshot_seen_epoch" in r for r in receipts.values())
                ):
                    break
            time.sleep(1)
        if (
            not completed
            or not receipts
            or not all("snapshot_seen_epoch" in r for r in receipts.values())
        ):
            raise ValueError(
                "Capture/catch-up did not complete within the declared observation window"
            )
    finally:
        stop()
        stdout.close()
        stderr.close()
        write_new(
            root / "observation.json",
            {
                "events": events,
                "samples": samples,
                "receipts": receipts,
                "completed": completed,
                "elapsed_seconds": time.monotonic() - started,
                "collector_ticks": len(collector_ticks),
            },
        )
    print(
        json.dumps(
            {
                "observation_complete": True,
                "root": str(root),
                "collector_ticks": len(collector_ticks),
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--target", default="lab@127.0.0.1")
    parser.add_argument("--port", type=int, default=22220)
    parser.add_argument("--seconds", type=int, default=1200)
    main(parser.parse_args())
