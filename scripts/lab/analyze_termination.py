"""Validate a predeclared short live workload without tuning detection gates."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from termination_workload import ATTEMPTS, MODES, PORT_BASE, plan
from threatfusion.connection_timeline import validate_timeline_report
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot


def analyze(directory: Path):
    directory = directory.resolve(strict=True)
    if (directory.is_relative_to(ROOT) or directory.stat().st_uid != os.getuid()
        or directory.stat().st_mode & 0o077):
        raise ValueError("Live results require an owner-only directory outside the repository")
    if any((directory / name).exists() or (directory / name).is_symlink()
           for name in ("collector-state", "collector-input", "connection-report.json", "proof.json")):
        raise ValueError("Existing analysis outputs are preserved; use a new result directory")
    manifest = json.loads((directory / "manifest.json").read_text())
    if manifest != plan():
        raise ValueError("Workload manifest differs from its predeclared contract")
    log = directory / "zeek" / "conn.log"
    raw = log.read_text()
    result, diagnostics = analyze_zeek_conn_log_with_diagnostics(raw, [], None)
    if (diagnostics.accepted_rows != ATTEMPTS * len(MODES)
        or diagnostics.invalid_connection_fields or diagnostics.invalid_timestamps
        or diagnostics.invalid_response_ips or diagnostics.skipped_missing_query_name):
        raise ValueError("Invalid or unexpected Zeek records")
    fields = []
    counts = Counter()
    for line in raw.splitlines():
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#"):
            row = dict(zip(fields, line.split("\t"), strict=True))
            counts[(int(row["id.resp_p"]), row["conn_state"])] += 1
    expected = Counter({(PORT_BASE + i, mode): ATTEMPTS for i, mode in enumerate(MODES)})
    if counts != expected:
        raise ValueError("Observed states differ from the predeclared per-port contract")
    capture = (directory / "capture.txt").read_text()
    if not re.search(r"^0 packets dropped by kernel$", capture, re.MULTILINE):
        raise ValueError("Capture drops are unknown or nonzero")
    if "Traceback" in (directory / "server.txt").read_text() or "Traceback" in (directory / "client.txt").read_text():
        raise ValueError("Live workload reported an error")
    if len(result.connection_findings) != len(MODES) or any(f.priority != "observe" for f in result.connection_findings):
        raise ValueError("Short-window connection queue differs from the declared contract")
    report = json.loads(build_connection_report(result))
    validate_timeline_report(report["timelines"], report["findings"])
    states = Counter()
    starts = 0
    for timeline in report["timelines"]["groups"]:
        if timeline["untimed_connections"]:
            raise ValueError("Live timeline contains missing time")
        for bucket in timeline["buckets"]:
            states.update(bucket["states"])
            starts += bucket["connections"]
    if states != Counter({mode: ATTEMPTS for mode in MODES}) or starts != ATTEMPTS * len(MODES):
        raise ValueError("Investigation summaries lost or invented live connection evidence")
    state = directory / "collector-state"
    source = directory / "collector-input"
    source.mkdir(mode=0o700)
    (source / "conn.log").write_bytes(log.read_bytes())
    with ZeekCollector(source, state) as collector:
        initial = collector.tick()
    snapshot = read_snapshot(state)
    if snapshot["findings"] != report["findings"] or snapshot["timelines"] != report["timelines"]:
        raise ValueError("Collector investigation differs from offline analysis")
    (source / "conn.copy.log.gz").write_bytes(gzip.compress(log.read_bytes()))
    with ZeekCollector(source, state) as collector:
        restart = collector.tick()
    if restart["counts"]["new_records"] != 0 or restart["counts"]["duplicate_files"] != 1:
        raise ValueError("Restart/gzip replay duplicated live evidence")
    if read_snapshot(state)["timelines"] != report["timelines"]:
        raise ValueError("Timeline changed after duplicate replay")
    proof = {"protocol": manifest["protocol"], "conn_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
             "pcap_sha256": hashlib.sha256((directory / "scenario.pcap").read_bytes()).hexdigest(),
             "accepted_rows": diagnostics.accepted_rows, "review_groups": 0,
             "states": dict(states), "timeline_starts": starts,
             "collector_imported": initial["counts"]["new_records"],
             "collector_restart_added": restart["counts"]["new_records"],
             "gzip_duplicate_files": restart["counts"]["duplicate_files"],
             "limitations": manifest["limitations"]}
    for name, payload in (("connection-report.json", report), ("proof.json", proof)):
        path = directory / name
        with path.open("x") as file:
            json.dump(payload, file, indent=2)
            file.write("\n")
        path.chmod(0o600)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(args.directory), indent=2))


if __name__ == "__main__":
    main()
