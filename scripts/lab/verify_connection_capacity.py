"""Frozen known-source and reserved-address capacity/recovery engineering checks.

Use a new private root with immutable connection-capacity-v1 plan/evaluation
declaration before candidate evaluation. No capture acquisition/transmission,
malware execution, threshold tuning, fresh detection or enterprise claim.
"""
from __future__ import annotations

import argparse
import gc
import gzip
import ipaddress
import json
import os
import resource
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.evaluate_review_workload import sha, verify_hashes
from scripts.lab.independent_replay import REPO, runtime_hashes
from scripts.lab.verify_log_preparation import expected_payloads, verify_rows
from threatfusion.connections import ConnectionRecord
from threatfusion.collector_reports import read_archive
from threatfusion.dns_collection import build_dns_snapshot
from threatfusion.log_preparation import prepare_file
from threatfusion.reporting import connection_report_payload
from threatfusion.runtime_analysis import analyze_connection_records
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot

KEYS = ("findings", "timelines", "attempts", "dns")


def fingerprints():
    return {"runtime": runtime_hashes(), "method_sha256": sha(Path(__file__)),
            "tests_sha256": sha(REPO / "tests/test_connection_capacity.py"),
            "oracle_sha256": sha(REPO / "scripts/lab/verify_log_preparation.py")}


def complete_report(state):
    snapshot = read_snapshot(state)
    return json.loads(gzip.decompress(read_archive(state, snapshot["full_report"]))) if "full_report" in snapshot else snapshot


def retained_analysis(actual, now):
    records, dns = [], []
    for _, kind, text in actual:
        if kind == "dns":
            dns.append(text)
        else:
            values = json.loads(text)
            values["timestamp"] = datetime.fromisoformat(values["timestamp"]) if values["timestamp"] else None
            records.append(ConnectionRecord(**values))
    result = analyze_connection_records(records)
    expected = connection_report_payload(result, generated_at=now, evaluated_at=now)
    expected["dns"] = build_dns_snapshot(dns, (), generated_at=now)
    # Canonical JSON arrays match decoded exports, not Python dataclass tuples.
    return json.loads(json.dumps(expected))


def check_arm(directory, source, connections, transactions, now, baseline_report=None):
    state = directory / "collector-state"
    started = time.perf_counter()
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        initial = collector.tick(now=now)
        actual = sorted(collector.db.execute("SELECT hash,kind,payload FROM records"))
        if actual != expected_payloads(connections, transactions, 100000):
            raise ValueError("Full retained payloads differ from independent window oracle")
        full = complete_report(state)
        expected = retained_analysis(actual, now)
        if any(full[key] != expected[key] for key in KEYS):
            raise ValueError("Full export differs from retained offline analysis")
        if initial["counts"]["rejected_files"] or initial["preparation"]["pending_files"]:
            raise ValueError("Capacity replay has rejected/pending input")
        if baseline_report and any(full[key] != baseline_report[key] for key in KEYS):
            raise ValueError("Original known-source evidence changed")
        first_seconds = time.perf_counter()-started
        snapshot = read_snapshot(state)
        archive_reference = snapshot.get("full_report")
        started = time.perf_counter()
        idle = collector.tick(now=now)
        idle_seconds = time.perf_counter()-started
        if idle["counts"]["new_records"] or (archive_reference and not idle["scan"]["archive_reused"]):
            raise ValueError("Idle replay regenerated evidence/archive")
        if archive_reference != read_snapshot(state).get("full_report"):
            raise ValueError("Idle archive reference changed")
    copies = source / "gzip-copies"
    copies.mkdir(mode=0o700)
    files = sorted(source.glob("*/*.log")) if any(source.glob("*/*.log")) else sorted(source.glob("*.log"))
    for number, file in enumerate(files):
        copy = copies / f"{file.name.split('.')[0]}.copy-{number}.log.gz"
        copy.write_bytes(gzip.compress(file.read_bytes()))
        copy.chmod(0o600)
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        repeated = collector.tick(now=now)
    after = complete_report(state)
    if repeated["counts"]["new_records"] or any(full[key] != after[key] for key in KEYS):
        raise ValueError("Full restart/gzip evidence differs")
    return {"counts": initial["counts"], "preparation": initial["preparation"],
            "capacity_coverage_loss": initial["capacity_coverage_loss"], "input_coverage_loss": initial["input_coverage_loss"],
            "snapshot_groups": len(snapshot["findings"]), "connection_coverage": snapshot.get("connection_coverage"),
            "archive_expanded_bytes": archive_reference["expanded_bytes"] if archive_reference else None,
            "archive_compressed_bytes": archive_reference["compressed_bytes"] if archive_reference else None,
            "initial_wall_seconds": round(first_seconds, 3), "idle_wall_seconds": round(idle_seconds, 3),
            "idle_archive_reused": idle["scan"]["archive_reused"], "restart_new_records": repeated["counts"]["new_records"],
            "gzip_duplicates": repeated["counts"]["duplicate_files"], "retained_payloads_offline_full_export_equal": True,
            "baseline_full_evidence_unchanged": True if baseline_report else None}


def synthetic(directory, declaration):
    source = private_root(directory / "source")
    fields = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration", "orig_bytes", "resp_bytes", "conn_state", "missed_bytes")
    start = datetime.fromisoformat(declaration["timestamp_start"])
    target = int(ipaddress.IPv6Address(declaration["target_base"]))
    rows, records = [], []
    for index in range(declaration["records"]):
        timestamp = start + timedelta(seconds=index*declaration["step_seconds"])
        ip = str(ipaddress.IPv6Address(target+index))
        uid = declaration["uids"].format(index=index)
        values = (timestamp.timestamp(), uid, declaration["source"], 45000, ip, declaration["responder_port"],
                  declaration["protocol"], declaration["duration_seconds"], declaration["orig_bytes"], declaration["resp_bytes"], declaration["state"], 0)
        rows.append("\t".join(map(str, values))+"\n")
        records.append(ConnectionRecord(uid, timestamp, declaration["source"], ip, 45000, declaration["responder_port"], declaration["protocol"],
                                        float(declaration["duration_seconds"]), declaration["orig_bytes"], declaration["resp_bytes"], declaration["state"], 0))
    path = source / "conn.synthetic.log"
    path.write_text("#separator \\x09\n#path\tconn\n#fields\t"+"\t".join(fields)+"\n"+"".join(rows)+"#close\tcontrolled\n")
    path.chmod(0o600)
    write_new(directory / "source-freeze.json", {"sha256": sha(path), "records": len(records), "declaration": declaration})
    return source, records, records[-1].timestamp + timedelta(seconds=1)


def kill_recovery(directory, source, now):
    state = directory / "collector-state"
    snapshot = (state / "connections.json").read_bytes()
    reference = read_snapshot(state)["full_report"]
    previous = read_archive(state, reference)
    existing = set(state.glob(".collector-archive-*"))
    with (directory / "killed.stdout").open("xb") as stdout, (directory / "killed.stderr").open("xb") as stderr:
        child = subprocess.Popen([sys.executable, "-m", "threatfusion.telemetry_collector", "--input-dir", str(source),
                                  "--state-dir", str(state), "--window-hours", "168", "--once"], cwd=REPO, stdout=stdout, stderr=stderr)
        deadline, interrupted = time.monotonic()+120, None
        try:
            while child.poll() is None and time.monotonic() < deadline:
                stages = [p for p in state.glob(".collector-archive-*") if p not in existing and p.stat().st_size > 32768]
                if stages:
                    interrupted = {"stage_bytes": stages[0].stat().st_size}
                    child.kill()  # Only this explicitly spawned own process.
                    break
                time.sleep(0.025)
            code = child.wait(timeout=10)
            if interrupted is None or code != -signal.SIGKILL:
                raise ValueError("Declared archive interruption was not observed")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
    if (state / "connections.json").read_bytes() != snapshot or read_archive(state, reference) != previous:
        raise ValueError("Killed writer changed previously published snapshot/archive")
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        restored = collector.tick(now=now)
    full = complete_report(state)
    if restored["counts"]["new_records"] or restored["counts"]["retained_records"] != 100000 or len(full["findings"]) != 100000:
        raise ValueError("Recovery changed retained evidence")
    return interrupted | {"killed_process_exit": code, "previous_snapshot_archive_unchanged": True,
                          "restart_new_records": 0, "full_retained_groups": len(full["findings"]),
                          "private_unpublished_stages": len(set(state.glob(".collector-archive-*"))-existing)}


def evaluate(root, baseline):
    root, baseline = private_root(root), private_root(baseline)
    if sha(root / "plan.json") != (root / "plan.sha256").read_text().strip():
        raise ValueError("Capacity plan changed")
    plan = json.loads((root / "plan.json").read_text())
    declaration = json.loads((root / "evaluation-plan.json").read_text())
    runtime = runtime_hashes()
    changes = sorted(p for p in set(runtime) | set(plan["baseline_runtime"]) if runtime.get(p) != plan["baseline_runtime"].get(p))
    if (plan["protocol"] != "connection-capacity-v1" or changes != sorted(plan["permitted_runtime_changes"])
        or declaration["primary_max_records"] != 100000 or declaration["synthetic"]["records"] != 100000
        or set(declaration["known_cases"]) != set(plan["sources"]) or set(declaration["quarantine_cases"]) != {"normal-21", "malware-3"}):
        raise ValueError("Unexpected capacity scope")
    for name, hashes in plan["sources"].items():
        verify_hashes(baseline / name, hashes)
    freeze = fingerprints() | {"evaluation_plan_sha256": sha(root / "evaluation-plan.json")}
    write_new(root / "candidate-freeze.json", freeze)
    results = []
    for name, hashes in plan["sources"].items():
        directory = private_root(root / name)
        source = private_root(directory / "prepared")
        records, manifests = {}, {}
        for relative in hashes:
            kind = Path(relative).stem
            prepare_file(baseline / name / relative, source / kind, quarantine_incomplete_dns=name in declaration["quarantine_cases"])
            manifests[kind], records[kind] = verify_rows(baseline / name / relative, source / kind)
        now = max(record.timestamp for record in records["conn"]) + timedelta(seconds=1)
        if records.get("dns"):
            now = max(now, max(t.event.timestamp for t in records["dns"]) + timedelta(seconds=1))
        previous = json.loads((baseline / name / "collector-state/connections.json").read_text()) if name in {"normal-20", "malware-8"} else None
        proof = check_arm(directory, source, records["conn"], records.get("dns", ()), now, previous)
        results.append({"case": name, "source_rows": sum(m["source_rows"] for m in manifests.values()),
                        "eligible_rows": sum(m["accepted_rows"] for m in manifests.values()),
                        "quarantined_rows": sum(m["quarantined_rows"] for m in manifests.values()), "proof": proof})
        del records, previous
        gc.collect()
    directory = private_root(root / "synthetic-100k")
    source, records, now = synthetic(directory, declaration["synthetic"])
    proof = check_arm(directory, source, records, (), now)
    killed = kill_recovery(directory, source, now)
    if sha(source / "conn.synthetic.log") != json.loads((directory / "source-freeze.json").read_text())["sha256"]:
        raise ValueError("Synthetic source changed")
    if freeze != fingerprints() | {"evaluation_plan_sha256": sha(root / "evaluation-plan.json")}:
        raise ValueError("Candidate/method changed during replay")
    for name, hashes in plan["sources"].items():
        verify_hashes(baseline / name, hashes)
    summary = {"protocol": plan["protocol"], "runtime_changes": changes, "sources": results,
               "synthetic_100k": proof, "kill_recovery": killed,
               "process_peak_rss_MiB": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024, 1),
               "new_independent_detection_evidence": False, "baseline_exclusions_preserved": True}
    write_new(root / "summary.json", summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(evaluate(args.root, args.baseline_root), indent=2))
