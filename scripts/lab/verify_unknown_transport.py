"""Evaluate a separately frozen enum-compatibility replay; not fresh detection evidence.

Prepare plan.json/plan.sha256 in a new private root BEFORE the parser repair:
baseline_runtime = all module hashes; permitted_change = network_telemetry.py;
sources = unchanged Zeek log hashes, copied into case/zeek directories.
Keep the original baseline exclusions intact. Candidate fingerprints are sealed
before this evaluator analyzes any replay and subsequent changes fail closed.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import timedelta
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.evaluate_review_workload import reconcile, sha, verify_hashes
from scripts.lab.independent_replay import REPO, runtime_hashes
from threatfusion.dns_zeek import parse_zeek_dns_transactions
from threatfusion.reporting import build_connection_report, build_device_report
from threatfusion.runtime_analysis import analyze_dns_events, analyze_zeek_conn_log_with_diagnostics


def evaluate(root, baseline_root):
    root, baseline_root = private_root(root), private_root(baseline_root)
    if sha(root / "plan.json") != (root / "plan.sha256").read_text().strip():
        raise ValueError("Compatibility plan changed")
    plan = json.loads((root / "plan.json").read_text())
    if plan["protocol"] not in {"unknown-transport-import-v1", "unknown-transport-connection-only-v1"} or plan["permitted_change"] != ["src/threatfusion/network_telemetry.py"]:
        raise ValueError("Unexpected compatibility scope")
    connection_only = plan["protocol"] == "unknown-transport-connection-only-v1"
    candidate = runtime_hashes()
    changes = sorted(path for path in set(candidate) | set(plan["baseline_runtime"]) if candidate.get(path) != plan["baseline_runtime"].get(path))
    if changes != plan["permitted_change"]:
        raise ValueError("Runtime differs outside permitted parser repair")
    if set(plan["sources"]) != {"normal-20", "normal-21", "malware-8"}:
        raise ValueError("Unexpected compatibility source identities")
    if (root / "summary.json").exists() or any((root / name / "collector-state").exists() for name in plan["sources"]):
        raise FileExistsError("Preserve previous compatibility outputs")
    for name, hashes in plan["sources"].items():
        allowed_paths = {"zeek/conn.log"} if connection_only else {"zeek/conn.log", "zeek/dns.log"}
        if "zeek/conn.log" not in hashes or set(hashes) - allowed_paths:
            raise ValueError("Unexpected compatibility input paths")
        if connection_only and (root / name / "zeek/dns.log").exists():
            raise ValueError("Unexpected DNS input in connection-only scope")
        verify_hashes(root / name, hashes)
        verify_hashes(baseline_root / name, hashes)
    freeze = {"runtime": candidate, "method_sha256": sha(Path(__file__)), "tests_sha256": sha(REPO / "tests/test_unknown_transport.py")}
    write_new(root / "candidate-freeze.json", freeze)
    results = []
    for name in plan["sources"]:
        directory = root / name
        conn, diagnostics = analyze_zeek_conn_log_with_diagnostics((directory / "zeek/conn.log").read_text(), (), None)
        if any((diagnostics.invalid_connection_fields, diagnostics.invalid_timestamps, diagnostics.invalid_response_ips, diagnostics.skipped_missing_query_name)):
            raise ValueError("Compatibility source still has invalid metadata")
        path = directory / "zeek/dns.log"
        transactions = parse_zeek_dns_transactions(path.read_text()) if path.exists() else ()
        dns = analyze_dns_events([t.event for t in transactions], (), None)
        now = max(e.timestamp for e in (*conn.events, *dns.events) if e.timestamp) + timedelta(seconds=1)
        proof = reconcile(directory, transactions, conn, now)
        connection = json.loads(build_connection_report(conn, generated_at=now, evaluated_at=now))
        device = json.loads(build_device_report(dns, generated_at=now))
        unchanged = name != "normal-21"
        if unchanged:
            pairs = [("offline-connections.json", connection)]
            if not connection_only:
                pairs.append(("offline-dns.json", device))
            for filename, report in pairs:
                previous = json.loads((baseline_root / name / filename).read_text())
                if connection_only:
                    # Conn-only max timestamp can differ from mixed-log clock.
                    for key in ("generated_at", "context_evaluated_at"):
                        previous.pop(key, None)
                        report = {k: v for k, v in report.items() if k != key}
                if report != previous:
                    raise ValueError("Known-source original output changed")
        write_new(directory / "offline-connections.json", connection)
        write_new(directory / "offline-dns.json", device)
        results.append({"case": name, "conn_rows": len(conn.events), "dns_rows": None if connection_only else len(transactions),
                        "tcp_groups": sum(f.protocol == "tcp" for f in conn.connection_findings),
                        "tcp_reviews": sum(f.protocol == "tcp" and f.priority == "review" for f in conn.connection_findings),
                        "dns_groups": None if connection_only else len(dns.device_findings), "dns_reviews": None if connection_only else sum(f.priority != "observe" for f in dns.device_findings),
                        "unknown_groups": sum(f.protocol == "unknown_transport" for f in conn.connection_findings),
                        "unknown_reviews": sum(f.protocol == "unknown_transport" and f.priority == "review" for f in conn.connection_findings),
                        "attempt_patterns": len(conn.connection_attempts.findings), "reconciliation": proof,
                        "baseline_full_connection_evidence_unchanged": True if unchanged else None,
                        "dns_evaluated": not connection_only})
    if freeze != {"runtime": runtime_hashes(), "method_sha256": sha(Path(__file__)), "tests_sha256": sha(REPO / "tests/test_unknown_transport.py")}:
        raise ValueError("Candidate changed during compatibility evaluation")
    for name, hashes in plan["sources"].items():
        verify_hashes(root / name, hashes)
        verify_hashes(baseline_root / name, hashes)
    summary = {"protocol": plan["protocol"], "runtime_changes": changes, "sources": results,
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
