"""Known-source ingestion regression; source accounting is not detection efficacy.

Use a new private root with the immutable bounded-log-preparation-v1 plan.
Before running, write evaluation-plan.json declaring both 100k/default and 20k
IoT-3 windows. Default unique-target/snapshot exclusions remain recorded failures;
the smaller window is a distinct arm, never substituted for full retention.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.evaluate_review_workload import sha, verify_hashes
from scripts.lab.independent_replay import REPO, runtime_hashes
from threatfusion.connections import ConnectionRecord
from threatfusion.dns import DNSEvent
from threatfusion.dns_collection import build_dns_snapshot, transaction_payload
from threatfusion.dns_zeek import parse_zeek_dns_transactions
from threatfusion.log_preparation import prepare_file, read_bundle
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_dns_events
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot

ALLOWED_CHANGES = {"src/threatfusion/log_preparation.py", "src/threatfusion/telemetry_collector.py",
                   "src/threatfusion/collector_health.py", "src/threatfusion/ui_collector.py", "src/threatfusion/i18n.py"}
KEYS = ("findings", "timelines", "attempts", "dns")


def candidate():
    return {"runtime": runtime_hashes(), "method_sha256": sha(Path(__file__)),
            "tests_sha256": sha(REPO / "tests/test_log_preparation.py")}


def verify_rows(source, bundle):
    """Independent byte/line conservation, including raw quarantined rows."""
    original = source.read_bytes().splitlines(keepends=True)
    data = read_bundle(bundle)
    if data["source_sha256"] != sha(source):
        raise ValueError("Prepared source digest differs")
    excluded = {}
    for text in (bundle / "quarantine.jsonl").read_text().splitlines():
        row = json.loads(text)
        raw = base64.b64decode(row["row_base64"], validate=True)
        if (row["line"] in excluded or raw != original[row["line"] - 1]
            or hashlib.sha256(raw).hexdigest() != row["sha256"]):
            raise ValueError("Quarantine does not preserve original evidence")
        excluded[row["line"]] = raw
    eligible = [raw for number, raw in enumerate(original, 1)
                if raw.strip() and not raw.startswith(b"#") and number not in excluded]
    prepared, records = [], []
    for item in data["shards"]:
        path = bundle / item["name"]
        if path.stat().st_size != item["bytes"] or sha(path) != item["sha256"]:
            raise ValueError("Prepared shard integrity differs")
        prepared.extend(raw for raw in path.read_bytes().splitlines(keepends=True) if raw.strip() and not raw.startswith(b"#"))
        text = path.read_text()
        records.extend(parse_zeek_dns_transactions(text) if data["kind"] == "dns"
                       else parse_zeek_conn_log_with_diagnostics(text).connections)
    if (eligible != prepared or len(records) != data["accepted_rows"]
        or data["source_rows"] != len(eligible) + len(excluded)):
        raise ValueError("Original rows differ from prepared/quarantined evidence")
    return data, records


def expected_payloads(connections, transactions, limit):
    values = {}
    for record in connections:
        row = asdict(record)
        row["timestamp"] = record.timestamp.isoformat() if record.timestamp else None
        text = json.dumps(row, sort_keys=True, separators=(",", ":"))
        values[hashlib.sha256(text.encode()).hexdigest()] = (record.timestamp.timestamp(), "conn", text)
    for record in transactions:
        text = transaction_payload(record)
        values[hashlib.sha256(text.encode()).hexdigest()] = (record.event.timestamp.timestamp(), "dns", text)
    watermark = max(v[0] for v in values.values())
    bounded = sorted(((v[0], key, v[1], v[2]) for key, v in values.items()
                      if v[0] >= watermark - 7 * 86400), key=lambda row: (-row[0], row[1]))[:limit]
    return sorted((row[1], row[2], row[3]) for row in bounded)


def run_arm(directory, source, connections, transactions, now, limit, default_exclusion=False):
    state = directory / f"state-{limit}"
    with ZeekCollector(source, state, window_seconds=7 * 86400, max_records=limit) as collector:
        try:
            status = collector.tick(now=now)
        except ValueError as error:
            exclusions = {"Collector report exceeds 64 MiB; use a smaller record window": "snapshot_exceeds_64MiB",
                          "DNS input exceeds the 25000 unique-query analysis limit": "unique_query_analysis_limit"}
            if not default_exclusion or str(error) not in exclusions:
                raise
            if sorted(collector.db.execute("SELECT hash,kind,payload FROM records")) != expected_payloads(connections, transactions, limit):
                raise ValueError("Excluded snapshot also has incorrect retained evidence") from None
            write_new(directory / f"failure-{limit}.json", {"reason": exclusions[str(error)], "retained": collector.db.execute("SELECT count(*) FROM records").fetchone()[0]})
            return {"max_records": limit, "passed": False, "exclusion": exclusions[str(error)], "retained_payloads_equal": True}
        actual = sorted(collector.db.execute("SELECT hash,kind,payload FROM records"))
        if actual != expected_payloads(connections, transactions, limit):
            raise ValueError("Retained evidence differs from independently calculated window")
        retained_conn, retained_dns = [], []
        for _, kind, text in actual:
            if kind == "dns":
                retained_dns.append(text)
            else:
                values = json.loads(text)
                values["timestamp"] = datetime.fromisoformat(values["timestamp"])
                retained_conn.append(ConnectionRecord(**values))
        result = analyze_dns_events([DNSEvent(r.responder_ip, r.timestamp, r.originator_ip, response_ip=r.responder_ip)
                                     for r in retained_conn], (), None, connections=retained_conn)
        offline = json.loads(build_connection_report(result, generated_at=now, evaluated_at=now))
        snap = read_snapshot(state)
        if (any(snap[k] != offline[k] for k in KEYS[:3])
            or snap["dns"] != build_dns_snapshot(retained_dns, (), generated_at=now)
            or status["counts"]["rejected_files"] or status["preparation"]["pending_files"]):
            raise ValueError("Collector/offline evidence differs or input remains pending")
    copies = source / "gzip-copies"
    if not copies.exists():
        copies.mkdir(mode=0o700)
        for number, file in enumerate(sorted(source.glob("*/*.log"))):
            path = copies / f"{file.name.split('.')[0]}.copy-{number}.log.gz"
            path.write_bytes(gzip.compress(file.read_bytes()))
            path.chmod(0o600)
    with ZeekCollector(source, state, window_seconds=7 * 86400, max_records=limit) as collector:
        repeat = collector.tick(now=now)
    restarted = read_snapshot(state)
    if repeat["counts"]["new_records"] or any(snap[key] != restarted[key] for key in KEYS):
        raise ValueError("Restart/gzip changed evidence")
    return {"max_records": limit, "passed": True, "counts": status["counts"], "preparation": status["preparation"],
            "capacity_coverage_loss": status["capacity_coverage_loss"], "input_coverage_loss": status["input_coverage_loss"],
            "restart_new_records": repeat["counts"]["new_records"], "restart_duplicate_files": repeat["counts"]["duplicate_files"],
            "retained_offline_timeline_restart_equal": True}


def evaluate(root, baseline):
    root, baseline = private_root(root), private_root(baseline)
    if sha(root / "plan.json") != (root / "plan.sha256").read_text().strip():
        raise ValueError("Preparation plan changed")
    plan = json.loads((root / "plan.json").read_text())
    declaration = json.loads((root / "evaluation-plan.json").read_text())
    if (plan["protocol"] != "bounded-log-preparation-v1" or declaration != {"iot3_windows": [100000, 20000],
                                                                           "allow_default_exclusions": ["unique_query_analysis_limit", "snapshot_exceeds_64MiB"],
                                                                           "quarantine_cases": ["normal-21", "malware-3"]}
        or set(plan["sources"]) != {"normal-20", "normal-21", "malware-3", "malware-8"}):
        raise ValueError("Unexpected preparation/evaluation scope")
    runtime = runtime_hashes()
    changes = {p for p in set(runtime) | set(plan["baseline_runtime"])
               if runtime.get(p) != plan["baseline_runtime"].get(p)}
    if changes != ALLOWED_CHANGES or (root / "candidate-freeze.json").exists():
        raise ValueError("Unexpected runtime changes or prior run")
    for name, hashes in plan["sources"].items():
        verify_hashes(baseline / name, hashes)
    freeze = candidate() | {"evaluation_plan_sha256": sha(root / "evaluation-plan.json")}
    write_new(root / "candidate-freeze.json", freeze)
    results = []
    for name, hashes in plan["sources"].items():
        directory = private_root(root / name)
        source = private_root(directory / "prepared")
        records, manifests = {}, {}
        for relative in hashes:
            kind = Path(relative).stem
            bundle = source / kind
            prepare_file(baseline / name / relative, bundle, quarantine_incomplete_dns=name in declaration["quarantine_cases"])
            manifests[kind], records[kind] = verify_rows(baseline / name / relative, bundle)
        connections, transactions = records["conn"], records.get("dns", ())
        now = max(r.timestamp for r in connections) + timedelta(seconds=1)
        if transactions:
            now = max(now, max(r.event.timestamp for r in transactions) + timedelta(seconds=1))
        arms = [run_arm(directory, source, connections, transactions, now, limit, default_exclusion=name == "malware-3" and limit == 100000)
                for limit in (declaration["iot3_windows"] if name == "malware-3" else [100000])]
        unchanged = None
        if name in {"normal-20", "malware-8"}:
            previous = json.loads((baseline / name / "collector-state/connections.json").read_text())
            latest = read_snapshot(directory / "state-100000")
            unchanged = all(previous[key] == latest[key] for key in KEYS)
            if not unchanged:
                raise ValueError("Known baseline findings/timelines changed")
        results.append({"case": name, "conn_source_rows": len(connections),
                        "dns_source_rows": manifests.get("dns", {}).get("source_rows", 0),
                        "dns_eligible_rows": len(transactions), "dns_quarantined_rows": manifests.get("dns", {}).get("quarantined_rows", 0),
                        "dns_quarantine_reasons": manifests.get("dns", {}).get("quarantine_reasons", {}),
                        "shard_files": sum(len(m["shards"]) for m in manifests.values()), "source_row_byte_conservation": True,
                        "baseline_full_findings_timelines_unchanged": unchanged, "arms": arms})
    if freeze != candidate() | {"evaluation_plan_sha256": sha(root / "evaluation-plan.json")}:
        raise ValueError("Candidate/method changed during evaluation")
    for name, hashes in plan["sources"].items():
        verify_hashes(baseline / name, hashes)
    summary = {"protocol": plan["protocol"], "runtime_changes": sorted(changes), "sources": results,
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
