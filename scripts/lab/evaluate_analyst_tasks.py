"""Frozen synthetic analyst tasks; private outputs, no human efficacy claim.

Prepare before running pinned offline Zeek; evaluate complete logs afterwards.
Reuses the reviewed workload generator with new seeds, not independent traffic.
"""
from __future__ import annotations

import argparse
import gzip
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.lab.analyze_periodic import zeek_rows
from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.evaluate_review_workload import ZEEK_IMAGE, sha, validate_pcap, validate_synthetic
from scripts.lab.review_workload import DURATION, START, create, manifest
from threatfusion.dashboard import contextual_connection_rows
from threatfusion.dns_zeek import parse_zeek_dns_transactions
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.expected_connections import parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot
from threatfusion.ui_review_guidance import connection_steps, review_counts

REPO = Path(__file__).resolve().parents[2]
SEEDS = {"development": 20261071, "reserved": 20261171}
EXPECTED_ROLES = ("regular-updater", "jittered-updater", "cached-polling", "shared-resolver-normal", "normal-long-stream")
NOW = datetime.fromtimestamp(START + DURATION + 7200, timezone.utc)


def declared_plan():
    return {"protocol": "analyst-guidance-v1", "seeds": SEEDS, "expected_roles": list(EXPECTED_ROLES),
            "context_limits": {"max_connections": 100, "max_duration_seconds": 8000,
                               "max_originator_bytes": 100000, "max_responder_bytes": 100000},
            "cti_conflict_role": "regular-updater", "evaluated_at": NOW.isoformat(),
            "zeek_image": ZEEK_IMAGE,
            "limits": ["New synthetic seeds reuse an inspected generator; not independent real traffic.",
                       "Context represents separately supplied lab inventory, never inferred from periodicity.",
                       "Same-endpoint unrelated processes can match; original evidence remains.",
                       "No threshold/ML change, RITA ranking, malware accuracy or human-time claim."]}


def prepare(root):
    if root.exists():
        raise FileExistsError("Use a new private experiment root")
    root = private_root(root)
    plan = declared_plan()
    write_new(root / "plan.json", plan)
    files = list((REPO / "src/threatfusion").glob("*.py")) + [Path(__file__), REPO / "scripts/lab/run_analyst_tasks.sh",
            REPO / "scripts/lab/review_workload.py", REPO / "scripts/lab/evaluate_review_workload.py"]
    write_new(root / "source-freeze.json", {str(p.relative_to(REPO)): sha(p) for p in sorted(files)})
    for phase, seed in SEEDS.items():
        scenario = create(root / phase, seed)
        rules = []
        for index, name in enumerate(EXPECTED_ROLES):
            role = scenario["roles"][name]
            rules.append(dict(id=f"lab-inventory-{index}", originator_ip=role["client"], responder_ip=role["server"],
                              responder_port=8000, protocol="tcp",
                              valid_from=datetime.fromtimestamp(START - 3600, timezone.utc).isoformat(),
                              valid_until=datetime.fromtimestamp(START + 86400, timezone.utc).isoformat(),
                              **plan["context_limits"]))
        write_new(root / phase / "rules.json", {"schema_version": 1, "rules": rules})
    write_new(root / "input-freeze.json", {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob("*")) if p.is_file()})


def evaluate(root):
    private_root(root)
    if json.loads((root / "plan.json").read_text()) != declared_plan():
        raise ValueError("Declared task plan changed")
    for filename, digest in json.loads((root / "input-freeze.json").read_text()).items():
        if sha(root / filename) != digest:
            raise ValueError("Frozen task input changed")
    for filename, digest in json.loads((root / "source-freeze.json").read_text()).items():
        if sha(REPO / filename) != digest:
            raise ValueError("Frozen task source changed")
    if (root / "summary.json").exists():
        raise FileExistsError("Preserve previous task results")
    summary = {"protocol": "analyst-guidance-v1", "cases": [], "limits": declared_plan()["limits"]}
    for phase, seed in SEEDS.items():
        directory = root / phase
        if (directory / "zeek.exit").read_text().strip() != "0" or (directory / "image.txt").read_text().strip() != ZEEK_IMAGE:
            raise ValueError("Pinned complete offline Zeek required")
        packets = validate_pcap(directory / "scenario.pcap")
        conn_text = (directory / "zeek/conn.log").read_text()
        result, diagnostics = analyze_zeek_conn_log_with_diagnostics(conn_text, (), None)
        if any((diagnostics.invalid_timestamps, diagnostics.invalid_connection_fields, diagnostics.invalid_response_ips,
                diagnostics.skipped_missing_query_name)):
            raise ValueError("Invalid connection evidence")
        transactions = parse_zeek_dns_transactions((directory / "zeek/dns.log").read_text())
        validate_synthetic(manifest(seed), [r.event for r in transactions], zeek_rows(directory / "zeek/http.log"),
                           parse_zeek_conn_log_with_diagnostics(conn_text).connections)
        rules = parse_expected_connections((directory / "rules.json").read_bytes())
        before = contextual_connection_rows(result, evaluated_at=NOW)
        rows = contextual_connection_rows(result, rules, evaluated_at=NOW)
        for row in rows:
            if not connection_steps(row):
                raise ValueError("Missing task guidance")
        source = directory / "collector-input"
        source.mkdir(mode=0o700)
        for kind in ("conn", "dns"):
            shutil.copyfile(directory / f"zeek/{kind}.log", source / f"{kind}.log")
            (source / f"{kind}.log").chmod(0o600)
        state = directory / "collector-state"
        with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
            initial = collector.tick(rules=rules, now=NOW)
        snapshot = read_snapshot(state)
        offline = json.loads(build_connection_report(result, expected_rules=rules, evaluated_at=NOW, generated_at=NOW))
        if any(snapshot[key] != offline[key] for key in ("findings", "timelines", "attempts")):
            raise ValueError("Context offline/collector mismatch")
        if (initial["counts"]["rejected_files"] or initial["counts"]["trimmed_records"]
            or initial["counts"]["retained_total_records"] != len(result.events) + len(transactions)):
            raise ValueError("Incomplete collector retention")
        for kind in ("conn", "dns"):
            target = source / f"{kind}.copy.log.gz"
            target.write_bytes(gzip.compress((source / f"{kind}.log").read_bytes()))
            target.chmod(0o600)
        indicator = IOCRecord(manifest(seed)["roles"]["regular-updater"]["server"], IOCType.IPV4, "synthetic-task")
        cti_result, _ = analyze_zeek_conn_log_with_diagnostics(conn_text, [indicator], None)
        cti_rows = contextual_connection_rows(cti_result, rules, evaluated_at=NOW)
        with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
            repeat = collector.tick(rules=rules, now=NOW)
            duplicate = read_snapshot(state)
            collector.tick(rules=rules, indicators=[indicator], now=NOW)
            conflict = read_snapshot(state)
            collector.tick(rules=rules, now=NOW + timedelta(days=1))
            expired = read_snapshot(state)
        if (repeat["counts"]["new_records"] or repeat["counts"]["duplicate_files"] != 2
            or any(duplicate[key] != snapshot[key] for key in ("findings", "timelines", "attempts", "dns"))
            or conflict["findings"] != cti_rows
            or expired["findings"] != before):
            raise ValueError("Restart/copy/CTI/expiry task failed")
        # Context is the only additive difference: underlying queue/evidence unchanged.
        context_fields = {"Analyst context", "Context reason", "CTI match", "Declared expected"}
        if [{k: v for k, v in r.items() if k not in context_fields} for r in rows] != [
            {k: v for k, v in r.items() if k not in context_fields} for r in before]:
            raise ValueError("Original evidence changed")
        item = {"phase": phase, "seed": seed, "packets": packets, "conn_records": len(result.events),
                "dns_records": len(transactions), "before": review_counts(before), "declared": review_counts(rows),
                "cti_conflict": review_counts(cti_rows), "expired": review_counts(expired["findings"]),
                "offline_collector_restart_gzip_cti_expiry": True,
                "input_hashes": json.loads((directory / "input-hashes.json").read_text())}
        write_new(directory / "evaluation.json", item)
        summary["cases"].append(item)
    write_new(root / "summary.json", summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "evaluate"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.root)
        print("Private task inputs frozen; run offline Zeek before evaluation.")
    else:
        result = evaluate(args.root)
        print(json.dumps(result, indent=2))
