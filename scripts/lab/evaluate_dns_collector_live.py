"""Freeze the DNS collector candidate and verify a new isolated live recording."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from scripts.lab.dns_collector_workload import plan
from scripts.lab.evaluate_dns_collector import private_root, write_new

REPO = Path(__file__).resolve().parents[2]


def fingerprints():
    paths = list((REPO / "src/threatfusion").glob("*.py")) + [
        REPO / "scripts/lab/dns_collector_workload.py",
        REPO / "scripts/lab/run_dns_collector_live.sh",
        REPO / "scripts/lab/evaluate_dns_collector.py",
        REPO / "scripts/lab/evaluate_dns_collector_live.py",
    ]
    return {
        str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
    }


def freeze(root):
    write_new(
        root / "source-freeze.json",
        {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "fingerprints": fingerprints(),
            "inputs": {
                name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in ("plan.json", "development.json", "reserved.json")
            },
            "live_contract": plan(),
        },
    )


def verify_freeze(root):
    frozen = json.loads((root / "source-freeze.json").read_text())
    assert frozen["fingerprints"] == fingerprints(), "Candidate changed since freeze"
    assert all(
        hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        for name, digest in frozen["inputs"].items()
    )
    return frozen


def live(root, capture):
    from threatfusion.dns_zeek import parse_zeek_dns_transactions
    from threatfusion.reporting import build_connection_report, build_device_report
    from threatfusion.runtime_analysis import (
        analyze_dns_events,
        analyze_zeek_conn_log_with_diagnostics,
    )
    from threatfusion.telemetry_collector import ZeekCollector
    from threatfusion.ui_collector import read_snapshot

    frozen = verify_freeze(root)
    capture = private_root(capture)
    manifest = json.loads((capture / "manifest.json").read_text())
    assert manifest == plan()
    # Hashes written before packet capture, verified against frozen local scripts.
    rows = (capture / "pre-capture.sha256").read_text().splitlines()
    assert len(rows) == 3
    for row in rows:
        digest, name = row.split(maxsplit=1)
        filename = Path(name).name
        assert filename in (
            "manifest.json",
            "dns_collector_workload.py",
            "run_dns_collector_live.sh",
        )
        local = (
            capture / filename
            if filename == "manifest.json"
            else REPO / "scripts/lab" / filename
        )
        assert hashlib.sha256(local.read_bytes()).hexdigest() == digest
    capture_text = (capture / "capture.txt").read_text()
    assert "0 packets dropped by kernel" in capture_text
    dns_text = (capture / "zeek/dns.log").read_text()
    conn_text = (capture / "zeek/conn.log").read_text()
    transactions = parse_zeek_dns_transactions(dns_text)
    assert len(transactions) == manifest["expected_dns_records"]
    transports = Counter(record.protocol for record in transactions)
    codes = Counter(
        record.event.response_code or "unanswered" for record in transactions
    )
    assert transports == {"udp": 12, "tcp": 12}
    assert codes == {"NOERROR": 8, "NXDOMAIN": 6, "SERVFAIL": 6, "unanswered": 4}
    conn_result, diagnostics = analyze_zeek_conn_log_with_diagnostics(
        conn_text, (), None
    )
    assert len(conn_result.events) == manifest["expected_connection_records"]
    assert not any(
        (
            diagnostics.invalid_timestamps,
            diagnostics.invalid_connection_fields,
            diagnostics.invalid_response_ips,
            diagnostics.skipped_missing_query_name,
        )
    )
    dns_result = analyze_dns_events([record.event for record in transactions], (), None)
    source = capture / "collector-input"
    source.mkdir(mode=0o700)
    for name in ("conn.log", "dns.log"):
        shutil.copyfile(capture / "zeek" / name, source / name)
        (source / name).chmod(0o600)
    state = capture / "collector-state"
    with ZeekCollector(source, state) as collector:
        initial = collector.tick()
    snapshot = read_snapshot(state)
    offline = json.loads(build_connection_report(conn_result))
    assert all(
        snapshot[key] == offline[key] for key in ("findings", "timelines", "attempts")
    )
    assert (
        snapshot["dns"]["report"]["findings"]
        == json.loads(build_device_report(dns_result))["findings"]
    )
    assert (
        initial["counts"]["dns_review_groups"] == manifest["expected_dns_review_groups"]
    )
    for name in ("conn", "dns"):
        (source / f"{name}.copy.log.gz").write_bytes(
            gzip.compress((source / f"{name}.log").read_bytes())
        )
    with ZeekCollector(source, state) as collector:
        restarted = collector.tick()
    assert (
        restarted["counts"]["new_records"] == 0
        and restarted["counts"]["duplicate_files"] == 2
    )
    assert (
        read_snapshot(state)["dns"]["report"]["findings"]
        == snapshot["dns"]["report"]["findings"]
    )
    proof = {
        "initial_counts": initial["counts"],
        "restart_counts": restarted["counts"],
        "transports": dict(transports),
        "response_codes": dict(codes),
        "dns_uids": len({record.uid for record in transactions}),
        "offline_collector_equal": True,
        "reported_kernel_drops": 0,
        "capture_name": capture.name,
        "source_freeze_sha256": hashlib.sha256(
            (root / "source-freeze.json").read_bytes()
        ).hexdigest(),
        "source_modules": len(frozen["fingerprints"]),
        "input_hashes": {
            name: hashlib.sha256((capture / "zeek" / name).read_bytes()).hexdigest()
            for name in ("conn.log", "dns.log")
        },
        "limitations": "Short synthetic DNS plumbing only; not independent benign FPR, malware recall, sensor visibility or tunneling coverage.",
    }
    write_new(capture / "proof.json", proof)
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "live", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.root)
    if args.action == "freeze":
        freeze(root)
    elif args.action == "verify":
        verify_freeze(root)
    elif args.capture_dir is None:
        parser.error("Live evaluation requires --capture-dir")
    else:
        live(root, args.capture_dir)
