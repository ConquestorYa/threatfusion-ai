"""Measure separate review units on frozen private Zeek/native RITA evidence.

Intent labels are evaluation metadata, never inputs to ThreatFusion. This does
not estimate malware accuracy, FPR, recall, analyst time or RITA equivalence.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import struct
from collections import Counter
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path

from scripts.lab.analyze_periodic import read_rita, zeek_rows
from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.review_workload import SHARED_RESOLVER, manifest
from threatfusion.dns_collection import build_dns_snapshot, transaction_payload
from threatfusion.dns_zeek import (
    parse_zeek_dns_log_with_diagnostics,
    parse_zeek_dns_transactions,
)
from threatfusion.reporting import build_connection_report, build_device_report
from threatfusion.runtime_analysis import (
    analyze_dns_events,
    analyze_zeek_conn_log_with_diagnostics,
)
from threatfusion.telemetry_collector import MAX_FILE_BYTES, MAX_RECORDS, ZeekCollector
from threatfusion.ui_collector import read_snapshot

REPO = Path(__file__).resolve().parents[2]
PLAN_SHA = "e0c146c41c809c35bd33cb30e0c6863621217e3365c5d97ddc0f3b5a24f0ee79"
CASES = ("development", "reserved", "somfy-02", "somfy-03", "trojan-42")
ZEEK_IMAGE = "activecm/zeek@sha256:3c2eeb0190881a2c1d194bcc6e820a88987d54a6cc5f6ed2a2b92f3e9f7df6c5"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_runtime(root):
    if sha(root / "plan.json") != PLAN_SHA:
        raise ValueError("Declared acquisition plan changed")
    expected = json.loads((root / "runtime-freeze.json").read_text())
    actual = {p.name: sha(p) for p in (REPO / "src/threatfusion").glob("*.py")}
    if actual != expected:
        raise ValueError("Runtime changed since preanalysis freeze")


def verify_hashes(directory, expected):
    for name, digest in expected.items():
        path = directory / name
        if Path(name).is_absolute() or not path.resolve().is_relative_to(
            directory.resolve()
        ):
            raise ValueError("Input path escapes experiment")
        if path.is_symlink() or sha(path) != digest:
            raise ValueError("Frozen input changed")


def freeze(root):
    """Seal acquired/generated inputs and native outputs before TF evaluation."""
    verify_runtime(root)
    plan = json.loads((root / "plan.json").read_text())
    cases = {}
    for name in CASES:
        directory = private_root(root / name)
        if name in ("development", "reserved"):
            generated = json.loads((directory / "manifest.json").read_text())
            if generated != manifest(plan["synthetic"][name + "_seed"]):
                raise ValueError("Unexpected phase manifest")
            verify_hashes(
                directory, json.loads((directory / "input-hashes.json").read_text())
            )
        else:
            source = next(s for s in plan["sources"] if s["name"] == name)
            acquired = json.loads((directory / "acquisition.json").read_text())
            if (
                acquired["url"] != source["url"]
                or acquired["bytes"] != source["head_bytes"]
                or sha(directory / "scenario.pcap") != acquired["sha256"]
            ):
                raise ValueError("Official acquisition differs from plan/receipt")
        before = (directory / "pre-analysis.sha256").read_text().split()
        if before[0] != sha(directory / "scenario.pcap"):
            raise ValueError("PCAP changed between acquisition and Zeek")
        stderr = (directory / "zeek.stderr").read_text()
        failed = "fatal error:" in stderr
        if not failed:
            if (directory / "image.txt").read_text().strip() != ZEEK_IMAGE:
                raise ValueError("Unexpected Zeek image")
            for line in (directory / "post-analysis.sha256").read_text().splitlines():
                digest, path = line.split(maxsplit=1)
                local = directory / (
                    "zeek/conn.log" if Path(path).name == "conn.log" else "rita.csv"
                )
                if sha(local) != digest:
                    raise ValueError("Native output changed after analysis")
        cases[name] = {
            "zeek_failed": failed,
            "hashes": {
                str(p.relative_to(directory)): sha(p)
                for p in directory.rglob("*")
                if p.is_file() and not p.is_symlink()
            },
        }
    tools = (
        "review_workload.py",
        "evaluate_review_workload.py",
        "run_review_offline.sh",
    )
    write_new(
        root / "evidence-freeze.json",
        {
            "cases": cases,
            "tooling": {name: sha(REPO / "scripts/lab" / name) for name in tools},
            "rita_contract_sha256": sha(root / "rita-contract.json"),
            "plan_sha256": sha(root / "plan.json"),
            "runtime_sha256": sha(root / "runtime-freeze.json"),
        },
    )


def validate_synthetic(plan, dns_events, http, connections):
    """Verify complete observations; labels are used only for reconciliation."""
    if plan != manifest(plan["seed"]):
        raise ValueError("Synthetic manifest differs from declared generator")
    roles, events = plan["roles"], plan["events"]
    expected_dns = Counter(
        (roles[e["role"]]["dns_origin"], roles[e["role"]]["domain"])
        for e in events
        if e["dns"]
    )
    observed_dns = Counter((e.client_ip, e.query_name) for e in dns_events)
    if expected_dns != observed_dns:
        raise ValueError("Captured DNS counts differ from manifest")
    expected_answers = Counter(
        (
            roles[e["role"]]["dns_origin"],
            roles[e["role"]]["domain"],
            "SERVFAIL" if roles[e["role"]]["schedule"] == "failure" else "NOERROR",
            None
            if roles[e["role"]]["schedule"] == "failure"
            else roles[e["role"]]["server"],
        )
        for e in events
        if e["dns"]
    )
    if (
        Counter(
            (e.client_ip, e.query_name, e.response_code, e.response_ip)
            for e in dns_events
        )
        != expected_answers
    ):
        raise ValueError("Captured DNS answers differ from manifest")
    expected_http = Counter(
        (roles[e["role"]]["client"], roles[e["role"]]["domain"], "/observe")
        for e in events
        if roles[e["role"]]["schedule"] != "failure"
    )
    if Counter(
        (r["id.orig_h"], r["host"], r["uri"]) for r in http
    ) != expected_http or any(r["status_code"] != "200" for r in http):
        raise ValueError("Captured HTTP differs from manifest")
    counts = Counter(e["role"] for e in events)
    expected_tcp = Counter(
        {
            (r["client"], r["server"], 8000): 1
            if r["schedule"] == "stream"
            else counts[name]
            for name, r in roles.items()
        }
    )
    if (
        Counter(
            (r.originator_ip, r.responder_ip, r.responder_port)
            for r in connections
            if r.protocol == "tcp"
        )
        != expected_tcp
    ):
        raise ValueError("Captured TCP starts differ from manifest")
    for r in connections:
        if r.protocol != "tcp":
            continue
        role = next(v for v in roles.values() if v["client"] == r.originator_ip)
        if r.missed_bytes != 0 or r.state != (
            "S0" if role["schedule"] == "failure" else "SF"
        ):
            raise ValueError("Captured TCP state/coverage differs from manifest")
        if role["schedule"] == "stream" and (
            r.duration_seconds is None or r.duration_seconds < 7000
        ):
            raise ValueError("Long stream did not remain a single long connection")


def role_metrics(plan, conn_result, dns_result, native):
    """Keep connection, DNS and native units separate, including shared origins."""
    rows = []
    for name, role in plan["roles"].items():
        source = role["client"]
        groups = [
            f
            for f in conn_result.connection_findings
            if f.protocol == "tcp" and f.originator_ip == source
        ]
        dns = [f for f in dns_result.device_findings if f.client_ip == source]
        rows.append(
            {
                "role": name,
                "intent": role["intent"],
                "tcp_groups": len(groups),
                "tcp_review_groups": sum(f.priority == "review" for f in groups),
                "tcp_reasons": [f.reasons for f in groups],
                "dns_endpoint_groups": len(dns),
                "dns_endpoint_review_groups": sum(f.priority != "observe" for f in dns),
                "dns_events": sum(f.assessment.behavior.event_count for f in dns),
                "dns_coverage_limits": [f.limitations for f in dns],
                "attempt_patterns": sum(
                    f.originator_ip == source
                    for f in conn_result.connection_attempts.findings
                ),
                "native_rows": sum(r["Source IP"] == source for r in native),
                "native_severities": dict(
                    Counter(r["Severity"] for r in native if r["Source IP"] == source)
                ),
                "shared_dns_origin": role["dns_origin"] != source,
            }
        )
    shared = [f for f in dns_result.device_findings if f.client_ip == SHARED_RESOLVER]
    return {
        "roles": rows,
        "shared_resolver": {
            "groups": len(shared),
            "review_groups": sum(f.priority != "observe" for f in shared),
            "events": sum(f.assessment.behavior.event_count for f in shared),
            "underlying_endpoint_attribution": False,
        },
        "by_intent": {
            intent: {
                key: sum(r[key] for r in rows if r["intent"] == intent)
                for key in (
                    "tcp_groups",
                    "tcp_review_groups",
                    "dns_endpoint_groups",
                    "dns_endpoint_review_groups",
                    "attempt_patterns",
                    "native_rows",
                )
            }
            for intent in ("benign", "controlled_simulation")
        },
    }


def validate_pcap(path):
    """Reject incomplete records rather than silently consuming a valid prefix."""
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("PCAP exceeds declared acquisition bound")
    with path.open("rb") as file:
        header = file.read(24)
        formats = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }
        if len(header) != 24 or header[:4] not in formats:
            raise ValueError("Invalid classic PCAP header")
        endian = formats[header[:4]]
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header[4:])
        if (
            (major, minor) != (2, 4)
            or link != 1
            or not 1 <= snaplen <= 16 * 1024 * 1024
        ):
            raise ValueError("Unsupported PCAP format or link type")
        packets = 0
        while record := file.read(16):
            if len(record) != 16:
                raise ValueError("Truncated PCAP record header")
            _, _, captured, original = struct.unpack(endian + "IIII", record)
            if captured > snaplen or captured > original:
                raise ValueError("Invalid PCAP record length")
            if len(file.read(captured)) != captured:
                raise ValueError("Truncated PCAP packet")
            packets += 1
    return packets


def reconcile(directory, transactions, conn_result, now):
    source = directory / "collector-input"
    source.mkdir(mode=0o700)
    kinds = ["conn"] + (["dns"] if (directory / "zeek/dns.log").exists() else [])
    for kind in kinds:
        shutil.copyfile(directory / f"zeek/{kind}.log", source / f"{kind}.log")
        (source / f"{kind}.log").chmod(0o600)
    state = directory / "collector-state"
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        initial = collector.tick(now=now)
    snap = read_snapshot(state)
    conn = json.loads(
        build_connection_report(conn_result, generated_at=now, evaluated_at=now)
    )
    dns = build_dns_snapshot(
        [transaction_payload(r) for r in transactions], (), generated_at=now
    )
    if (
        not all(snap[key] == conn[key] for key in ("findings", "timelines", "attempts"))
        or snap["dns"] != dns
    ):
        raise ValueError("Offline and collector reports differ")
    if (
        initial["counts"]["rejected_files"]
        or initial["counts"]["trimmed_records"]
        or initial["capacity_coverage_loss"]
    ):
        raise ValueError("Collector rejected or trimmed source evidence")
    if initial["counts"]["retained_total_records"] != len(conn_result.events) + len(
        transactions
    ):
        raise ValueError("Collector retained count differs from full source")
    for kind in kinds:
        (source / f"{kind}.copy.log.gz").write_bytes(
            gzip.compress((source / f"{kind}.log").read_bytes())
        )
        (source / f"{kind}.copy.log.gz").chmod(0o600)
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        repeat = collector.tick(now=now)
    restarted = read_snapshot(state)
    if (
        repeat["counts"]["new_records"]
        or repeat["counts"]["duplicate_files"] != len(kinds)
        or any(
            restarted[key] != snap[key]
            for key in ("findings", "timelines", "attempts", "dns")
        )
    ):
        raise ValueError("Restart/gzip reconciliation failed")
    return {
        "passed": True,
        "initial_counts": initial["counts"],
        "restart_counts": repeat["counts"],
    }


def evaluate(root, name):
    verify_runtime(root)
    evidence = json.loads((root / "evidence-freeze.json").read_text())
    if (
        any(
            sha(REPO / "scripts/lab" / tool) != digest
            for tool, digest in evidence["tooling"].items()
        )
        or sha(root / "rita-contract.json") != evidence["rita_contract_sha256"]
    ):
        raise ValueError("Evaluation tooling/configuration changed since freeze")
    directory = private_root(root / name)
    verify_hashes(directory, evidence["cases"][name]["hashes"])
    if evidence["cases"][name]["zeek_failed"]:
        try:
            validate_pcap(directory / "scenario.pcap")
            structural_error = None
        except ValueError as error:
            structural_error = str(error)
        result = {
            "case": name,
            "status": "excluded",
            "reason": "Offline Zeek failed; partial logs not evaluated",
            "structural_error": structural_error,
            "sha256": sha(directory / "scenario.pcap"),
        }
        write_new(directory / "evaluation.json", result)
        return result
    packet_count = validate_pcap(directory / "scenario.pcap")
    if any(
        (directory / f"zeek/{kind}.log").stat().st_size > MAX_FILE_BYTES
        for kind in ("conn", "dns")
        if (directory / f"zeek/{kind}.log").exists()
    ):
        raise ValueError(
            "Source exceeds existing collector file bound; do not truncate"
        )
    conn_text = (directory / "zeek/conn.log").read_text()
    conn_result, diagnostics = analyze_zeek_conn_log_with_diagnostics(
        conn_text, (), None
    )
    if any(
        (
            diagnostics.invalid_timestamps,
            diagnostics.invalid_connection_fields,
            diagnostics.invalid_response_ips,
            diagnostics.skipped_missing_query_name,
        )
    ):
        raise ValueError("Invalid connection evidence")
    dns_path = directory / "zeek/dns.log"
    parsed = (
        parse_zeek_dns_log_with_diagnostics(dns_path.read_text())
        if dns_path.exists()
        else None
    )
    transactions = (
        parse_zeek_dns_transactions(dns_path.read_text()) if dns_path.exists() else ()
    )
    if len(conn_result.events) + len(transactions) > MAX_RECORDS:
        raise ValueError("Full source exceeds shared capacity; do not sample")
    dns_result = analyze_dns_events([r.event for r in transactions], (), None)
    native = read_rita(directory / "rita.csv")
    if len(native) >= 100000 or any(
        None in row or any(v is None for v in row.values()) for row in native
    ):
        raise ValueError("Native export malformed or possibly capped")
    timestamps = [
        e.timestamp for e in (*conn_result.events, *dns_result.events) if e.timestamp
    ]
    if (
        not timestamps
        or (max(timestamps) - min(timestamps)).total_seconds() >= 7 * 86400
    ):
        raise ValueError("Full capture outside collector retention; do not shorten")
    now = max(timestamps) + timedelta(seconds=1)
    if name in ("development", "reserved"):
        plan = json.loads((directory / "manifest.json").read_text())
        from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics

        validate_synthetic(
            plan,
            dns_result.events,
            zeek_rows(directory / "zeek/http.log"),
            parse_zeek_conn_log_with_diagnostics(conn_text).connections,
        )
        workload = role_metrics(plan, conn_result, dns_result, native)
    else:
        plan = json.loads((root / "plan.json").read_text())
        workload = {
            "provider_capture_intent": next(
                s["provider_intent"] for s in plan["sources"] if s["name"] == name
            ),
            "per_group_truth_available": False,
        }
    proof = reconcile(directory, transactions, conn_result, now)
    for filename, text in (
        (
            "offline-connections.json",
            build_connection_report(conn_result, generated_at=now, evaluated_at=now),
        ),
        ("offline-dns.json", build_device_report(dns_result, generated_at=now)),
    ):
        write_new(directory / filename, json.loads(text))
    groups = conn_result.connection_findings
    result = {
        "case": name,
        "status": "evaluated",
        "cti_enabled": False,
        "ml_enabled": False,
        "label_input": False,
        "pcap_packets": packet_count,
        "source_sha256": sha(directory / "scenario.pcap"),
        "conn_diagnostics": asdict(diagnostics),
        "dns_diagnostics": asdict(parsed.diagnostics) if parsed else None,
        "dns_absent": not dns_path.exists(),
        "observed_span_seconds": (max(timestamps) - min(timestamps)).total_seconds(),
        "connection_groups": len(groups),
        "tcp_groups": sum(f.protocol == "tcp" for f in groups),
        "tcp_review_groups": sum(
            f.protocol == "tcp" and f.priority == "review" for f in groups
        ),
        "connection_coverage_limits": dict(
            Counter(reason for f in groups for reason in f.limitations)
        ),
        "dns_events": len(dns_result.events),
        "dns_groups": len(dns_result.device_findings),
        "dns_review_groups": sum(
            f.priority != "observe" for f in dns_result.device_findings
        ),
        "dns_coverage_limits": dict(
            Counter(
                reason for f in dns_result.device_findings for reason in f.limitations
            )
        ),
        "attempt_patterns": len(conn_result.connection_attempts.findings),
        "fallback_verdicts": dict(
            Counter(a.verdict.value for a in conn_result.assessments)
        ),
        "native_rows": len(native),
        "native_severities": dict(Counter(r["Severity"] for r in native)),
        "workload": workload,
        "reconciliation": proof,
        "limitations": [
            "Review units and native severities are not malware probabilities or comparable truth labels.",
            "Represented historical time uses a retrospective collector clock, not live wall time.",
            "DNS observations may be shared resolvers; they do not prove endpoint visits/downloads.",
            "All private reports retain telemetry; publish only manually reviewed aggregate results.",
        ],
    }
    write_new(directory / "evaluation.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "evaluate"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.root)
    if args.action == "freeze":
        freeze(root)
        print("Private input/native-output freeze complete")
        return
    if args.case is None:
        parser.error("Evaluation requires --case")
    result = evaluate(root, args.case)
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "case",
                    "status",
                    "tcp_groups",
                    "tcp_review_groups",
                    "dns_events",
                    "dns_groups",
                    "dns_review_groups",
                    "attempt_patterns",
                    "native_rows",
                )
                if k in result
            }
        )
    )


if __name__ == "__main__":
    main()
