"""Freeze a TCP-attempt candidate, then acquire one new official log and live controls."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from urllib.request import urlopen

from scripts.lab.attempt_workload import plan as live_plan
from scripts.lab.evaluate_iot23 import ATTRIBUTION, ROOT as SOURCE_ROOT, strip_labels
from threatfusion.connection_attempts import POLICY_ID, validate_attempt_report
from threatfusion.reporting import build_connection_report
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "b00fc836367c7ff0f408c6d1bd56d1130a7d5d59"
SOURCE = SOURCE_ROOT + "CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled"
MAX_BYTES = 4 * 1024 * 1024
MODULES = (
    "connection_attempts",
    "connections",
    "connection_timeline",
    "runtime_analysis",
    "network_telemetry",
    "reporting",
    "dashboard",
    "expected_connections",
    "dns",
    "dns_behavior",
    "hybrid_assessment",
    "matching",
    "normalization",
    "models",
    "device_triage",
)


def write(path, content):
    with path.open("xb") as file:
        file.write(content if isinstance(content, bytes) else content.encode())
    path.chmod(0o600)


def private_directory(directory):
    directory = directory.resolve(strict=True)
    if (
        directory.is_relative_to(ROOT)
        or directory.stat().st_uid != os.getuid()
        or directory.stat().st_mode & 0o077
    ):
        raise ValueError("Experiment results require a private directory outside Git")
    return directory


def fingerprints():
    return {
        name: hashlib.sha256(
            (ROOT / "src/threatfusion" / (name + ".py"))
            .read_bytes()
            .replace(b"\r\n", b"\n")
        ).hexdigest()
        for name in MODULES
    }


def freeze(directory):
    directory = private_directory(directory)
    manifest = {
        "protocol": "tcp-attempt-sources-v1",
        "policy": POLICY_ID,
        "baseline_commit": BASELINE,
        "official_url": SOURCE,
        "max_bytes": MAX_BYTES,
        "head_bytes_before_freeze": 1431000,
        "selection": "Previously uninspected capture selected by HEAD size only; 33-1 and 9-1 exceeded the byte bound. No traffic bodies inspected.",
        "attribution": ATTRIBUTION,
        "license_record": "https://zenodo.org/api/records/4743746",
        "live_contract": live_plan(),
        "fingerprints": fingerprints(),
        "control_manifests": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("plan.json", "development.json", "reserved.json")
        },
        "limitations": [
            "One old IoT malware capture, no new independent benign capture; not representative enterprise traffic.",
            "Live controls are synthetic; control expectations/provider labels are not malware truth.",
            "No ML/CTI/rules, threshold tuning, native RITA or accuracy/parity claim.",
        ],
    }
    write(directory / "source-freeze.json", json.dumps(manifest, indent=2) + "\n")
    write(
        directory / "source-freeze.sha256",
        hashlib.sha256((directory / "source-freeze.json").read_bytes()).hexdigest()
        + "\n",
    )


def verify_freeze(directory):
    raw = (directory / "source-freeze.json").read_bytes()
    if (
        hashlib.sha256(raw).hexdigest()
        != (directory / "source-freeze.sha256").read_text().strip()
    ):
        raise ValueError("Source freeze changed")
    manifest = json.loads(raw)
    if manifest["fingerprints"] != fingerprints():
        raise ValueError("Candidate changed; use the recorded frozen source revision")
    for name, digest in manifest["control_manifests"].items():
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
            raise ValueError("Declared control inputs changed")
    return manifest


def collector_proof(directory, clean_path, report):
    source = directory / "collector-input"
    source.mkdir(mode=0o700)
    raw = clean_path.read_bytes()
    # Older official files do not consistently include a final #close marker.
    if not raw.rstrip().splitlines()[-1].startswith(b"#close\t"):
        raw += b"#close\tcompleted-offline-copy\n"
    write(source / "conn.log", raw)
    state = directory / "collector-state"
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        initial = collector.tick()
    snapshot = read_snapshot(state)
    for key in ("findings", "timelines", "attempts"):
        if snapshot[key] != report[key]:
            raise ValueError("Offline/collector mismatch")
    write(source / "conn.copy.log.gz", gzip.compress(raw))
    with ZeekCollector(source, state, window_seconds=7 * 86400) as collector:
        restarted = collector.tick()
    if (
        restarted["counts"]["new_records"] != 0
        or restarted["counts"]["duplicate_files"] != 1
    ):
        raise ValueError("Restart/gzip replay duplicated evidence")
    if read_snapshot(state)["attempts"] != report["attempts"]:
        raise ValueError("Attempt findings changed on restart")
    return {
        "imported": initial["counts"]["new_records"],
        "restart_added": 0,
        "gzip_duplicate_files": 1,
    }


def evaluate_official(directory, baseline):
    directory = private_directory(directory)
    manifest = verify_freeze(directory)
    # Verify archived baseline files against trusted Git objects, not input-provided paths.
    baseline = baseline.resolve(strict=True)
    for name in MODULES:
        if name == "connection_attempts":
            continue
        path = "src/threatfusion/" + name + ".py"
        trusted = subprocess.check_output(
            ["git", "show", BASELINE + ":" + path], cwd=ROOT
        )
        if (baseline / path).read_bytes() != trusted:
            raise ValueError("Trusted baseline source mismatch")
    with urlopen(manifest["official_url"], timeout=30) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError(
            "Reserved source exceeds declared byte limit; do not replace after inspection"
        )
    target = directory / "official-8-1"
    target.mkdir(mode=0o700)
    write(target / "original.labeled", raw)
    text, labels = strip_labels(raw.decode())
    clean = target / "conn.log"
    write(clean, text)
    result, diagnostics = analyze_zeek_conn_log_with_diagnostics(text, [], None)
    report = json.loads(build_connection_report(result))
    validate_attempt_report(report["attempts"])
    write(target / "candidate-report.json", json.dumps(report, indent=2) + "\n")
    worker = "import sys,json;sys.path[:0]=[sys.argv[1],sys.argv[1]+'/src'];from pathlib import Path;from collections import Counter;from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics;from threatfusion.reporting import build_connection_report;r,d=analyze_zeek_conn_log_with_diagnostics(Path(sys.argv[2]).read_text(),[],None);p=json.loads(build_connection_report(r));print(json.dumps({'findings':p['findings'],'timelines':p['timelines'],'verdicts':dict(Counter(a.verdict.value for a in r.assessments))}))"
    old = subprocess.run(
        [sys.executable, "-c", worker, str(baseline), str(clean)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    old = json.loads(old.stdout)
    if (
        old["findings"] != report["findings"]
        or old["timelines"] != report["timelines"]
        or old["verdicts"] != dict(Counter(a.verdict.value for a in result.assessments))
    ):
        raise ValueError("Original findings/verdicts changed from trusted baseline")
    proof = {
        "source": "CTU-IoT-Malware-Capture-8-1",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "accepted_rows": diagnostics.accepted_rows,
        "invalid_connection_fields": diagnostics.invalid_connection_fields,
        "invalid_timestamps": diagnostics.invalid_timestamps,
        "skipped_rows": diagnostics.skipped_missing_query_name,
        "original_groups": len(result.connection_findings),
        "original_reviews": sum(
            f.priority == "review" for f in result.connection_findings
        ),
        "attempt_patterns": dict(
            Counter(f.pattern for f in result.connection_attempts.findings)
        ),
        "eligible_records": result.connection_attempts.eligible_records,
        "excluded_tcp_records": result.connection_attempts.excluded_tcp_records,
        "provider_labels": dict(Counter(labels)),
        "original_findings_verdicts_unchanged": True,
        "collector": collector_proof(target, clean, report),
        "limitations": manifest["limitations"],
    }
    write(target / "proof.json", json.dumps(proof, indent=2) + "\n")
    return proof


def evaluate_live(directory, live_directory):
    directory = private_directory(directory)
    verify_freeze(directory)
    target = private_directory(live_directory)
    if json.loads((target / "manifest.json").read_text()) != live_plan():
        raise ValueError("Live plan changed")
    if not re.search(
        r"^0 packets dropped by kernel$",
        (target / "capture.txt").read_text(),
        re.MULTILINE,
    ):
        raise ValueError("Live capture has unknown/nonzero drops")
    result, diagnostics = analyze_zeek_conn_log_with_diagnostics(
        (target / "zeek/conn.log").read_text(), [], None
    )
    parsed = parse_zeek_conn_log_with_diagnostics(
        (target / "zeek/conn.log").read_text()
    )
    if (
        dict(Counter(r.state for r in parsed.connections))
        != live_plan()["expected_states"]
    ):
        raise ValueError("Live TCP state totals differ from the predeclared contract")
    expected_sources = {
        "failed_port_diversity": "198.19.1.11",
        "failed_host_diversity": "198.19.1.12",
        "repeated_connection_failures": "198.19.1.13",
    }
    if any(
        expected_sources.get(f.pattern) != f.originator_ip
        for f in result.connection_attempts.findings
    ):
        raise ValueError("Live role/source isolation failed")
    if (
        diagnostics.accepted_rows != 120
        or diagnostics.invalid_connection_fields
        or diagnostics.invalid_timestamps
    ):
        raise ValueError("Unexpected live row count/metadata")
    expected = {
        "failed_port_diversity": 1,
        "failed_host_diversity": 1,
        "repeated_connection_failures": 1,
    }
    if (
        dict(Counter(f.pattern for f in result.connection_attempts.findings))
        != expected
    ):
        raise ValueError("Live attempt patterns differ from declared contract")
    if any(f.priority == "review" for f in result.connection_findings):
        raise ValueError("Original short-window review unexpectedly changed")
    report = json.loads(build_connection_report(result))
    validate_attempt_report(report["attempts"])
    proof = {
        "accepted_rows": 120,
        "attempt_patterns": expected,
        "original_reviews": 0,
        "sha256": hashlib.sha256((target / "zeek/conn.log").read_bytes()).hexdigest(),
        "collector": collector_proof(target, target / "zeek/conn.log", report),
        "limitations": live_plan()["limitations"],
    }
    write(target / "candidate-report.json", json.dumps(report, indent=2) + "\n")
    write(target / "proof.json", json.dumps(proof, indent=2) + "\n")
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("action", choices=("freeze", "official", "live"))
    parser.add_argument("--baseline-source", type=Path)
    parser.add_argument("--live-directory", type=Path)
    args = parser.parse_args()
    if args.action == "freeze":
        freeze(args.directory)
    elif args.action == "official":
        if not args.baseline_source:
            parser.error("Trusted baseline source required")
        print(
            json.dumps(
                evaluate_official(args.directory, args.baseline_source), indent=2
            )
        )
    else:
        if not args.live_directory:
            parser.error("Private live directory required")
        print(json.dumps(evaluate_live(args.directory, args.live_directory), indent=2))


if __name__ == "__main__":
    main()
