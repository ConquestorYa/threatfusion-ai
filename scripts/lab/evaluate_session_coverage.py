"""Predeclared TCP termination controls and reserved official IoT-23 evaluation."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import subprocess
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from urllib.request import urlopen

from scripts.lab.evaluate_connection_controls import zeek_text
from scripts.lab.evaluate_iot23 import ATTRIBUTION, ROOT, strip_labels, write
from threatfusion.connections import POLICY_ID
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics

PROTOCOL = "tcp-termination-coverage-v1"
BASELINE = "bf5155c3d4378f5d5280c8b422ef379da99eeb80"
CAPTURES = (
    ("CTU-Honeypot-Capture-7-1-Somfy-01", "CTU-Honeypot-Capture-7-1/Somfy-01"),
    ("CTU-IoT-Malware-Capture-34-1", "CTU-IoT-Malware-Capture-34-1"),
    ("CTU-IoT-Malware-Capture-21-1", "CTU-IoT-Malware-Capture-21-1"),
)
MAX_BYTES = 4 * 1024 * 1024
MODULES = ("connections", "network_telemetry", "runtime_analysis", "dashboard",
           "reporting", "expected_connections", "dns", "dns_behavior",
           "hybrid_assessment", "matching", "normalization", "models", "device_triage")


def fingerprints():
    return {name: hashlib.sha256(Path(importlib.util.find_spec("threatfusion." + name).origin)
                                .read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in MODULES}


def controls(seed):
    """Declared contract labels stay outside the product's input."""
    rng = random.Random(seed)
    cases = []
    def add(name, offsets, *, state="SF", expected="observe", intent="benign_control", **changes):
        records = [{"ts": 1791072000 + offset, "uid": f"C{i}", "id.orig_h": "192.0.2.1",
                    "id.orig_p": 40000+i, "id.resp_h": "198.51.100.1", "id.resp_p": 443,
                    "proto": "tcp", "duration": 1, "orig_bytes": 100, "resp_bytes": 200,
                    "conn_state": state, "missed_bytes": 0} | changes for i, offset in enumerate(offsets)]
        cases.append({"name": name, "intent": intent, "expected_priority": expected, "records": records})
    times = [i * 300 + rng.randint(0, 20) for i in range(24)]
    for state in ("S2", "S3", "RSTO", "RSTR"):
        add("long_"+state, [0], state=state, duration=4000, expected="review", intent="termination_control")
        add("periodic_"+state, times, state=state, expected="review", intent="termination_control")
        add("short_"+state, [0], state=state)
    for state in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"):
        add("unconfirmed_"+state, times, state=state, orig_bytes=0, resp_bytes=0, duration=4000)
    for name, changes in (
        ("capture_gap", {"missed_bytes": 1}), ("unknown_duration", {"duration": "-"}),
        ("one_way_payload", {"resp_bytes": 0}), ("unknown_bytes", {"orig_bytes": "-"}),
        ("unknown_originator_port", {"id.orig_p": "-"}), ("unknown_time", {"ts": "-"}),
    ):
        add(name, times, state="RSTR", **changes)
    add("irregular_reset_browsing", sorted(rng.sample(range(86400), 24)), state="RSTR")
    add("short_reset_window", [i * 30 for i in range(24)], state="RSTR")
    add("benign_periodic_updates", times, expected="review")
    add("matching_heartbeat", times, expected="review", intent="controlled_suspicious_simulation")
    add("duplicate_resets", times[:12], state="RSTR")
    cases[-1]["records"] *= 2
    add("conflicting_reset_uids", times, state="RSTR")
    cases[-1]["records"] += [r | {"resp_bytes": 201} for r in cases[-1]["records"]]
    add("mixed_established_states", times, expected="review", intent="termination_control")
    for i, record in enumerate(cases[-1]["records"]):
        record["conn_state"] = ("SF", "S2", "RSTO", "RSTR")[i % 4]
    return cases


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    plan = {"protocol": PROTOCOL, "baseline_commit": BASELINE,
            "development_seed": 20261005, "reserved_seed": 20261027,
            "candidate_policy": "zeek-connection-context-v2",
            "contract": "Add S2/S3/RSTO/RSTR payload evidence; retain 3600s long/20 timestamps/1800s span/0.85 timing gates. Missing/conflicting/gapped evidence does not qualify. Failed/half-open attempts count separately without malware inference. Expected declarations retain SF/S1 coverage.",
            "captures": [{"id": name, "url": ROOT + path + "/bro/conn.log.labeled"} for name, path in CAPTURES],
            "max_bytes": MAX_BYTES, "attribution": ATTRIBUTION,
            "limitations": ["Constructed controls establish contracts, not malware truth.",
                            "Three reserved old-device captures, not representative production traffic.",
                            "No ML/CTI/rules, native RITA, threshold tuning or malware FPR/recall claim.",
                            "Inputs/results stay private; labels never reach the detector."]}
    write(directory / "plan.json", json.dumps(plan, indent=2)+"\n")
    write(directory / "plan.sha256", hashlib.sha256((directory/"plan.json").read_bytes()).hexdigest()+"\n")
    for phase, seed in (("development", plan["development_seed"]), ("reserved", plan["reserved_seed"])):
        entries = []
        for index, case in enumerate(controls(seed)):
            filename = f"{phase}-{index:02d}.conn.log"
            content = zeek_text(case["records"])+"#close\tcontrolled-offline\n"
            write(directory / filename, content)
            entries.append({k: v for k, v in case.items() if k != "records"} |
                           {"file": filename, "sha256": hashlib.sha256(content.encode()).hexdigest()})
        write(directory / (phase+".json"), json.dumps(entries, indent=2)+"\n")


def check_controls(directory, phase):
    rows = []
    for case in json.loads((directory / (phase+".json")).read_text()):
        raw = (directory/case["file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != case["sha256"]:
            raise ValueError("Control input changed")
        result, diagnostics = analyze_zeek_conn_log_with_diagnostics(raw.decode(), [], None)
        priority = "review" if any(f.priority == "review" for f in result.connection_findings) else "observe"
        rows.append(case | {"actual_priority": priority, "passed": priority == case["expected_priority"],
                            "diagnostics": asdict(diagnostics)})
    write(directory/(phase+".results.json"), json.dumps(rows, indent=2)+"\n")
    return rows


def freeze(directory):
    if POLICY_ID != "zeek-connection-context-v2":
        raise ValueError("Implement declared candidate before freezing")
    manifests = {phase: hashlib.sha256((directory/(phase+".json")).read_bytes()).hexdigest()
                 for phase in ("development", "reserved")}
    write(directory/"freeze.json", json.dumps({"policy": POLICY_ID, "fingerprints": fingerprints(),
                                             "control_manifests": manifests}, indent=2)+"\n")


def summary(text):
    result, diagnostics = analyze_zeek_conn_log_with_diagnostics(text, [], None)
    parsed = parse_zeek_conn_log_with_diagnostics(text)
    times = [r.timestamp for r in parsed.connections if r.timestamp]
    return {"diagnostics": asdict(diagnostics), "groups": len(result.connection_findings),
            "reviews": sum(f.priority == "review" for f in result.connection_findings),
            "reasons": dict(Counter(r for f in result.connection_findings for r in f.reasons)),
            "span_seconds": (max(times)-min(times)).total_seconds() if times else None,
            "domain_verdicts": dict(Counter(a.verdict.value for a in result.assessments))}, result, parsed


def evaluate(directory, baseline_source):
    frozen = json.loads((directory/"freeze.json").read_text())
    if frozen["fingerprints"] != fingerprints():
        raise ValueError("Candidate changed after freeze")
    for phase, digest in frozen["control_manifests"].items():
        if hashlib.sha256((directory/(phase+".json")).read_bytes()).hexdigest() != digest:
            raise ValueError("Declared control expectations changed")
    plan_bytes = (directory/"plan.json").read_bytes()
    if hashlib.sha256(plan_bytes).hexdigest() != (directory/"plan.sha256").read_text().strip():
        raise ValueError("Plan changed")
    plan = json.loads(plan_bytes)
    if plan["captures"] != [{"id": name, "url": ROOT+path+"/bro/conn.log.labeled"} for name, path in CAPTURES]:
        raise ValueError("Reserved capture selection changed")
    reserved = check_controls(directory, "reserved")
    receipts = []
    for capture in plan["captures"]:
        with urlopen(capture["url"], timeout=30) as response:
            raw = response.read(MAX_BYTES+1)
        if len(raw) > MAX_BYTES:
            raise ValueError("Reserved file exceeds limit; do not replace selection after inspection")
        write(directory/(capture["id"]+".labeled"), raw)
        receipts.append(capture | {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    write(directory/"acquisition.json", json.dumps(receipts, indent=2)+"\n")
    observations = []
    for capture in receipts:
        raw = (directory/(capture["id"]+".labeled")).read_bytes()
        text, labels = strip_labels(raw.decode())
        clean = directory/(capture["id"]+".conn.log")
        write(clean, text)
        candidate, result, parsed = summary(text)
        # The isolated process imports only the trusted archived baseline source.
        code = "import sys;sys.path[:0]=[sys.argv[1],sys.argv[1]+'/src'];from scripts.lab.evaluate_iot23 import verify_frozen_code;verify_frozen_code();from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics;from pathlib import Path;import json;from collections import Counter;r,d=analyze_zeek_conn_log_with_diagnostics(Path(sys.argv[2]).read_text(),[],None);print(json.dumps({'groups':len(r.connection_findings),'reviews':sum(f.priority=='review' for f in r.connection_findings),'domain_verdicts':dict(Counter(a.verdict.value for a in r.assessments))}))"
        baseline = subprocess.run([sys.executable, "-c", code, str(baseline_source), str(clean)],
                                  check=True, capture_output=True, text=True, timeout=60)
        reviewed = {(f.originator_ip,f.responder_ip,f.protocol,f.responder_port)
                    for f in result.connection_findings if f.priority == "review"}
        flow_labels = Counter(label for record,label in zip(parsed.connections,labels,strict=True)
                              if (record.originator_ip,record.responder_ip,record.protocol,record.responder_port) in reviewed)
        observations.append(capture | {"baseline": json.loads(baseline.stdout), "candidate": candidate,
                                       "provider_labels_in_reviewed_groups": dict(flow_labels)})
        write(directory/(capture["id"]+".report.json"), build_connection_report(result))
    report = {"protocol": PROTOCOL, "observations": observations, "reserved_contract_checks":
              {"passed": sum(r["passed"] for r in reserved), "total": len(reserved)}, "limitations": plan["limitations"]}
    write(directory/"summary.json", json.dumps(report,indent=2)+"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("action", choices=("prepare", "development", "freeze", "evaluate"))
    parser.add_argument("--baseline-source", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        parser.error("All evaluation files must stay outside the repository")
    if args.action == "prepare":
        prepare(directory)
    elif args.action == "development":
        rows = check_controls(directory,"development")
        print(json.dumps({"passed": sum(r["passed"] for r in rows), "total": len(rows)}))
    elif args.action == "freeze":
        freeze(directory)
    else:
        if not args.baseline_source:
            parser.error("A trusted archived baseline source is required")
        print(json.dumps(evaluate(directory,args.baseline_source.resolve()),indent=2))


if __name__ == "__main__":
    main()
