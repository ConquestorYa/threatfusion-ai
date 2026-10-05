"""Exercise declared context boundaries, including a same-endpoint masquerade."""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatfusion.expected_connections import connection_contexts, parse_expected_connections
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics

if __package__:
    from .evaluate_connection_controls import write, zeek_text
else:
    from evaluate_connection_controls import write, zeek_text

PROTOCOL = "expected-connection-controls-v1"
EVALUATED_AT = datetime(2026, 11, 18, 18, tzinfo=timezone.utc)


def plan():
    now = EVALUATED_AT
    start = int((now - timedelta(hours=8)).timestamp())
    records = [dict(ts=start + i * 300, uid=f"C{i}",
                    **{"id.orig_h": "192.0.2.1", "id.orig_p": 40000 + i,
                       "id.resp_h": "198.51.100.1", "id.resp_p": 443},
                    proto="tcp", duration=0.5, orig_bytes=128, resp_bytes=256,
                    conn_state="SF", missed_bytes=0) for i in range(72)]
    rule = dict(id="declared-updater", originator_ip="192.0.2.1", responder_ip="198.51.100.1",
                responder_port=443, protocol="tcp", valid_from=(now - timedelta(days=1)).isoformat(),
                valid_until=(now + timedelta(days=1)).isoformat(), max_connections=100,
                max_duration_seconds=8000, max_originator_bytes=100000, max_responder_bytes=100000)
    cases = []
    def add(name, intent, status, *, changes=None, declaration=None, cti=False):
        rows = [r | (changes or {}) for r in records]
        cases.append(dict(name=name, intent=intent, expected_status=status, records=rows,
                          declarations={"schema_version": 1, "rules": [rule | (declaration or {})]}, cti=cti))
    add("declared_updates", "benign", "declared_expected")
    add("undeclared_updates", "benign", "review", declaration={"originator_ip": "192.0.2.2"})
    add("expired_updates", "benign", "review", declaration={"valid_until": now.isoformat()})
    add("volume_deviation", "benign", "review", changes={"resp_bytes": 2000})
    add("other_device", "benign", "review", changes={"id.orig_h": "192.0.2.2"})
    add("other_port", "benign", "review", changes={"id.resp_p": 8443})
    add("heartbeat_unknown", "harmless_simulation", "review", changes={"id.resp_h": "198.51.100.2"})
    # Deliberately identical telemetry: declarations cannot identify software.
    add("heartbeat_on_declared_endpoint", "harmless_simulation", "declared_expected")
    add("cti_conflict", "synthetic_cti", "cti_conflict", cti=True)
    add("incomplete_capture", "benign", "observe", changes={"missed_bytes": 1})
    stream = cases[0]["records"][0] | {"duration": 7200, "orig_bytes": 10000, "resp_bytes": 50000}
    cases.append(dict(name="declared_stream", intent="benign", expected_status="declared_expected",
                      records=[stream], declarations={"schema_version": 1, "rules": [rule]}, cti=False))
    return cases


def evaluate(directory: Path):
    directory = directory.resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Control outputs must stay outside the repository")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    cases = plan()
    manifest = {"protocol": PROTOCOL, "evaluated_at": EVALUATED_AT.isoformat(), "cases": []}
    for case in cases:
        log = directory / f"{case['name']}.conn.log"
        rules = directory / f"{case['name']}.rules.json"
        write(log, zeek_text(case["records"]))
        write(rules, json.dumps(case["declarations"], indent=2) + "\n")
        manifest["cases"].append({key: value for key, value in case.items() if key not in {"records", "declarations"}} | {
            "log": log.name, "rules": rules.name,
            "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
            "rules_sha256": hashlib.sha256(rules.read_bytes()).hexdigest(),
        })
    write(directory / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    write(directory / "manifest.sha256", hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest() + "\n")
    observations = []
    for case in manifest["cases"]:
        for field in ("log", "rules"):
            if hashlib.sha256((directory / case[field]).read_bytes()).hexdigest() != case[field + "_sha256"]:
                raise ValueError("Frozen context input changed")
        indicators = [IOCRecord("198.51.100.1", IOCType.IPV4, "synthetic")] if case["cti"] else []
        result, _ = analyze_zeek_conn_log_with_diagnostics((directory / case["log"]).read_text(), indicators, None)
        rules = parse_expected_connections((directory / case["rules"]).read_bytes())
        context, = connection_contexts(result, rules, evaluated_at=EVALUATED_AT)
        if context.status != case["expected_status"]:
            raise ValueError("Context contract failed")
        write(directory / f"{case['name']}.report.json", build_connection_report(result, expected_rules=rules, evaluated_at=EVALUATED_AT))
        observations.append(dict(name=case["name"], intent=case["intent"], status=context.status,
                                 original_priority=result.connection_findings[0].priority))
    summary = {"protocol": PROTOCOL, "passed_controls": len(observations), "observations": observations,
               "limitations": ["Constructed records, not independent real traffic or malware accuracy.",
                               "Same-endpoint heartbeat also matches the declaration; software identity is unverified.",
                               "Original priorities remain unchanged. This tests context policy, not improved detection.",
                               "CTI is a reserved-IP fixture; ML and real feeds are disabled."]}
    write(directory / "summary.json", json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    result = evaluate(parser.parse_args().output_dir)
    print(f"Context contracts passed: {result['passed_controls']}; not a malware benchmark")
    print("Same-endpoint simulation matches the declaration too; CTI conflict stays visible.")


if __name__ == "__main__":
    main()
