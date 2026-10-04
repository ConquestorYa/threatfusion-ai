"""Validate cache/persistence capture, then measure actual review workload."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics, analyze_zeek_dns_log_with_diagnostics
if __package__:
    from .analyze_periodic import read_rita, zeek_rows
else:
    from analyze_periodic import read_rita, zeek_rows


def analyze(directory: Path, rita_csv: Path | None = None) -> dict:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != manifest_path.with_suffix(".sha256").read_text().strip():
        raise ValueError("Workload manifest hash mismatch")
    if manifest["protocol"] != "cached-http-controls-v1":
        raise ValueError("Unexpected workload protocol")
    dns, diag = analyze_zeek_dns_log_with_diagnostics((directory / "zeek/dns.log").read_text(), [], None)
    expected_dns = Counter({(manifest["roles"][e["role"]][0], e["domain"]): 1 for e in manifest["events"]})
    if Counter((e.client_ip, e.query_name) for e in dns.events) != expected_dns or diag.invalid_timestamps:
        raise ValueError("Cached DNS capture differs from plan")
    targets = {e["domain"]: manifest["roles"][e["role"]][1] for e in manifest["events"]}
    if any(e.response_code != "NOERROR" or e.response_ip != targets[e.query_name] for e in dns.events):
        raise ValueError("Unexpected cached DNS answer")
    capture = (directory / "capture.txt").read_text()
    drops = re.search(r"(\d+) packets dropped by kernel", capture)
    if not drops or int(drops.group(1)):
        raise ValueError("Missing capture drop accounting or dropped packets")
    http = zeek_rows(directory / "zeek/http.log")
    expected_http = Counter((manifest["roles"][e["role"]][0], e["domain"], e["path"]) for e in manifest["events"])
    if Counter((r["id.orig_h"], r["host"], r["uri"]) for r in http) != expected_http or any(r["status_code"] != "200" for r in http):
        raise ValueError("Captured HTTP requests differ from plan")
    conn, conn_diag = analyze_zeek_conn_log_with_diagnostics((directory / "zeek/conn.log").read_text(), [], None)
    if conn_diag.invalid_connection_fields:
        raise ValueError("Invalid captured connection metadata")
    # Product sees logs only; labels enter reporting after analysis.
    observations = []
    for role, values in manifest["roles"].items():
        source, target, _, intent = values
        sessions = [f for f in conn.connection_findings if f.originator_ip == source and f.responder_ip == target and f.protocol == "tcp"]
        observations.append({
            "role": role, "intent": intent,
            "dns_queries": sum(e.client_ip == source for e in dns.events),
            "http_requests": sum(r["id.orig_h"] == source for r in http),
            "tcp_sessions": sum(f.connection_count for f in sessions),
            "dns_reviews": sum(f.client_ip == source and f.priority != "observe" for f in dns.device_findings),
            "connection_reviews": sum(f.priority == "review" for f in sessions),
            "max_duration_seconds": max((f.max_duration_seconds or 0 for f in sessions), default=0),
        })
    expected_sessions = {"browser": 1, "updater": 30, "heartbeat": 30}
    if any(row["tcp_sessions"] != expected_sessions[row["role"]] for row in observations):
        raise ValueError("TCP persistence differs from declared workload")
    if any(f.confirmed_session_count != f.connection_count for f in conn.connection_findings if f.protocol == "tcp"):
        raise ValueError("Incomplete TCP sessions in captured workload")
    paths = [manifest_path, directory / "scenario.pcap", *(directory / f"zeek/{name}.log" for name in ("dns", "http", "conn"))]
    if rita_csv:
        paths.append(rita_csv)
    return {
        "protocol": manifest["protocol"], "cti_enabled": False, "ml_enabled": False,
        "dns_events": len(dns.events), "http_events": len(http),
        "observations": observations,
        "connection_report": json.loads(build_connection_report(conn)),
        "rita_native_rows": read_rita(rita_csv) if rita_csv else [],
        "input_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths},
        "limitations": manifest["limitations"] + ["Review burden is counted separately from malware verdict accuracy; no FPR/recall claim."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--rita-csv", type=Path)
    args = parser.parse_args()
    result = analyze(args.directory, args.rita_csv)
    with (args.directory / "workload-analysis.json").open("x") as file:
        json.dump(result, file, indent=2)
        file.write("\n")
    print(f"Validated cached workload: {result['dns_events']} DNS, {result['http_events']} HTTP")
    for row in result["observations"]:
        print(f"{row['role']}: {row['tcp_sessions']} TCP sessions, {row['dns_reviews']} DNS reviews, {row['connection_reviews']} connection reviews")


if __name__ == "__main__":
    main()
