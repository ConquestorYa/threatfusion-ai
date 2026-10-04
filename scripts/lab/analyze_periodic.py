"""Validate capture against its predeclared plan, then describe native outputs.

The labels are used only for validation/reporting, never as detector input.
This is a behavior-only engineering comparison, not a malware benchmark.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from collections import Counter
from pathlib import Path

from threatfusion.dns_zeek import parse_zeek_dns_log_with_diagnostics
from threatfusion.hybrid_assessment import assess_dns_domains


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def zeek_rows(path: Path) -> list[dict[str, str]]:
    fields = None
    rows = []
    for line in path.read_text().splitlines():
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#"):
            if not fields:
                raise ValueError("Zeek field header missing")
            rows.append(dict(zip(fields, line.split("\t"), strict=True)))
    return rows


def read_rita(path: Path) -> list[dict[str, str]]:
    lines = path.read_text().splitlines()
    # RITA v5.1.2 writes one human-readable database banner before its CSV.
    if lines and lines[0].startswith("Viewing database: "):
        lines = lines[1:]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or not {"Source IP", "FQDN", "Beacon Score", "Severity", "Modifiers"}.issubset(reader.fieldnames):
        raise ValueError("Unexpected RITA CSV schema")
    return list(reader)


def analyze(directory: Path, rita_csv: Path | None = None) -> dict:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if sha256(manifest_path) != manifest_path.with_suffix(".sha256").read_text().strip():
        raise ValueError("Scenario manifest hash mismatch")
    if manifest["protocol"] != "periodic-controls-v1":
        raise ValueError("Unsupported scenario protocol")
    dns_path = directory / "zeek" / "dns.log"
    parsed = parse_zeek_dns_log_with_diagnostics(dns_path.read_text())
    expected = Counter((manifest["roles"][event["role"]][0], event["domain"]) for event in manifest["events"])
    observed = Counter((event.client_ip, event.query_name) for event in parsed.events)
    if observed != expected:
        raise ValueError("Captured DNS events differ from the frozen plan")
    if parsed.diagnostics.invalid_timestamps or parsed.diagnostics.invalid_response_ips:
        raise ValueError("Invalid captured DNS fields")
    http_path = directory / "zeek" / "http.log"
    http = zeek_rows(http_path)
    expected_http = Counter((manifest["roles"][event["role"]][0], event["domain"], event["path"]) for event in manifest["events"])
    observed_http = Counter((row["id.orig_h"], row["host"], row["uri"]) for row in http)
    if observed_http != expected_http or any(row["status_code"] != "200" for row in http):
        raise ValueError("Captured HTTP requests differ from the frozen plan")
    answers = {domain: values[1] for role, values in manifest["roles"].items() for domain in {e["domain"] for e in manifest["events"] if e["role"] == role}}
    if any(event.response_ip != answers[event.query_name] or event.response_code != "NOERROR" for event in parsed.events):
        raise ValueError("Unexpected DNS answer in capture")
    # Product code receives only captured DNS events, no ground truth or feeds.
    assessments = assess_dns_domains(parsed.events, [])
    rita = read_rita(rita_csv) if rita_csv else []
    rows = []
    for assessment in assessments:
        domain = assessment.domain
        role = next(event["role"] for event in manifest["events"] if event["domain"] == domain)
        source = manifest["roles"][role][0]
        native = [row for row in rita if row["Source IP"] == source and row["FQDN"] == domain]
        rows.append({
            "role": role, "domain": domain, "expected_intent": manifest["roles"][role][3],
            "dns_events": assessment.behavior.event_count,
            "threatfusion_verdict": assessment.verdict.value,
            "threatfusion_periodic_context": assessment.behavior.periodic_query_pattern,
            "threatfusion_periodicity_score": assessment.behavior.periodicity_score,
            "threatfusion_reasons": assessment.reasons,
            "rita_rows": native,
        })
    paths = [manifest_path, dns_path, http_path, directory / "zeek" / "conn.log", directory / "scenario.pcap"]
    if rita_csv:
        paths.append(rita_csv)
    return {
        "protocol": manifest["protocol"], "mode": manifest["mode"],
        "validated_dns_events": len(parsed.events), "validated_http_events": len(http),
        "represented_window_seconds": manifest["represented_window_seconds"],
        "cti_enabled": False, "ml_enabled": False,
        "detector_labels_used_as_input": False,
        "inputs_sha256": {str(path.relative_to(directory)) if path.is_relative_to(directory) else path.name: sha256(path) for path in paths},
        "observations": rows,
        "limitations": manifest["limitations"] + [
            "RITA sees connection/HTTP/DNS metadata; ThreatFusion's current behavior verdict sees DNS only.",
            "Native scores and severity labels are not calibrated or directly comparable probabilities.",
            "Synthetic MIME types, user agent and fixed payloads can influence RITA modifiers.",
            "Three role scenarios cannot establish recall, FPR or superiority on real traffic.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--rita-csv", type=Path)
    parser.add_argument("--output-prefix", default="comparison")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", args.output_prefix):
        parser.error("Output prefix must be a simple filename")
    result = analyze(args.directory, args.rita_csv)
    with (args.directory / f"{args.output_prefix}.json").open("x") as file:
        json.dump(result, file, indent=2)
        file.write("\n")
    lines = [
        f"Protocol: {result['protocol']} | mode: {result['mode']}",
        f"Validated: {result['validated_dns_events']} DNS, {result['validated_http_events']} HTTP",
        "CTI / ML: disabled. Lab intent labels are not detector input.", "",
    ]
    for row in result["observations"]:
        lines.append(f"{row['role']} | {row['domain']} | intended: {row['expected_intent']}")
        lines.append(f"  ThreatFusion: {row['threatfusion_verdict']}; periodic context: {row['threatfusion_periodic_context']}")
        for native in row["rita_rows"]:
            lines.append(f"  RITA: {native['Severity']}; beacon score: {native['Beacon Score']}; modifiers: {native['Modifiers']}")
    lines += ["", "Engineering observation only; not a malware accuracy/production benchmark."]
    summary = "\n".join(lines) + "\n"
    with (args.directory / f"{args.output_prefix}-summary.txt").open("x") as file:
        file.write(summary)
    print(summary)


if __name__ == "__main__":
    main()
