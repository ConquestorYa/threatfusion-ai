"""Frozen, offline connection-policy evaluation on selected official IoT-23 logs."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

from threatfusion.connections import POLICY_ID
from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics

PROTOCOL = "iot23-connection-coverage-v1"
ROOT = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
CAPTURES = ("CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1",
            "CTU-IoT-Malware-Capture-44-1", "CTU-IoT-Malware-Capture-20-1")
FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "missed_bytes")
MAX_BYTES = 2 * 1024 * 1024
FROZEN_MODULES = {
    "connections": "5430c129d3eae1c4ea3d3d76d414766d280d1e1fe9e7760df2839091d421af11",
    "network_telemetry": "e356820894fdf16c095cf418a2c677b5e280907a000cfb3c8c2cd2c3970da6f6",
    "runtime_analysis": "f3895c061b05c460282be4bb14e1e1ea9060c52833eade7a6311b1387b879a94",
    "hybrid_assessment": "ba0227953a773c1af687606f2a6c78bf5c679922ec9fb99dd29e853f28efe7c4",
    "dns_behavior": "f3d0762e39a78ac02f296927126e224e15302b741884f5e6f5b3c80cf10fa12d",
    "normalization": "c850a406399b89e4febe22795e9f61898b9c6ddb05bf3df6dac932dd12316629",
    "models": "726067ddfcf82daec3a96da3899cc78045ed3f123d868d18a6da0fee9ac52d67",
    "matching": "37e7a2c2b602822fa4a5ce6c010d9c1b8266f74e9eae0d760b9bec9c842e5fd2",
    "dns": "54db741c76a1c1c67f38e85db8d9e97c46f7bff61250628eec24f2545e7d72a6",
    "device_triage": "27ac513f68c258bf4a49331abee77c8f7880a0b415471b9b61330ef34593ccc1",
    "dashboard": "7e3b31b59486ea448dcdf118b21052678d58f7ab724b0e21fa2ca54a020c46fd",
    "reporting": "e0ac16579caf6d30d74cc4094330b0db847c6823524419c5791957a4dfff37ee",
    "expected_connections": "7b6899c0da5782c24e268b8fa51b19333b7029a51ab545dbea8e6874ddd44709",
}
ATTRIBUTION = "Garcia, S., Parmisano, A., & Erquiaga, M. J. (2020). IoT-23 (v1.0.0). https://doi.org/10.5281/zenodo.4743746"
LIMITATIONS = [
    "Four preselected small official connection logs, not representative enterprise traffic.",
    "Provider intent/flow labels describe dataset evidence, not calibrated malware verdicts.",
    "Labels are removed before product analysis. No live CTI, ML, expectations or threshold tuning.",
    "Review groups and flow labels have different units; no malware FPR/recall/parity claim.",
    "No DNS/HTTP metadata, native RITA scoring, malware execution or destination access.",
    "Source acquisition hashes identify these files; individual-source contents can change.",
]


def write(path: Path, content: str | bytes):
    with path.open("xb") as file:
        file.write(content.encode() if isinstance(content, str) else content)
    path.chmod(0o600)


def acquisition_plan():
    return {"protocol": PROTOCOL, "detector_policy": POLICY_ID,
            "frozen_source_commit": "0a3e17c1f4724f2f3d75966b08125ee5e26c8c1d",
            "attribution": ATTRIBUTION, "license_record": "https://zenodo.org/api/records/4743746",
            "captures": [{"id": name, "url": ROOT + name + "/bro/conn.log.labeled"} for name in CAPTURES],
            "max_download_bytes_per_capture": MAX_BYTES, "limitations": LIMITATIONS}


def verify_frozen_code():
    for name, digest in FROZEN_MODULES.items():
        spec = importlib.util.find_spec("threatfusion." + name)
        if not spec or not spec.origin or hashlib.sha256(Path(spec.origin).read_bytes().replace(b"\r\n", b"\n")).hexdigest() != digest:
            raise ValueError("Frozen evaluation code changed; use the recorded source revision")


def acquire(directory: Path):
    verify_frozen_code()
    directory = directory.resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Evaluation data must stay outside the repository")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    plan = acquisition_plan()
    write(directory / "plan.json", json.dumps(plan, indent=2) + "\n")
    write(directory / "plan.sha256", hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest() + "\n")
    receipts = []
    for capture in plan["captures"]:
        with urlopen(capture["url"], timeout=30) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("Source log exceeds declared size limit")
            metadata = {key: response.headers.get(key) for key in ("ETag", "Last-Modified")}
        path = directory / (capture["id"] + ".labeled")
        write(path, raw)
        receipts.append(capture | {"file": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
                                   "bytes": len(raw), "http_metadata": metadata})
    receipt = {"acquired_at": datetime.now(timezone.utc).isoformat(), "captures": receipts}
    write(directory / "acquisition.json", json.dumps(receipt, indent=2) + "\n")


def strip_labels(content: str):
    """IoT-23 embeds label fields with spaces inside its last TSV cell.

    Preserve only declared standard connection fields; keep labels in a separate
    evaluation vector which never reaches the detector.
    """
    columns = None
    rows = []
    labels = []
    for line in content.splitlines():
        if line.startswith("#separator") and line != r"#separator \x09":
            raise ValueError("Expected standard TSV separator")
        if line.startswith("#fields\t"):
            columns = re.split(r"\t| {2,}", line[len("#fields\t"):])
        elif line and not line.startswith("#"):
            if not columns or not set(FIELDS).issubset(columns) or "label" not in columns:
                raise ValueError("Unsupported official labeled connection schema")
            values = re.split(r"\t| {2,}", line)
            if len(values) != len(columns):
                raise ValueError("Labeled row does not match source schema")
            record = dict(zip(columns, values, strict=True))
            rows.append("\t".join(record[field] for field in FIELDS))
            labels.append(record["label"])
    header = "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n"
    return header + "\n".join(rows) + "\n#close\tcompleted-offline\n", labels


def evaluate(directory: Path):
    verify_frozen_code()
    directory = directory.resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Evaluation data must stay outside the repository")
    plan_path = directory / "plan.json"
    if hashlib.sha256(plan_path.read_bytes()).hexdigest() != (directory / "plan.sha256").read_text().strip():
        raise ValueError("Acquisition plan changed")
    if json.loads(plan_path.read_text()) != acquisition_plan():
        raise ValueError("Unexpected evaluation plan")
    receipts = json.loads((directory / "acquisition.json").read_text())["captures"]
    if [c["id"] for c in receipts] != list(CAPTURES):
        raise ValueError("Capture selection changed")
    observations = []
    for capture in receipts:
        if (capture["file"] != capture["id"] + ".labeled"
            or capture["url"] != ROOT + capture["id"] + "/bro/conn.log.labeled"
            or type(capture["bytes"]) is not int or not 0 <= capture["bytes"] <= MAX_BYTES):
            raise ValueError("Unexpected acquisition receipt")
        raw = (directory / capture["file"]).read_bytes()
        if len(raw) != capture["bytes"] or hashlib.sha256(raw).hexdigest() != capture["sha256"]:
            raise ValueError("Frozen input changed")
        text, labels = strip_labels(raw.decode("utf-8"))
        parsed = parse_zeek_conn_log_with_diagnostics(text)
        result, diagnostics = analyze_zeek_conn_log_with_diagnostics(text, [], None)
        times = [r.timestamp for r in parsed.connections if r.timestamp is not None]
        groups = result.connection_findings
        observations.append({
            "capture": capture["id"], "source_sha256": capture["sha256"],
            "label_counts": dict(Counter(labels)), "diagnostics": asdict(diagnostics),
            "observed_span_seconds": (max(times) - min(times)).total_seconds() if times else None,
            "connection_groups": len(groups), "review_groups": sum(f.priority == "review" for f in groups),
            "tcp_rows": sum(r.protocol == "tcp" for r in parsed.connections),
            "confirmed_sessions": sum(f.confirmed_session_count for f in groups),
            "coverage_limits": dict(Counter(limit for f in groups for limit in f.limitations)),
            "review_reasons": dict(Counter(reason for f in groups for reason in f.reasons)),
            "domain_verdict_counts": dict(Counter(a.verdict.value for a in result.assessments)),
        })
        clean_path = directory / (capture["id"] + ".conn.log")
        if not clean_path.exists():
            write(clean_path, text)
        elif clean_path.read_text() != text:
            raise ValueError("Label-free input changed")
        report_path = directory / (capture["id"] + ".report.json")
        if not report_path.exists():
            write(report_path, build_connection_report(result))
    summary = {"protocol": PROTOCOL, "attribution": ATTRIBUTION,
               "observations": observations, "limitations": LIMITATIONS}
    write(directory / "summary.json", json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--download", action="store_true", help="Explicit bounded official-source acquisition")
    args = parser.parse_args()
    if args.download:
        acquire(args.directory)
    summary = evaluate(args.directory)
    for row in summary["observations"]:
        print(f"{row['capture']}: {row['diagnostics']['accepted_rows']} rows; {row['review_groups']}/{row['connection_groups']} review groups; span {row['observed_span_seconds']}s")


if __name__ == "__main__":
    main()
