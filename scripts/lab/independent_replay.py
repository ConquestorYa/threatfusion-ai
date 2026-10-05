"""Frozen official-capture comparison; diagnostic units, never malware accuracy."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

from scripts.lab.analyze_periodic import read_rita
from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.evaluate_review_workload import ZEEK_IMAGE, reconcile, sha, verify_hashes
from scripts.lab.pcap_structure import validate_capture
from threatfusion.dns_zeek import parse_zeek_dns_log_with_diagnostics, parse_zeek_dns_transactions
from threatfusion.reporting import build_connection_report, build_device_report
from threatfusion.runtime_analysis import analyze_dns_events, analyze_zeek_conn_log_with_diagnostics
from threatfusion.telemetry_collector import MAX_FILE_BYTES, MAX_RECORDS

REPO = Path(__file__).resolve().parents[2]
PLAN_SHA = "5208372b594becc6ea848f262a2659565f8eec78c19a91b5736e19ab87db0b2a"
RITA_IMAGE = "ghcr.io/activecm/rita@sha256:a2bb0ef6185e33780dbc3ce7d86e38ac7a65c98e729e17510fe29717eb34b76a"


def declared_plan():
    return json.loads(r'''{
  "protocol": "independent-replay-v1",
  "baseline_commit": "cc38d3210f57d1e0174f98712c0ca609bf3648d6",
  "sources": [
    {
      "name": "normal-20",
      "provider_intent": "benign",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-20/2017-04-30_win-normal.pcap",
      "head_bytes": 282415864
    },
    {
      "name": "normal-21",
      "provider_intent": "benign",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-21/2017-05-02_kali-normal.pcap",
      "head_bytes": 311638284
    },
    {
      "name": "malware-3",
      "provider_intent": "malicious_capture",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-3-1/2018-05-21_capture.pcap",
      "head_bytes": 57919772
    },
    {
      "name": "malware-8",
      "provider_intent": "malicious_capture",
      "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113.pcap",
      "head_bytes": 2098362
    }
  ],
  "reserved_unacquired": [
    "CTU-Normal-7/2013-12-17_capture1.pcap",
    "IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-1-1/2018-05-09-192.168.100.103.pcap"
  ],
  "metadata_excluded": [
    "IoT-23 7-1 exceeds 512 MiB; no body acquired",
    "9-1 has filtered derivatives; no body acquired",
    "3-1 test.pcap is a derivative; main original selected"
  ],
  "max_pcap_bytes": 536870912,
  "source_selection": "Official identities/index/HEAD sizes and described use only; no traffic bodies/results inspected. Metadata candidates are not evaluated captures.",
  "internal_subnets": [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
    "fe80::/10"
  ],
  "limits": [
    "No malware binary acquisition, execution, payload extraction, destination visits or packet transmission",
    "All dataset/evaluation/model/cache/telemetry outputs stay private outside Git",
    "Class metadata is not per-flow malware truth; no FPR/recall/parity/human efficacy claim",
    "No threshold/ML/context tuning; reserved sources stay unacquired",
    "Any structural/parser/full-retention/native failure remains excluded; no partial scoring or replacement after results",
    "Keep native RITA scores/filtering policy except preregistered internal subnets and input-owner UID/GID; feeds/updates disabled"
  ],
  "units": [
    "TCP groups/reviews",
    "DNS observed-client/domain groups/reviews",
    "TCP attempt patterns",
    "Separate domain/IP fallback verdicts",
    "Native RITA CSV rows/severities"
  ],
  "acceptance": [
    "Complete structural PCAP validation",
    "Same full pinned Zeek logs for RITA/ThreatFusion",
    "Full offline/collector/timeline/restart/gzip reconciliation, zero rejected/pruned rows",
    "Explicit diagnostic gaps and excluded sources"
  ],
  "attribution": [
    "Garcia, Sebastian. Malware Capture Facility Project. https://www.stratosphereips.org",
    "Garcia, S., Parmisano, A., Erquiaga, M. J. IoT-23 v1.0.0. doi:10.5281/zenodo.4743746"
  ]
}''')


def runtime_hashes():
    return {str(p.relative_to(REPO)): sha(p) for p in sorted((REPO / "src/threatfusion").glob("*.py"))}


def verify(root):
    root = private_root(root)
    if sha(root / "plan.json") != PLAN_SHA or json.loads((root / "plan.json").read_text()) != declared_plan():
        raise ValueError("Declared source plan changed")
    if json.loads((root / "runtime-freeze.json").read_text()) != runtime_hashes():
        raise ValueError("Runtime changed since preanalysis freeze")
    return root


def prepare(root):
    if root.exists():
        raise FileExistsError("Use a new private experiment root")
    root = private_root(root)
    write_new(root / "plan.json", declared_plan())
    write_new(root / "runtime-freeze.json", runtime_hashes())
    verify(root)
    seal(root)


def tooling_hashes():
    tools = [Path(__file__), REPO / "scripts/lab/run_independent_replay.sh", REPO / "scripts/lab/evaluate_review_workload.py", REPO / "scripts/lab/pcap_structure.py"]
    return {str(p.relative_to(REPO)): sha(p) for p in tools}


def seal(root):
    root = verify(root)
    write_new(root / "method-freeze.json", tooling_hashes())


def verify_method(root):
    revision = root / "format-revision.json"
    if revision.exists():
        data = json.loads(revision.read_text())
        if data["previous_method_sha256"] != sha(root / "method-freeze.json") or data["tooling"] != tooling_hashes():
            raise ValueError("Format qualification method changed")
        for name, hashes in data["sources"].items():
            verify_hashes(root / name, hashes)
        return
    if json.loads((root / "method-freeze.json").read_text()) != tooling_hashes():
        raise ValueError("Preanalysis method changed")


def effective_receipt(directory):
    receipt = json.loads((directory / "acquisition.json").read_text())
    qualification = directory / "format-qualification.json"
    if qualification.exists():
        receipt.update(json.loads(qualification.read_text()))
    return receipt


def qualify(root):
    """Explicit pre-outcome method amendment; preserve first exclusion/receipt."""
    root = verify(root)
    if (root / "format-revision.json").exists() or any(root.rglob("pre-analysis.json")) or any(root.rglob("evaluation.json")) or (root / "evidence-freeze.json").exists():
        raise FileExistsError("Format revision must precede all native/evaluation outcomes")
    sources = {}
    for source in declared_plan()["sources"]:
        directory = root / source["name"]
        receipt = json.loads((directory / "acquisition.json").read_text())
        path = directory / "scenario.pcap"
        if any(receipt.get(k) != v for k, v in source.items()) or receipt["bytes"] != source["head_bytes"] or sha(path) != receipt["sha256"]:
            raise ValueError("Cannot requalify changed/incomplete acquisition")
        try:
            packets = validate_capture(path, max_bytes=declared_plan()["max_pcap_bytes"])
            if not packets:
                raise ValueError("Empty capture")
            result = {"status": "complete", "packets": packets}
        except ValueError as error:
            result = {"status": "excluded", "reason": str(error)}
        write_new(directory / "format-qualification.json", result)
        sources[source["name"]] = {name: sha(directory / name) for name in ("acquisition.json", "scenario.pcap", "format-qualification.json")}
    write_new(root / "format-revision.json", {"revision": "pre-outcome-pcapng-v1", "previous_method_sha256": sha(root / "method-freeze.json"),
              "reason": "Normal-21 is PCAPNG, not corrupt; complete bounded structural support added before native/detector outcomes. Original receipts and packet bytes preserved.",
              "tooling": tooling_hashes(), "sources": sources})
    verify_method(root)


def allowed_url(url):
    parts = urlsplit(url)
    return (parts.scheme == "https" and parts.hostname == "mcfp.felk.cvut.cz"
            and parts.port in (None, 443) and parts.username is None and parts.password is None)


class OfficialRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise ValueError("Redirect outside official HTTPS origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def acquire_case(root, source):
    directory = root / source["name"]
    directory.mkdir(mode=0o700)  # Existing/failed evidence is never overwritten.
    path = directory / "scenario.pcap"
    digest, size, started = hashlib.sha256(), 0, time.monotonic()
    receipt = dict(source)
    try:
        if not allowed_url(source["url"]):
            raise ValueError("Unsupported source origin")
        with build_opener(OfficialRedirects()).open(source["url"], timeout=30) as response:
            if not allowed_url(response.geturl()) or response.status != 200:
                raise ValueError("Unexpected acquisition response")
            receipt["http_metadata"] = {key: response.headers.get(key) for key in ("ETag", "Last-Modified", "Content-Length")}
            with path.open("xb") as file:
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > declared_plan()["max_pcap_bytes"] or size > source["head_bytes"] or time.monotonic() - started > 600:
                        raise ValueError("Acquisition exceeds declared size/time bounds")
                    file.write(block)
                    digest.update(block)
        if size != source["head_bytes"]:
            raise ValueError("Source length differs from preanalysis HEAD")
        receipt.update(bytes=size, sha256=digest.hexdigest())
        packets = validate_capture(path, max_bytes=declared_plan()["max_pcap_bytes"])
        if packets == 0:
            raise ValueError("Empty capture")
        receipt.update(status="complete", packets=packets)
    except (ValueError, OSError) as error:
        # Error text stays private. No failed prefixes are scored.
        receipt.update(status="excluded", reason=str(error), bytes=size,
                       sha256=sha(path) if path.exists() else None)
    write_new(directory / "acquisition.json", receipt)
    return {"case": source["name"], "status": receipt["status"], "reason": receipt.get("reason")}


def acquire(root):
    root = verify(root)
    verify_method(root)
    sources = declared_plan()["sources"]
    if any((root / s["name"]).exists() for s in sources):
        raise FileExistsError("Preserve existing acquisition; use a new root")
    with ThreadPoolExecutor(2) as pool:
        return list(pool.map(lambda source: acquire_case(root, source), sources))


def freeze(root):
    root = verify(root)
    verify_method(root)
    contract = json.loads((root / "rita-contract.json").read_text())
    if (contract["image"] != RITA_IMAGE or contract["internal_subnets"] != declared_plan()["internal_subnets"]
        or contract["feeds_empty"] is not True or contract["scores_unchanged"] is not True):
        raise ValueError("Native RITA contract differs from declared scope")
    cases = {}
    for source in declared_plan()["sources"]:
        directory = private_root(root / source["name"])
        receipt = effective_receipt(directory)
        if any(receipt.get(k) != v for k, v in source.items()) or (receipt["sha256"] and sha(directory / "scenario.pcap") != receipt["sha256"]):
            raise ValueError("Acquisition differs from source receipt")
        if receipt["status"] == "complete":
            before = json.loads((directory / "pre-analysis.json").read_text())
            if before["pcap_sha256"] != receipt["sha256"] or before["rita_files"] != contract["files"]:
                raise ValueError("Input/config changed before native analysis")
            # Tool failures are retained as excluded, never scored as zero.
            if (directory / "zeek.exit").read_text().strip() == "0":
                if (directory / "image.txt").read_text().strip() != ZEEK_IMAGE:
                    raise ValueError("Unexpected Zeek image")
            for file, digest in json.loads((directory / "native-output-hashes.json").read_text()).items():
                if sha(directory / file) != digest:
                    raise ValueError("Native output changed")
        cases[source["name"]] = {str(p.relative_to(directory)): sha(p) for p in sorted(directory.rglob("*")) if p.is_file() and not p.is_symlink()}
    write_new(root / "evidence-freeze.json", {"cases": cases, "rita_contract_sha256": sha(root / "rita-contract.json"),
              "tooling": tooling_hashes()})


def evaluate_case(root, source, frozen):
    directory = private_root(root / source["name"])
    verify_hashes(directory, frozen)
    receipt = effective_receipt(directory)
    if receipt["status"] != "complete":
        return {"case": source["name"], "status": "excluded", "reason": receipt["reason"], "source_sha256": receipt["sha256"]}
    if (directory / "zeek.exit").read_text().strip() != "0" or (directory / "rita.exit").read_text().strip() != "0":
        return {"case": source["name"], "status": "excluded", "reason": "Native Zeek/RITA failed; no partial scoring", "source_sha256": receipt["sha256"]}
    for kind in ("conn", "dns"):
        path = directory / f"zeek/{kind}.log"
        if path.exists() and path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("Full log exceeds existing collector bound")
    text = (directory / "zeek/conn.log").read_text()
    conn, diagnostics = analyze_zeek_conn_log_with_diagnostics(text, (), None)
    if any((diagnostics.invalid_timestamps, diagnostics.invalid_connection_fields, diagnostics.invalid_response_ips, diagnostics.skipped_missing_query_name)):
        raise ValueError("Invalid connection evidence")
    path = directory / "zeek/dns.log"
    parsed = parse_zeek_dns_log_with_diagnostics(path.read_text()) if path.exists() else None
    transactions = parse_zeek_dns_transactions(path.read_text()) if path.exists() else ()
    if parsed and any((parsed.diagnostics.invalid_timestamps, parsed.diagnostics.invalid_response_ips, parsed.diagnostics.skipped_missing_query_name)):
        raise ValueError("Invalid DNS evidence")
    if len(conn.events) + len(transactions) > MAX_RECORDS:
        raise ValueError("Full source exceeds shared capacity")
    dns = analyze_dns_events([r.event for r in transactions], (), None)
    timestamps = [e.timestamp for e in (*conn.events, *dns.events) if e.timestamp]
    if not timestamps or (max(timestamps) - min(timestamps)).total_seconds() >= 7 * 86400:
        raise ValueError("Full source outside seven-day retention")
    native = read_rita(directory / "rita.csv")
    if len(native) >= 100000 or any(None in row or any(v is None for v in row.values()) for row in native):
        raise ValueError("Malformed or capped native export")
    now = max(timestamps) + timedelta(seconds=1)
    proof = reconcile(directory, transactions, conn, now)
    write_new(directory / "offline-connections.json", json.loads(build_connection_report(conn, generated_at=now, evaluated_at=now)))
    write_new(directory / "offline-dns.json", json.loads(build_device_report(dns, generated_at=now)))
    return {"case": source["name"], "provider_intent": source["provider_intent"], "status": "evaluated",
            "source_sha256": receipt["sha256"], "packets": receipt["packets"], "conn_rows": len(conn.events), "dns_rows": len(transactions),
            "observed_span_seconds": (max(timestamps) - min(timestamps)).total_seconds(),
            "tcp_groups": sum(f.protocol == "tcp" for f in conn.connection_findings),
            "tcp_review_groups": sum(f.protocol == "tcp" and f.priority == "review" for f in conn.connection_findings),
            "tcp_coverage_limits": dict(Counter(reason for f in conn.connection_findings for reason in f.limitations)),
            "dns_groups": len(dns.device_findings), "dns_review_groups": sum(f.priority != "observe" for f in dns.device_findings),
            "dns_coverage_limits": dict(Counter(reason for f in dns.device_findings for reason in f.limitations)),
            "attempt_patterns": len(conn.connection_attempts.findings),
            "fallback_verdicts": dict(Counter(a.verdict.value for a in conn.assessments)),
            "native_rows": len(native), "native_severities": dict(Counter(r["Severity"] for r in native)),
            "conn_diagnostics": asdict(diagnostics), "dns_diagnostics": asdict(parsed.diagnostics) if parsed else None,
            "reconciliation": proof, "cti_ml_context_labels_enabled": False}


def evaluate(root):
    root = verify(root)
    verify_method(root)
    if (root / "summary.json").exists() or any((root / s["name"] / "evaluation.json").exists() for s in declared_plan()["sources"]):
        raise FileExistsError("Preserve previous comparison results")
    evidence = json.loads((root / "evidence-freeze.json").read_text())
    verify_hashes(REPO, evidence["tooling"])
    if sha(root / "rita-contract.json") != evidence["rita_contract_sha256"]:
        raise ValueError("Native contract changed")
    results = []
    for source in declared_plan()["sources"]:
        # Integrity failures abort. Product bounds/parser/reconciliation failures
        # retain an exclusion, never a misleading zero or a scored prefix.
        verify_hashes(root / source["name"], evidence["cases"][source["name"]])
        try:
            item = evaluate_case(root, source, evidence["cases"][source["name"]])
        except ValueError as error:
            item = {"case": source["name"], "status": "excluded", "reason": str(error),
                    "source_sha256": effective_receipt(root / source["name"])["sha256"]}
        write_new(root / source["name"] / "evaluation.json", item)
        results.append(item)
    summary = {"protocol": "independent-replay-v1", "cases": results, "limits": declared_plan()["limits"]}
    write_new(root / "summary.json", summary)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "seal", "acquire", "qualify", "freeze", "evaluate"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = globals()[args.action](args.root)
    print(json.dumps(result, indent=2) if result is not None else "Private experiment step completed")
