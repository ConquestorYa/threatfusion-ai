"""Immutable synthetic DNS coverage controls, not a malware-accuracy benchmark."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import random
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from threatfusion.dns import DNSEvent
from threatfusion.models import IOCRecord, IOCType
from threatfusion.reporting import build_device_report
from threatfusion.runtime_analysis import analyze_dns_csv_with_diagnostics

PROTOCOL = "dns-device-controls-v1"
SEEDS = (20261005, 20261019)


def controls(seed: int) -> tuple[list[dict], list[IOCRecord]]:
    rng = random.Random(seed)
    cases = []
    start = datetime(2026, 9, 10, tzinfo=timezone.utc)

    def add(name, offsets, *, clients=None, missing=False, duplicate=False, intent="benign", priorities=("observe",)):
        domain = f"s{rng.randrange(100000000, 999999999)}.test"
        events = [DNSEvent(
            domain, timestamp=start + timedelta(seconds=offset),
            client_ip=clients[index] if clients else "192.0.2.1",
            query_type="A", response_ip="198.51.100.1", response_code="NOERROR",
        ) for index, offset in enumerate(offsets)]
        if missing:
            events[0].timestamp = None
        if duplicate:
            events = [event for event in events for _ in range(2)]
        cases.append({"name": name, "intent": intent, "events": events,
                      "expected_priorities": sorted(priorities)})
        return domain

    add("irregular_browsing", sorted(rng.sample(range(7200), 24)))
    add("legitimate_updates", [i * 300 for i in range(24)], priorities=("review",))
    add("heartbeat_simulation", [i * 300 for i in range(24)],
        intent="controlled_suspicious_simulation", priorities=("review",))
    add("jittered_benign_polling", [i * 300 + rng.randint(0, 15) for i in range(24)], priorities=("review",))
    add("sparse_cached_dns", [i * 600 for i in range(5)])
    add("short_capture", [i * 2 for i in range(20)])
    add("duplicate_answer_rows", [i * 300 for i in range(10)], duplicate=True)
    add("missing_timestamp", [i * 300 for i in range(24)], missing=True)
    add("missing_client", [i * 300 for i in range(24)], clients=[None] * 24)
    add("pooled_clients", [i * 300 for i in range(24)],
        clients=[f"192.0.2.{1 + i % 2}" for i in range(24)], priorities=("observe", "observe"))
    add("shared_host_ip_context", [0, 1], clients=["192.0.2.1", "192.0.2.2"], priorities=("review", "observe"))
    cases[-1]["events"][1].response_ip = "198.51.100.2"
    exact = add("exact_domain_fixture", [0], intent="synthetic_ioc_observation", priorities=("investigate",))
    # Only this one case gets IP context; other synthetic answers stay clean.
    for case in cases:
        if case["name"] != "shared_host_ip_context":
            for event in case["events"]:
                event.response_ip = "198.51.100.2"
    return cases, [IOCRecord(exact, IOCType.DOMAIN, "Synthetic-Lab"),
                   IOCRecord("198.51.100.1", IOCType.IPV4, "Synthetic-Lab")]


def _csv(events: list[DNSEvent]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(asdict(events[0])))
    writer.writeheader()
    for event in events:
        row = asdict(event)
        row["timestamp"] = event.timestamp.isoformat() if event.timestamp else ""
        writer.writerow(row)
    return output.getvalue()


def _write(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8") as file:
        file.write(content)
    path.chmod(0o600)


def evaluate(directory: Path) -> dict:
    repository = Path(__file__).resolve().parents[2]
    directory = directory.resolve()
    if directory.is_relative_to(repository):
        raise ValueError("Evaluation output must stay outside the repository")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    inputs = []
    for seed in SEEDS:
        cases, fixtures = controls(seed)
        for index, case in enumerate(cases):
            path = directory / f"seed-{seed}-case-{index:02d}.csv"
            _write(path, _csv(case["events"]))
            inputs.append((path, case, fixtures))
    manifest = {
        "protocol": PROTOCOL, "seeds": SEEDS, "ml_enabled": False,
        "cti_mode": "reserved_synthetic_fixtures_only",
        "cases": [{"input": path.name, "name": case["name"], "intent": case["intent"],
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "expected_priorities": case["expected_priorities"]}
                  for path, case, _ in inputs],
        "limitations": [
            "Synthetic engineering controls; not real benign traffic or a malware dataset.",
            "Expected priorities test policy contracts, not FPR, recall or RITA superiority.",
            "Benign updates and heartbeat simulations must both receive periodic review.",
            "No new ML evaluation, threshold selection or promotion.",
        ],
    }
    _write(directory / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    _write(directory / "manifest.sha256", hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest() + "\n")
    observations = []
    for (path, case, fixtures), declared in zip(inputs, manifest["cases"], strict=True):
        if hashlib.sha256(path.read_bytes()).hexdigest() != declared["sha256"]:
            raise ValueError("Frozen control input changed before evaluation")
        # No scenario intent, role or expected result enters product code.
        result, diagnostics = analyze_dns_csv_with_diagnostics(path.read_text(), fixtures, None)
        priorities = sorted(f.priority for f in result.device_findings)
        _write(path.with_suffix(".device.json"), build_device_report(result))
        observations.append({"input": path.name, "case": case["name"],
                             "accepted_events": diagnostics.accepted_rows,
                             "priorities": priorities,
                             "passed": priorities == case["expected_priorities"]})
    summary = {"protocol": PROTOCOL, "cases": len(observations),
               "passed": sum(row["passed"] for row in observations),
               "observations": observations, "limitations": manifest["limitations"]}
    _write(directory / "summary.json", json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.output_dir)
    print(f"Synthetic device controls: {result['passed']}/{result['cases']} policy checks passed")
    print("Engineering coverage only; no accuracy or superiority claim.")
    raise SystemExit(0 if result["passed"] == result["cases"] else 1)


if __name__ == "__main__":
    main()
