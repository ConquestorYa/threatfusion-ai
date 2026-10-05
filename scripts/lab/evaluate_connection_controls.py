"""Count review burden on declared synthetic connection workloads, not FPR."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from threatfusion.connections import POLICY_ID
from threatfusion.reporting import build_connection_report
from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics

PROTOCOL = "connection-workload-controls-v1"
SEEDS = (20261007, 20261021, 20261104)
FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "missed_bytes")


def controls(seed: int) -> list[dict]:
    rng = random.Random(seed)
    cases = []
    def add(name, times, *, intent="benign", **changes):
        records = [dict(zip(FIELDS, (1791072000 + offset, f"C{index}", "192.0.2.1", 40000 + index,
                                     "198.51.100.1", 443, "tcp", 0.5, 128, 256, "SF", 0), strict=True)) | changes
                   for index, offset in enumerate(times)]
        cases.append({"name": name, "intent": intent, "records": records})
    add("irregular_browser", sorted(rng.sample(range(21600), 24)))
    for index, record in enumerate(cases[-1]["records"]):
        record["resp_bytes"] = 256 + index * 191
    periodic = [i * 300 for i in range(72)]
    add("legitimate_updates", periodic)
    add("heartbeat_simulation", periodic, intent="controlled_suspicious_simulation")
    add("jittered_benign_polling", [i * 300 + rng.randint(0, 15) for i in range(72)])
    add("long_benign_stream", [0], duration=7200, orig_bytes=100000, resp_bytes=5000000)
    add("long_idle_session", [0], duration=7200, orig_bytes=0, resp_bytes=0)
    add("short_persistent_session", [0], duration=2400, resp_bytes=250000)
    add("failed_retries", periodic, conn_state="S0", resp_bytes=0, duration=3)
    add("duplicate_rows", [i * 300 for i in range(10)])
    cases[-1]["records"] *= 3
    add("split_ports", [i * 300 for i in range(24)])
    for index, record in enumerate(cases[-1]["records"]):
        record["id.resp_p"] = 443 if index % 2 else 8443
    add("missing_duration", periodic, duration="-")
    return cases


def zeek_text(records: list[dict]) -> str:
    return "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n" + "".join(
        "\t".join(str(record[field]) for field in FIELDS) + "\n" for record in records
    )


def write(path: Path, content: str) -> None:
    with path.open("x") as file:
        file.write(content)
    path.chmod(0o600)


def evaluate(directory: Path) -> dict:
    directory = directory.resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Control outputs must stay outside the repository")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    cases = []
    for seed in SEEDS:
        for index, case in enumerate(controls(seed)):
            path = directory / f"seed-{seed}-case-{index:02d}.conn.log"
            write(path, zeek_text(case["records"]))
            cases.append({"seed": seed, "name": case["name"], "intent": case["intent"],
                          "input": path.name, "rows": len(case["records"]),
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    limitations = [
        "Constructed Zeek-format records, not packet capture or production telemetry.",
        "Labels describe workload intent, not confirmed malware.",
        "Review burden is analyst work, not malware false-positive rate or recall.",
        "Benign update timing and harmless heartbeat intentionally match.",
        "No ML/CTI, holdout tuning, RITA scoring or production parity claim.",
    ]
    manifest = {"protocol": PROTOCOL, "policy": POLICY_ID, "seeds": SEEDS,
                "cases": cases, "limitations": limitations}
    write(directory / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    write(directory / "manifest.sha256", hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest() + "\n")
    observations = []
    for case in cases:
        path = directory / case["input"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != case["sha256"]:
            raise ValueError("Frozen connection input changed")
        result, diagnostics = analyze_zeek_conn_log_with_diagnostics(path.read_text(), [], None)
        if diagnostics.accepted_rows != case["rows"] or diagnostics.invalid_connection_fields:
            raise ValueError("Control metadata failed validation")
        write(path.with_suffix(".review.json"), build_connection_report(result))
        observations.append({"seed": case["seed"], "name": case["name"], "intent": case["intent"],
                             "groups": len(result.connection_findings),
                             "review_groups": sum(f.priority == "review" for f in result.connection_findings)})
    benign = [row for row in observations if row["intent"] == "benign"]
    simulated = [row for row in observations if row["intent"] != "benign"]
    summary = {"protocol": PROTOCOL, "cases": len(cases),
               "benign_groups": sum(row["groups"] for row in benign),
               "benign_review_groups": sum(row["review_groups"] for row in benign),
               "simulated_groups": sum(row["groups"] for row in simulated),
               "simulated_review_groups": sum(row["review_groups"] for row in simulated),
               "observations": observations, "limitations": limitations}
    write(directory / "summary.json", json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.output_dir)
    print(f"Validated synthetic connection workloads: {result['cases']} cases")
    print(f"Benign review burden: {result['benign_review_groups']}/{result['benign_groups']} groups")
    print(f"Simulated review groups: {result['simulated_review_groups']}/{result['simulated_groups']}")
    print("Review counts are not malware accuracy, false-positive rate or recall.")


if __name__ == "__main__":
    main()
