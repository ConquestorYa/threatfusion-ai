"""Predeclare separate development/reserved TCP attempt controls before coding."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

from scripts.lab.evaluate_connection_controls import zeek_text

PROTOCOL = "tcp-attempt-controls-v1"
SEEDS = {"development": 20261008, "reserved": 20261119}
CONTRACT = {
    "policy": "tcp-attempt-review-v1",
    "window_seconds": 300,
    "distinct_failed_ports": 20,
    "distinct_failed_hosts": 20,
    "repeated_failures": 30,
    "repeated_failure_ratio": 0.9,
    "failure_states": ["S0", "REJ"],
    "max_findings": 500,
}


def controls(seed):
    rng = random.Random(seed)
    cases = []

    def rows(count, *, mode="ports", interval=1, **changes):
        return [
            {
                "ts": 1791072000 + i * interval + rng.random() * 0.05,
                "uid": f"C{i}",
                "id.orig_h": "192.0.2.1",
                "id.orig_p": 40000 + i,
                "id.resp_h": f"198.51.100.{i + 1}"
                if mode == "hosts"
                else "198.51.100.1",
                "id.resp_p": 20000 + i if mode == "ports" else 443,
                "proto": "tcp",
                "duration": 0.01,
                "orig_bytes": 0,
                "resp_bytes": 0,
                "conn_state": "REJ",
                "missed_bytes": 0,
            }
            | changes
            for i in range(count)
        ]

    def add(name, records, expected=(), intent="control"):
        cases.append(
            {
                "name": name,
                "records": records,
                "expected_patterns": sorted(expected),
                "intent": intent,
            }
        )

    add(
        "vertical_rejections",
        rows(24),
        ("failed_port_diversity",),
        "harmless_scan_simulation",
    )
    add("benign_inventory_scan", rows(24), ("failed_port_diversity",), "benign")
    add(
        "horizontal_rejections",
        rows(24, mode="hosts"),
        ("failed_host_diversity",),
        "harmless_scan_simulation",
    )
    add(
        "benign_service_outage",
        rows(36, mode="retry"),
        ("repeated_connection_failures",),
        "benign",
    )
    add("below_port_threshold", rows(19))
    add("below_host_threshold", rows(19, mode="hosts"))
    add("below_retry_threshold", rows(29, mode="retry"))
    add("slow_ports", rows(24, interval=301))
    records = rows(36)
    for i, r in enumerate(records):
        r["id.resp_p"] = 20000 + i % 18
    add("small_port_pool", records)
    add("duplicate_rows", rows(18) * 5)
    records = rows(24)
    add(
        "conflicting_uids",
        records + [r | {"id.resp_h": "198.51.100.2"} for r in records],
    )
    add("missing_originator", rows(24, **{"id.orig_h": "-"}))
    add("missing_uid", rows(24, uid="-"))
    add("missing_time", rows(24, ts="-"))
    add("capture_gap", rows(24, missed_bytes=1))
    add("udp_is_out_of_scope", rows(24, proto="udp", conn_state="S0"))
    add("half_open_is_out_of_scope", rows(24, conn_state="SH"))
    add("midstream_is_out_of_scope", rows(24, conn_state="OTH"))
    add("contradictory_failure_payload", rows(24, orig_bytes=16))
    boundary = rows(24, interval=0.5)
    for i, r in enumerate(boundary):
        r["ts"] = 1791072298 + i * 0.5
    add("crosses_aligned_bucket_boundary", boundary, ("failed_port_diversity",))
    records = rows(20, interval=0)
    records[-1]["ts"] = 1791072301
    for r in records[:-1]:
        r["ts"] = 1791072000
    add("outside_window", records)
    records = rows(20, interval=0)
    records[-1]["ts"] = 1791072300
    for r in records[:-1]:
        r["ts"] = 1791072000
    add("inclusive_window", records, ("failed_port_diversity",))
    records = rows(24)
    for i, r in enumerate(records):
        r["id.orig_h"] = "192.0.2.1" if i < 12 else "192.0.2.2"
    add("different_clients_do_not_pool", records)
    success = rows(10, mode="retry", conn_state="SF", orig_bytes=16, resp_bytes=16)
    failed = rows(30, mode="retry")
    for i, r in enumerate(failed):
        r.update(uid=f"F{i}", ts=1791072010 + i)
    add("mostly_successful_no_retry_review", success + failed)
    bad = rows(1, mode="retry", conn_state="SF", missed_bytes=1)
    add("incomplete_denominator_blocks_retry", bad + failed)
    bad = rows(1, mode="retry", conn_state="SF", ts="-")
    add("unknown_time_blocks_retry", bad + failed)
    add(
        "partial_scan_still_has_observed_diversity",
        rows(20) + rows(1, uid="-"),
        ("failed_port_diversity",),
    )
    add(
        "healthy_connections",
        rows(24, conn_state="SF", orig_bytes=16, resp_bytes=16),
        intent="benign",
    )
    add(
        "coarse_timestamp_unique_attempts",
        rows(30, mode="retry", ts=1791072000),
        ("repeated_connection_failures",),
    )
    add(
        "missing_optional_bytes",
        rows(24, orig_bytes="-", resp_bytes="-"),
        ("failed_port_diversity",),
    )
    add(
        "unanswered_syn_diversity",
        rows(24, conn_state="S0"),
        ("failed_port_diversity",),
    )
    simultaneous = rows(36, mode="retry", ts=1791072000)
    simultaneous += [
        r
        | {"uid": f"Success{i}", "conn_state": "SF", "orig_bytes": 16, "resp_bytes": 16}
        for i, r in enumerate(rows(5, mode="retry", ts=1791072000))
    ]
    add("simultaneous_successes_count_in_denominator", simultaneous)
    return cases


def write(path, content):
    with path.open("x") as file:
        file.write(content)
    path.chmod(0o600)


def prepare(directory):
    directory = directory.resolve()
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Experiment files must remain outside the repository")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    plan = {
        "protocol": PROTOCOL,
        "contract": CONTRACT,
        "seeds": SEEDS,
        "scope": "Observed S0/REJ TCP attempts with complete endpoints, aware time, nonconflicting UID and zero reported gaps. Port/host diversity reviews require 20 observed failed distinct targets; retries require 30 failures and >=90% among comparable records. Incomplete source-window evidence blocks the retry ratio, but observed scan diversity remains with coverage limits. Original connection/CTI/ML findings unchanged. One peak window per pattern/key, maximum 500 results.",
        "live_reserved_contract": {
            "vertical_closed_ports": 24,
            "horizontal_closed_hosts": 24,
            "outage_retries": 36,
            "healthy_sessions": 36,
            "attempt_reviews": 3,
            "original_connection_reviews": 0,
        },
        "limitations": [
            "Constructed controls/live synthetic packets are not independent production traffic or malware truth.",
            "Benign inventory scans and service outages can create review work.",
            "No ML, CTI, expected-declaration suppression, RITA parity or accuracy claim.",
        ],
    }
    write(directory / "plan.json", json.dumps(plan, indent=2) + "\n")
    write(
        directory / "plan.sha256",
        hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest() + "\n",
    )
    for phase, seed in SEEDS.items():
        entries = []
        for i, case in enumerate(controls(seed)):
            content = zeek_text(case["records"]) + "#close\tconstructed-control\n"
            name = f"{phase}-{i:02d}.conn.log"
            write(directory / name, content)
            entries.append(
                {k: v for k, v in case.items() if k != "records"}
                | {"file": name, "sha256": hashlib.sha256(content.encode()).hexdigest()}
            )
        write(directory / (phase + ".json"), json.dumps(entries, indent=2) + "\n")


def evaluate(directory, phase):
    from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics

    directory = directory.resolve(strict=True)
    if directory.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("Experiment files must remain outside the repository")

    rows = []
    for case in json.loads((directory / (phase + ".json")).read_text()):
        raw = (directory / case["file"]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != case["sha256"]:
            raise ValueError("Declared input changed")
        result, _ = analyze_zeek_conn_log_with_diagnostics(raw.decode(), [], None)
        actual = sorted(f.pattern for f in result.connection_attempts.findings)
        rows.append(
            case
            | {"actual_patterns": actual, "passed": actual == case["expected_patterns"]}
        )
    write(directory / (phase + ".results.json"), json.dumps(rows, indent=2) + "\n")
    return {
        "phase": phase,
        "passed": sum(r["passed"] for r in rows),
        "total": len(rows),
        "failed": [r["name"] for r in rows if not r["passed"]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("action", choices=("prepare", "development", "reserved"))
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.directory)
    else:
        print(json.dumps(evaluate(args.directory, args.action)))


if __name__ == "__main__":
    main()
