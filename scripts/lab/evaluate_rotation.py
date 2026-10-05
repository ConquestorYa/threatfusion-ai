"""Reconcile a completed private rotation observation with its frozen candidate."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.rotation_workload import plan


def packet_counts(path):
    """Count this fixture's small unfragmented, single-segment DNS queries only."""
    import dpkt

    counts = Counter()
    seen = set()
    with path.open("rb") as file:
        reader = dpkt.pcap.Reader(file)
        assert reader.datalink() == dpkt.pcap.DLT_EN10MB
        for _, raw in reader:
            ip = dpkt.ethernet.Ethernet(raw).data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            transport = ip.data
            if (
                not isinstance(transport, (dpkt.udp.UDP, dpkt.tcp.TCP))
                or transport.dport != 53
            ):
                continue
            data = transport.data
            if not data:
                continue
            protocol = "udp" if isinstance(transport, dpkt.udp.UDP) else "tcp"
            if protocol == "tcp":
                key = (
                    ip.src,
                    ip.dst,
                    transport.sport,
                    transport.dport,
                    transport.seq,
                    data,
                )
                if key in seen:
                    continue
                seen.add(key)
                assert (
                    len(data) >= 2 and int.from_bytes(data[:2], "big") == len(data) - 2
                ), (
                    "Fixture split/coalesced frames require a separate stream reassembly evaluation"
                )
                data = data[2:]
            message = dpkt.dns.DNS(data)
            assert not message.qr and len(message.qd) == 1
            assert message.qd[0].name in {
                "normal.test",
                "missing.test",
                "outage.test",
                "silent.test",
            }
            counts[protocol] += 1
    return dict(counts)


def quantiles(values):
    values = sorted(values)
    if not values:
        return None
    return {
        "min": round(values[0], 3),
        "p50": round(values[(len(values) - 1) // 2], 3),
        "p95": round(values[int((len(values) - 1) * 0.95)], 3),
        "max": round(values[-1], 3),
        "count": len(values),
    }


def evaluate(root, capture):
    from threatfusion.dns_collection import build_dns_snapshot, transaction_payload
    from threatfusion.dns_zeek import parse_zeek_dns_transactions
    from threatfusion.reporting import build_connection_report
    from threatfusion.runtime_analysis import analyze_zeek_conn_log_with_diagnostics
    from threatfusion.telemetry_collector import ZeekCollector
    from threatfusion.ui_collector import read_snapshot

    repo = Path(__file__).resolve().parents[2]
    freeze = json.loads((root / "source-freeze.json").read_text())
    assert all(
        hashlib.sha256((repo / "src/threatfusion" / name).read_bytes()).hexdigest()
        == digest
        == hashlib.sha256(
            (root / "frozen-src/threatfusion" / name).read_bytes()
        ).hexdigest()
        for name, digest in freeze["runtime_modules"].items()
    ), "Runtime changed after the observation freeze"
    manifest = json.loads((capture / "manifest.json").read_text())
    assert manifest == plan(freeze["duration_seconds"])
    assert "0 packets dropped by kernel" in (capture / "capture.txt").read_text()
    assert capture.name == Path(freeze["ssh_run"]).name
    hashes = (capture / "pre-capture.sha256").read_text().splitlines()
    assert len(hashes) == 5
    for line in hashes:
        digest, name = line.split(maxsplit=1)
        filename = Path(name).name
        assert filename in {
            "rotation_workload.py",
            "dns_collector_workload.py",
            "run_rotation_live.sh",
            "rotation.zeek",
            "manifest.json",
        }
        path = (
            capture
            if filename in {"rotation.zeek", "manifest.json"}
            else repo / "scripts/lab"
        ) / filename
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    inputs = root / "input"
    logs = {kind: sorted(inputs.glob(f"{kind}*.log")) for kind in ("conn", "dns")}
    assert all(logs.values())
    for kind, paths in logs.items():
        captured = sorted((capture / "zeek").glob(f"{kind}*.log"))
        assert [p.name for p in captured] == [p.name for p in paths]
        assert all(a.read_bytes() == b.read_bytes() for a, b in zip(captured, paths))
        assert all(
            p.read_text().rstrip().splitlines()[-1].startswith("#close\t")
            for p in paths
        )
    transactions = [
        row
        for path in logs["dns"]
        for row in parse_zeek_dns_transactions(path.read_text())
    ]
    payloads = {transaction_payload(row) for row in transactions}
    expected = manifest["expected_dns_requests"]
    assert len(transactions) == len(payloads) == expected
    transports = Counter(row.protocol for row in transactions)
    codes = Counter(row.event.response_code or "unanswered" for row in transactions)
    cycles = manifest["cycles_per_transport"]
    packets = packet_counts(capture / "scenario.pcap")
    assert packets == {"udp": cycles * 12, "tcp": cycles * 12}
    missing = expected - len(transactions)
    assert missing == 0
    assert transports == {"udp": cycles * 12, "tcp": cycles * 12}
    assert codes == {
        "NOERROR": cycles * 8,
        "NXDOMAIN": cycles * 6,
        "SERVFAIL": cycles * 6,
        "unanswered": cycles * 4,
    }
    result, diagnostics = analyze_zeek_conn_log_with_diagnostics(
        "\n".join(p.read_text() for p in logs["conn"]), (), None
    )
    assert not any(
        (
            diagnostics.invalid_timestamps,
            diagnostics.invalid_connection_fields,
            diagnostics.invalid_response_ips,
            diagnostics.skipped_missing_query_name,
        )
    )
    snapshot = read_snapshot(root / "state")
    offline = json.loads(build_connection_report(result))
    assert all(
        snapshot[key] == offline[key] for key in ("findings", "timelines", "attempts")
    )
    dns = build_dns_snapshot(
        sorted(payloads), (), generated_at=datetime.now(timezone.utc)
    )
    assert all(
        snapshot["dns"][key] == dns[key]
        for key in (
            "coverage",
            "total_findings",
            "omitted_findings",
        )
    )
    assert all(
        snapshot["dns"]["report"][key] == dns["report"][key]
        for key in ("findings", "timelines")
    )
    with sqlite3.connect(root / "state/collector.sqlite") as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT COUNT(*) FROM records WHERE kind='dns'").fetchone()[
            0
        ] == len(transactions)
    observation = json.loads((root / "observation.json").read_text())
    assert observation["completed"]
    receipts = list(observation["receipts"].values())
    assert len(receipts) == sum(map(len, logs.values()))
    assert all("snapshot_seen_epoch" in row for row in receipts)
    if freeze["duration_seconds"] >= 900:
        assert [event["action"] for event in observation["events"]] == [
            "sigterm",
            "sigkill",
            "pause",
            "resume",
        ]
    # Exact gzip replay after a final clean restart must add no evidence.
    for kind, paths in logs.items():
        (inputs / f"{kind}.replay.log.gz").write_bytes(
            gzip.compress(paths[0].read_bytes())
        )
    with ZeekCollector(inputs, root / "state") as collector:
        restart = collector.tick()
    assert restart["counts"]["new_records"] == 0
    assert restart["counts"]["duplicate_files"] == 2
    restored = read_snapshot(root / "state")
    assert all(
        restored[key] == snapshot[key] for key in ("findings", "timelines", "attempts")
    )
    assert all(
        restored["dns"]["report"][key] == snapshot["dns"]["report"][key]
        for key in ("findings", "timelines")
    )
    samples = observation["samples"]
    proof = {
        "capture": capture.name,
        "source_freeze_sha256": hashlib.sha256(
            (root / "source-freeze.json").read_bytes()
        ).hexdigest(),
        "duration_seconds": freeze["duration_seconds"],
        "observer_elapsed_seconds": observation["elapsed_seconds"],
        "collector_ticks": observation["collector_ticks"],
        "closed_files": len(receipts),
        "expected_dns_requests": expected,
        "packet_dns_queries": packets,
        "dns_records": len(transactions),
        "packet_to_zeek_query_gap": missing,
        "connection_records": len(result.events),
        "transports": dict(transports),
        "response_codes": dict(codes),
        "events": observation["events"],
        "offline_collector_equal": True,
        "reported_kernel_drops": 0,
        "restart_counts": restart["counts"],
        "peak_sampled_rss_bytes": max(row["rss_bytes"] for row in samples),
        "peak_sampled_state_bytes": max(row["state_disk_bytes"] for row in samples),
        "sampled_scan_seconds": quantiles([row["scan_seconds"] for row in samples]),
        "closed_mtime_proxy_to_delivery_seconds": quantiles(
            [row["delivered_epoch"] - row["closed_proxy_epoch"] for row in receipts]
        ),
        "delivery_to_snapshot_observation_seconds": quantiles(
            [row["snapshot_seen_epoch"] - row["delivered_epoch"] for row in receipts]
        ),
        "dns_review_groups": restart["counts"]["dns_review_groups"],
        "limitations": (
            "Synthetic .test fixture; no independent benign FPR, malware recall or ML promotion. "
            "RSS/disk are 1-second samples, not guaranteed peak; scan timing excludes report publication. "
            "File mtime is a closure proxy; relay is 5 seconds, collector 10 seconds, observer 1 second. "
            "Reported latencies are not packet-to-alert latency and include planned outages."
        ),
    }
    write_new(root / "proof.json", proof)
    print(json.dumps(proof, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--capture-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    evaluate(private_root(args.root), private_root(args.capture_dir))
