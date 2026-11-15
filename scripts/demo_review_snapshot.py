"""Write a synthetic collector state for UI development and browser tests.

Only documentation address ranges (RFC 5737) and ``.test`` names are used.
The real collector imports the generated Zeek logs, so the snapshot passes the
same validation as live data. A synthetic CTI cache (`cti.sqlite`, source
"Synthetic demo") lists one address and one name, so every row type of "What
to check" and a known-threat Quick lookup appear.

    .venv/bin/python scripts/demo_review_snapshot.py /tmp/tf-demo
    THREATFUSION_COLLECTOR_STATE_DIR=/tmp/tf-demo/collector THREATFUSION_DB_PATH=/tmp/tf-demo/cti.sqlite \
      .venv/bin/python -m threatfusion.api
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lab.evaluate_dns_collector import NOW as LAB_NOW, cases, log  # noqa: E402
from threatfusion.cti_cache import replace_source_records  # noqa: E402
from threatfusion.models import IOCRecord, IOCType  # noqa: E402
from threatfusion.telemetry_collector import ZeekCollector  # noqa: E402

FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
          "orig_bytes", "resp_bytes", "conn_state", "missed_bytes")
LISTED = "203.0.113.7"
LISTED_NAME = "malicious.example.test"
SOURCE = "Synthetic demo"


def write_logs(source: Path, now: datetime) -> None:
    start = int(now.timestamp()) - 6 * 3600
    rows = [[start + i * 300, f"P{i}", "192.0.2.10", 41000 + i, "198.51.100.20", 443, "tcp", 1, 120, 300, "SF", 0]
            for i in range(60)]
    rows.append([start + 100, "L1", "192.0.2.11", 42000, "203.0.113.5", 5228, "tcp", 5400, 9000, 90000, "SF", 0])
    rows += [[start + 2000 + i * 7, f"A{i}", "192.0.2.12", 43000 + i, "198.51.100.77", 20 + i, "tcp", 0, 0, 0, "S0", 0]
             for i in range(40)]
    rows += [[start + 900 + i * 1800, f"T{i}", "192.0.2.10", 44000 + i, LISTED, 443, "tcp", 2, 500, 900, "SF", 0]
             for i in range(12)]
    (source / "conn.log").write_text(
        "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n"
        + "".join("\t".join(map(str, row)) + "\n" for row in rows) + "#close\t2026-11-15-00-00-00\n")
    shift = int(now.timestamp()) - int(LAB_NOW.timestamp()) - 600
    for number, case in enumerate(case for case in cases(20261051) if case["reviews"]):
        moved = [[row[0] + shift, *row[1:]] for row in case["rows"]]
        (source / f"dns.{number}.log").write_text(log(moved, closed=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", type=Path, help="new private directory (created)")
    root = parser.parse_args(argv).root
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = root / "input"
    source.mkdir()
    now = datetime.now(timezone.utc)
    write_logs(source, now)
    indicators = [
        IOCRecord(LISTED, IOCType.IPV4, SOURCE, first_seen=now, last_seen=now, threat_type="botnet_cc",
                  confidence=0.9, tags=["synthetic"]),
        IOCRecord(LISTED_NAME, IOCType.DOMAIN, SOURCE, first_seen=now, last_seen=now, threat_type="phishing",
                  confidence=0.8, tags=["synthetic"]),
    ]
    replace_source_records(root / "cti.sqlite", SOURCE, indicators, refreshed_at=now)
    with ZeekCollector(source, root / "collector") as collector:
        counts = collector.tick(now=now, indicators=indicators)["counts"]
    print(f"state: {root / 'collector'}  review groups: {counts['review_groups']}  dns: {counts['dns_review_groups']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
