from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.cti_cache import load_ioc_records
from threatfusion.demo_data import build_demo_dns_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a safe local DNS CSV for ThreatFusion UI testing"
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("data/threatfusion.sqlite"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/demo/demo_dns.csv"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    indicators = load_ioc_records(args.db)
    dataset = build_demo_dns_csv(indicators)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(dataset.content, encoding="utf-8")

    print("ThreatFusion demo DNS CSV generated")
    print(f"  Output: {args.output}")
    print(f"  Rows: {dataset.row_count}")
    print(f"  Synthetic burst rows: {dataset.synthetic_burst_rows}")
    print(
        "  Includes cached known IOC match: "
        f"{'yes' if dataset.includes_known_ioc else 'no'}"
    )
    print("  IOC values were not printed or resolved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
