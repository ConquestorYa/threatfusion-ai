from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.demo_cti import write_public_demo_cti_cache


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a synthetic CTI cache for the hosted/public ThreatFusion demo"
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/demo/public_demo_cti.sqlite"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    count = write_public_demo_cti_cache(args.output)

    print("ThreatFusion synthetic public-demo CTI cache generated")
    print(f"  Output: {args.output}")
    print(f"  Synthetic IOC count: {count}")
    print("  Uses only reserved documentation domains/IP ranges.")
    print("  No third-party feed data was copied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
