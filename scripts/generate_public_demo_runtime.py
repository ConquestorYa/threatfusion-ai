from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.demo_runtime import create_public_demo_runtime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Create a synthetic, network-free runtime for the public demo"
        )
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("runtime"),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        db_path, model_dir = create_public_demo_runtime(
            args.output_dir,
            overwrite=args.overwrite,
        )
    except (FileExistsError, OSError, TypeError, ValueError) as error:
        raise SystemExit(
            f"Public demo runtime generation failed: {type(error).__name__}"
        ) from None

    print("ThreatFusion synthetic public-demo runtime generated")
    print(f"  CTI database: {db_path}")
    print(f"  ML artifact: {model_dir}")
    print("  All CTI and training samples are synthetic.")
    print("  No network requests or third-party feed data are required.")
    print("  The demo ML artifact is not a measured production model.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
