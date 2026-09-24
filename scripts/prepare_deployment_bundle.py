from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.deployment_bundle import create_deployment_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare a sanitized ThreatFusion hosted-runtime bundle"
    )
    parser.add_argument(
        "--source-db",
        type=Path,
        default=Path("data/threatfusion.sqlite"),
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path("data/models/development-001"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/deployment/runtime"),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        bundle = create_deployment_bundle(
            args.source_db,
            args.model_dir,
            args.output_dir,
            overwrite=args.overwrite,
        )
    except (FileNotFoundError, OSError, TypeError, ValueError) as error:
        raise SystemExit(
            f"Deployment bundle failed: {type(error).__name__}"
        ) from None

    print("ThreatFusion sanitized deployment bundle prepared")
    print(f"  Output directory: {bundle.output_dir}")
    print(f"  CTI database: {bundle.db_path}")
    print(f"  Model directory: {bundle.model_dir}")
    print("  CTI cache:")
    for status in bundle.cti_status:
        print(f"    {status.source}: {status.record_count} records")
    print("  Analysis history was not copied.")
    print("  IOC values and secrets were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
