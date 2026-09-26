from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.cti_refresh import refresh_configured_sources


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Refresh ThreatFusion CTI using full/current upstream feeds. "
            "Existing source data is preserved when a source refresh fails."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("data/threatfusion.sqlite"),
    )
    parser.add_argument(
        "--sgb-max-pages",
        "--sgb-pages",
        dest="sgb_max_pages",
        type=int,
        default=100,
        help="maximum SGB pages to fetch; stops earlier when the source ends",
    )
    parser.add_argument(
        "--stale-hours",
        type=float,
        default=6.0,
        help="skip a source refreshed more recently than this value",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="refresh configured sources even when their cache is fresh",
    )
    parser.add_argument(
        "--allow-missing-keys",
        action="store_true",
        help=(
            "skip keyed feeds whose environment variables are missing; "
            "SGB still refreshes"
        ),
    )
    return parser


def _secret(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else None


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.sgb_max_pages < 1:
        raise SystemExit("--sgb-max-pages must be at least 1")
    if args.stale_hours <= 0:
        raise SystemExit("--stale-hours must be positive")

    threatfox_key = _secret("THREATFOX_AUTH_KEY")
    urlhaus_key = _secret("URLHAUS_AUTH_KEY")
    phishtank_key = _secret("PHISHTANK_APP_KEY")

    missing = [
        name
        for name, value in (
            ("THREATFOX_AUTH_KEY", threatfox_key),
            ("URLHAUS_AUTH_KEY", urlhaus_key),
        )
        if value is None
    ]
    if missing and not args.allow_missing_keys:
        raise SystemExit(
            "Missing required environment variable(s): " + ", ".join(missing)
        )

    outcomes = refresh_configured_sources(
        args.db,
        threatfox_key=threatfox_key,
        urlhaus_key=urlhaus_key,
        phishtank_key=phishtank_key,
        sgb_max_pages=args.sgb_max_pages,
        stale_after=timedelta(hours=args.stale_hours),
        force=args.force,
    )

    print("ThreatFusion CTI refresh")
    print(f"  Database: {args.db}")
    for outcome in outcomes:
        if outcome.status == "refreshed":
            print(f"  {outcome.source}: refreshed ({outcome.record_count} records)")
        elif outcome.status == "fresh":
            print(f"  {outcome.source}: skipped (cache still fresh)")
        else:
            print(
                f"  {outcome.source}: failed "
                f"({outcome.error_type or 'unknown error'}); old cache preserved"
            )

    print("  IOC values and API keys were not printed.")
    return 1 if any(item.status == "failed" for item in outcomes) else 0


if __name__ == "__main__":
    raise SystemExit(main())
