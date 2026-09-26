from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.collectors.phishtank import PhishTankCollector
from threatfusion.collectors.sgb import SGBCollector
from threatfusion.collectors.threatfox import ThreatFoxCollector
from threatfusion.collectors.urlhaus import URLhausCollector
from threatfusion.cti_cache import (
    compact_cti_cache,
    prune_inactive_records,
    replace_source_records,
    validate_nonempty_refresh_batch,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Refresh the local ThreatFusion CTI SQLite cache"
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
        help=(
            "maximum SGB pages to fetch; collection stops earlier when "
            "the source reports its end"
        ),
    )
    parser.add_argument(
        "--inactive-retention-days",
        type=int,
        default=90,
        help="days of inactive IOC lifecycle history to retain",
    )
    return parser


def _required_secret(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise SystemExit(f"Missing required environment variable: {name}")
    return value.strip()


def _optional_secret(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.sgb_max_pages < 1:
        raise SystemExit("--sgb-max-pages must be at least 1")
    if args.inactive_retention_days < 1:
        raise SystemExit("--inactive-retention-days must be at least 1")

    threatfox_key = _required_secret("THREATFOX_AUTH_KEY")
    urlhaus_key = _required_secret("URLHAUS_AUTH_KEY")
    phishtank_key = _optional_secret("PHISHTANK_APP_KEY")

    print("Fetching ThreatFox full non-expired export...", flush=True)
    threatfox_records = ThreatFoxCollector(threatfox_key).fetch_full_iocs()
    print(f"  ThreatFox records: {len(threatfox_records)}", flush=True)

    print("Fetching URLhaus full database export...", flush=True)
    urlhaus_records = URLhausCollector(urlhaus_key).fetch_full_urls()
    print(f"  URLhaus records: {len(urlhaus_records)}", flush=True)

    print("Fetching SGB...", flush=True)
    sgb_result = SGBCollector().fetch_bounded_addresses(
        max_pages=args.sgb_max_pages
    )
    sgb_records = list(sgb_result.records)
    end_text = (
        "source end reached"
        if sgb_result.reached_source_end
        else "maximum page bound reached"
    )
    print(
        f"  SGB pages fetched: {sgb_result.pages_fetched} ({end_text})",
        flush=True,
    )
    print(f"  SGB records: {len(sgb_records)}", flush=True)

    refresh_batch: dict[str, list] = {
        "ThreatFox": threatfox_records,
        "URLhaus": urlhaus_records,
        "SGB": sgb_records,
    }

    if phishtank_key is not None:
        print("Fetching PhishTank verified online feed...", flush=True)
        phishtank_records = PhishTankCollector(
            phishtank_key
        ).fetch_online_verified_urls()
        print(f"  PhishTank records: {len(phishtank_records)}", flush=True)
        refresh_batch["PhishTank"] = phishtank_records
    else:
        print(
            "Skipping PhishTank (PHISHTANK_APP_KEY is not configured)",
            flush=True,
        )

    try:
        validate_nonempty_refresh_batch(refresh_batch)
    except ValueError as error:
        raise SystemExit(str(error)) from error

    refreshed_at = datetime.now(timezone.utc)
    for source, records in refresh_batch.items():
        replace_source_records(
            args.db,
            source,
            records,
            refreshed_at=refreshed_at,
        )

    pruned = prune_inactive_records(
        args.db,
        older_than_days=args.inactive_retention_days,
        now=refreshed_at,
    )
    if pruned:
        compact_cti_cache(args.db)

    print("ThreatFusion CTI cache refreshed")
    print(f"  Database: {args.db}")
    for source, records in refresh_batch.items():
        print(f"  {source}: {len(records)}")
    print(f"  Inactive lifecycle rows pruned: {pruned}")
    print("  IOC values and API keys were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
