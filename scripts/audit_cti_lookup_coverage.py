from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from threatfusion.cti_lookup_audit import audit_exact_url_lookup_coverage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit whether active cached URL IOCs can be retrieved by the "
            "indexed ThreatFusion quick-lookup path. No IOC destination is contacted."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("data/threatfusion.sqlite"),
    )
    parser.add_argument(
        "--source",
        default="URLhaus",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="optional maximum number of active URL records to audit",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = audit_exact_url_lookup_coverage(
        args.db,
        source=args.source,
        limit=args.limit,
    )

    print("ThreatFusion indexed CTI lookup audit")
    print(f"  Source: {report.source}")
    print(f"  Active URL records: {report.total_url_records:,}")
    print(f"  Audited URL records: {report.audited_url_records:,}")
    print(f"  Exact URL hits: {report.exact_url_hits:,}")
    print(f"  Exact URL misses: {report.exact_url_misses:,}")
    print(f"  Exact lookup coverage: {report.exact_url_coverage:.2%}")
    print(f"  IP-hosted URLs audited: {report.ip_hosted_records:,}")
    print(f"  IP-hosted exact hits: {report.ip_hosted_exact_hits:,}")
    print("  Passive local audit only; no IOC URLs were opened or resolved.")

    return 1 if report.exact_url_misses else 0


if __name__ == "__main__":
    raise SystemExit(main())
