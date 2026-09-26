from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .cti_cache import replace_source_records
from .models import IOCRecord, IOCType

_DEMO_SOURCE = "ThreatFusion Demo"


def build_public_demo_iocs() -> tuple[IOCRecord, ...]:
    """Return inert documentation-only IOC values for public demos."""
    return (
        IOCRecord(
            value="known-threat.example",
            ioc_type=IOCType.DOMAIN,
            source=_DEMO_SOURCE,
            threat_type="demo",
            tags=["synthetic", "documentation-only"],
        ),
        IOCRecord(
            value="https://download.example/payload",
            ioc_type=IOCType.URL,
            source=_DEMO_SOURCE,
            threat_type="demo",
            tags=["synthetic", "documentation-only"],
        ),
        IOCRecord(
            value="203.0.113.66",
            ioc_type=IOCType.IPV4,
            source=_DEMO_SOURCE,
            threat_type="demo",
            tags=["synthetic", "documentation-only"],
        ),
        IOCRecord(
            value="2001:db8:abcd::/48",
            ioc_type=IOCType.IPV6_NETWORK,
            source=_DEMO_SOURCE,
            threat_type="demo",
            tags=["synthetic", "documentation-only"],
        ),
    )


def write_public_demo_cti_cache(
    db_path: Path,
    *,
    refreshed_at: datetime | None = None,
    overwrite: bool = False,
) -> int:
    """Create a CTI cache containing only synthetic public-demo IOCs."""
    path = Path(db_path)
    if path.exists():
        if not overwrite:
            raise FileExistsError(
                "public demo CTI cache already exists; use overwrite=True"
            )
        path.unlink()

    timestamp = refreshed_at or datetime.now(timezone.utc)
    return replace_source_records(
        path,
        _DEMO_SOURCE,
        build_public_demo_iocs(),
        refreshed_at=timestamp,
    )
