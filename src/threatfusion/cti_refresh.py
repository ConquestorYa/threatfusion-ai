from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .collectors.phishtank import PhishTankCollector
from .collectors.sgb import SGBCollector
from .collectors.threatfox import ThreatFoxCollector
from .collectors.urlhaus import URLhausCollector
from .cti_cache import (
    list_cti_cache_status,
    prune_inactive_records,
    replace_source_records,
)
from .models import IOCRecord

PHISHTANK_PUBLIC_REFRESH_INTERVAL = timedelta(hours=24)


@dataclass(frozen=True)
class CTIRefreshOutcome:
    source: str
    status: str
    record_count: int = 0
    error_type: str | None = None


def _source_is_stale(
    db_path: Path,
    source: str,
    *,
    stale_after: timedelta,
    now: datetime,
) -> bool:
    statuses = {item.source: item for item in list_cti_cache_status(db_path)}
    status = statuses.get(source)
    if status is None:
        return True
    try:
        refreshed = datetime.fromisoformat(status.refreshed_at)
    except ValueError:
        return True
    if refreshed.tzinfo is None or refreshed.utcoffset() is None:
        return True
    return now - refreshed.astimezone(timezone.utc) >= stale_after


def _replace_nonempty(
    db_path: Path,
    source: str,
    records: list[IOCRecord],
    *,
    refreshed_at: datetime,
) -> int:
    if not records:
        raise ValueError(f"{source} returned no usable indicators")
    return replace_source_records(
        db_path,
        source,
        records,
        refreshed_at=refreshed_at,
    )


def _fetch_complete_sgb(max_pages: int) -> list[IOCRecord]:
    result = SGBCollector().fetch_bounded_addresses(max_pages=max_pages)
    if not result.reached_source_end:
        raise ValueError(
            "SGB page bound reached before the source end; old cache preserved"
        )
    return list(result.records)


def refresh_configured_sources(
    db_path: Path,
    *,
    threatfox_key: str | None,
    urlhaus_key: str | None,
    sgb_max_pages: int = 100,
    stale_after: timedelta = timedelta(hours=6),
    force: bool = False,
    now: datetime | None = None,
) -> tuple[CTIRefreshOutcome, ...]:
    """Refresh configured feeds independently while preserving old cache on failure."""
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None or reference.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    if sgb_max_pages < 1:
        raise ValueError("sgb_max_pages must be at least 1")

    jobs: list[tuple[str, Callable[[], list[IOCRecord]]]] = []
    if threatfox_key and threatfox_key.strip():
        jobs.append(
            (
                "ThreatFox",
                lambda: ThreatFoxCollector(threatfox_key.strip()).fetch_full_iocs(),
            )
        )
    if urlhaus_key and urlhaus_key.strip():
        jobs.append(
            (
                "URLhaus",
                lambda: URLhausCollector(urlhaus_key.strip()).fetch_full_urls(),
            )
        )
    jobs.append(
        (
            "PhishTank",
            lambda: PhishTankCollector().fetch_verified_online_urls(),
        )
    )

    jobs.append(
        (
            "SGB",
            lambda: _fetch_complete_sgb(sgb_max_pages),
        )
    )

    outcomes: list[CTIRefreshOutcome] = []
    for source, fetcher in jobs:
        source_stale_after = (
            PHISHTANK_PUBLIC_REFRESH_INTERVAL
            if source == "PhishTank"
            else stale_after
        )
        public_feed_fresh = source == "PhishTank" and not _source_is_stale(
            db_path,
            source,
            stale_after=source_stale_after,
            now=reference,
        )
        normal_feed_fresh = not force and not _source_is_stale(
            db_path,
            source,
            stale_after=source_stale_after,
            now=reference,
        )
        if public_feed_fresh or normal_feed_fresh:
            outcomes.append(CTIRefreshOutcome(source=source, status="fresh"))
            continue

        try:
            records = fetcher()
            count = _replace_nonempty(
                db_path,
                source,
                records,
                refreshed_at=reference,
            )
        except Exception as error:
            outcomes.append(
                CTIRefreshOutcome(
                    source=source,
                    status="failed",
                    error_type=type(error).__name__,
                )
            )
            continue

        outcomes.append(
            CTIRefreshOutcome(
                source=source,
                status="refreshed",
                record_count=count,
            )
        )

    prune_inactive_records(db_path, older_than_days=90, now=reference)
    return tuple(outcomes)


_AUTO_REFRESH_LOCK = threading.Lock()
_AUTO_REFRESH_STARTED = False


def _truthy_environment(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


def start_background_refresh_if_enabled(db_path: Path) -> bool:
    """Start one process-local CTI refresh loop when explicitly enabled."""
    global _AUTO_REFRESH_STARTED

    if not _truthy_environment("THREATFUSION_AUTO_REFRESH_CTI"):
        return False

    with _AUTO_REFRESH_LOCK:
        if _AUTO_REFRESH_STARTED:
            return True
        _AUTO_REFRESH_STARTED = True

    interval_hours = float(os.environ.get("THREATFUSION_CTI_REFRESH_HOURS", "6"))
    interval_seconds = max(3600.0, interval_hours * 3600.0)
    sgb_pages = int(os.environ.get("THREATFUSION_SGB_MAX_PAGES", "100"))

    def worker() -> None:
        while True:
            refresh_configured_sources(
                db_path,
                threatfox_key=os.environ.get("THREATFOX_AUTH_KEY"),
                urlhaus_key=os.environ.get("URLHAUS_AUTH_KEY"),
                sgb_max_pages=sgb_pages,
                stale_after=timedelta(seconds=interval_seconds),
            )
            time.sleep(interval_seconds)

    threading.Thread(
        target=worker,
        name="threatfusion-cti-refresh",
        daemon=True,
    ).start()
    return True
