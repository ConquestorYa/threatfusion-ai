from __future__ import annotations

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
ProgressCallback = Callable[[str, str, str | None], None]


@dataclass(frozen=True)
class CTIRefreshOutcome:
    source: str
    status: str
    record_count: int = 0
    error_type: str | None = None
    detail: str | None = None


class _IncompleteSGBSnapshotError(ValueError):
    """Internal marker for a safe, actionable pagination diagnostic."""


def _safe_failure_detail(error: Exception) -> str:
    # Exceptions from HTTP clients/parsers may contain key-bearing URLs,
    # response bodies or IOC/private values. Never forward their raw text.
    if isinstance(error, _IncompleteSGBSnapshotError):
        return "SGB snapshot incomplete; increase --sgb-max-pages and retry."
    return "Source refresh failed; check source access, credentials and network."


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


def _fetch_complete_sgb(
    max_pages: int,
    progress: ProgressCallback | None = None,
) -> list[IOCRecord]:
    def show_page(
        page: int,
        raw_items_seen: int,
        total_count: int | None,
    ) -> None:
        if total_count is None:
            detail = f"page {page} · {raw_items_seen:,} raw records"
        else:
            detail = f"page {page} · {raw_items_seen:,} / {total_count:,} raw records"
        _emit_progress(progress, "SGB", "fetching", detail)

    result = SGBCollector().fetch_bounded_addresses(
        max_pages=max_pages,
        progress=show_page,
    )
    if not result.reached_source_end:
        raise _IncompleteSGBSnapshotError(
            "SGB page bound reached before the source end "
            f"after {result.pages_fetched} pages; increase --sgb-max-pages"
        )
    return list(result.records)


def _emit_progress(
    callback: ProgressCallback | None,
    source: str,
    stage: str,
    detail: str | None = None,
) -> None:
    if callback is not None:
        callback(source, stage, detail)


def refresh_configured_sources(
    db_path: Path,
    *,
    threatfox_key: str | None,
    urlhaus_key: str | None,
    phishtank_key: str | None = None,
    sgb_max_pages: int = 100,
    stale_after: timedelta = timedelta(hours=6),
    force: bool = False,
    now: datetime | None = None,
    progress: ProgressCallback | None = None,
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
    phishtank_app_key = (
        phishtank_key.strip() if phishtank_key and phishtank_key.strip() else None
    )
    jobs.append(
        (
            "PhishTank",
            lambda: (
                PhishTankCollector(app_key=phishtank_app_key)
                if phishtank_app_key is not None
                else PhishTankCollector()
            ).fetch_verified_online_urls(),
        )
    )

    jobs.append(
        (
            "SGB",
            lambda: _fetch_complete_sgb(sgb_max_pages, progress),
        )
    )

    outcomes: list[CTIRefreshOutcome] = []
    for source, fetcher in jobs:
        source_stale_after = (
            PHISHTANK_PUBLIC_REFRESH_INTERVAL if source == "PhishTank" else stale_after
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
            _emit_progress(progress, source, "skipped", "cache still fresh")
            outcomes.append(CTIRefreshOutcome(source=source, status="fresh"))
            continue

        fetch_detail = {
            "ThreatFox": "downloading full current export",
            "URLhaus": "downloading full export with recent-feed fallback",
            "PhishTank": (
                "downloading authenticated phishing feed"
                if phishtank_app_key is not None
                else "downloading public phishing feed"
            ),
            "SGB": f"fetching paginated feed (up to {sgb_max_pages} pages)",
        }.get(source)
        _emit_progress(progress, source, "fetching", fetch_detail)

        try:
            records = fetcher()
            _emit_progress(
                progress,
                source,
                "saving",
                f"{len(records):,} records fetched; updating local cache",
            )
            count = _replace_nonempty(
                db_path,
                source,
                records,
                refreshed_at=reference,
            )
        except Exception as error:
            detail = _safe_failure_detail(error)
            _emit_progress(
                progress,
                source,
                "failed",
                f"{type(error).__name__}: {detail}",
            )
            outcomes.append(
                CTIRefreshOutcome(
                    source=source,
                    status="failed",
                    error_type=type(error).__name__,
                    detail=detail,
                )
            )
            continue

        _emit_progress(
            progress,
            source,
            "refreshed",
            f"{count:,} active records",
        )
        outcomes.append(
            CTIRefreshOutcome(
                source=source,
                status="refreshed",
                record_count=count,
            )
        )

    prune_inactive_records(db_path, older_than_days=90, now=reference)
    return tuple(outcomes)
