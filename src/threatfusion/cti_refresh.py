from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

from .collectors.sgb import SGBCollector
from .collectors.threatfox import ThreatFoxCollector
from .collectors.urlhaus import URLhausCollector
from .cti_cache import (
    RETIRED_SOURCES,
    list_cti_cache_status,
    prune_inactive_records,
    remove_source,
    replace_source_records,
)
from .models import IOCRecord

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
    jobs.append(
        (
            "SGB",
            lambda: _fetch_complete_sgb(sgb_max_pages, progress),
        )
    )

    outcomes: list[CTIRefreshOutcome] = []
    for source, fetcher in jobs:
        if not force and not _source_is_stale(
            db_path,
            source,
            stale_after=stale_after,
            now=reference,
        ):
            _emit_progress(progress, source, "skipped", "cache still fresh")
            outcomes.append(CTIRefreshOutcome(source=source, status="fresh"))
            continue

        fetch_detail = {
            "ThreatFox": "downloading full current export",
            "URLhaus": "downloading full export with recent-feed fallback",
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

    try:
        for retired in RETIRED_SOURCES:
            remove_source(db_path, retired)
        prune_inactive_records(db_path, older_than_days=90, now=reference)
    except (OSError, sqlite3.Error, ValueError):
        # Source snapshots have already committed independently. Maintenance
        # failure must not mislabel those updates as failed/preserved snapshots.
        outcomes.append(CTIRefreshOutcome(
            source="Cache maintenance", status="failed",
            detail="Inactive-history cleanup failed; completed source updates remain available.",
        ))
        _emit_progress(progress, "Cache maintenance", "failed", outcomes[-1].detail)
    return tuple(outcomes)
