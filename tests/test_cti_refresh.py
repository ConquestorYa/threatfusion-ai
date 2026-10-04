from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import importlib.util
from pathlib import Path

import pytest

from threatfusion import cti_refresh
from threatfusion.cti_cache import load_ioc_records, replace_source_records
from threatfusion.models import IOCRecord, IOCType


class FakeThreatFoxCollector:
    def __init__(self, key: str) -> None:
        self.key = key

    def fetch_full_iocs(self):
        return [
            IOCRecord(
                "threatfox.example",
                IOCType.DOMAIN,
                "ThreatFox",
            )
        ]


class FakeURLhausCollector:
    def __init__(self, key: str) -> None:
        self.key = key

    def fetch_full_urls(self):
        return [
            IOCRecord(
                "https://urlhaus.example/payload",
                IOCType.URL,
                "URLhaus",
            )
        ]


class FakePhishTankCollector:
    def fetch_verified_online_urls(self):
        return [
            IOCRecord(
                "https://phish.example/login",
                IOCType.URL,
                "PhishTank",
                threat_type="phishing",
            )
        ]


class FakeSGBCollector:
    def fetch_bounded_addresses(self, *, max_pages: int, progress=None):
        assert max_pages == 100
        if progress is not None:
            progress(1, 1, 1)
        return SimpleNamespace(
            records=(
                IOCRecord(
                    "sgb.example",
                    IOCType.DOMAIN,
                    "SGB",
                ),
            ),
            reached_source_end=True,
        )


def _patch_collectors(monkeypatch):
    monkeypatch.setattr(cti_refresh, "ThreatFoxCollector", FakeThreatFoxCollector)
    monkeypatch.setattr(cti_refresh, "URLhausCollector", FakeURLhausCollector)
    monkeypatch.setattr(cti_refresh, "PhishTankCollector", FakePhishTankCollector)
    monkeypatch.setattr(cti_refresh, "SGBCollector", FakeSGBCollector)


def test_refresh_updates_all_configured_sources(tmp_path, monkeypatch):
    _patch_collectors(monkeypatch)
    db_path = tmp_path / "cti.sqlite"
    now = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)

    outcomes = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key="tf",
        urlhaus_key="uh",
        force=True,
        now=now,
    )

    assert [(item.source, item.status) for item in outcomes] == [
        ("ThreatFox", "refreshed"),
        ("URLhaus", "refreshed"),
        ("PhishTank", "refreshed"),
        ("SGB", "refreshed"),
    ]
    assert {item.source for item in load_ioc_records(db_path)} == {
        "ThreatFox",
        "URLhaus",
        "PhishTank",
        "SGB",
    }


def test_refresh_emits_source_progress(tmp_path, monkeypatch):
    _patch_collectors(monkeypatch)
    db_path = tmp_path / "cti.sqlite"
    events: list[tuple[str, str, str | None]] = []

    cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key="tf",
        urlhaus_key="uh",
        force=True,
        now=datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc),
        progress=lambda source, stage, detail: events.append((source, stage, detail)),
    )

    assert ("ThreatFox", "fetching", "downloading full current export") in events
    assert any(
        source == "ThreatFox"
        and stage == "saving"
        and detail is not None
        and "records fetched" in detail
        for source, stage, detail in events
    )
    assert any(
        source == "SGB"
        and stage == "fetching"
        and detail is not None
        and "100 pages" in detail
        for source, stage, detail in events
    )
    assert any(source == "SGB" and stage == "refreshed" for source, stage, _ in events)


def test_public_phishtank_refresh_is_throttled_even_with_force(
    tmp_path,
    monkeypatch,
):
    _patch_collectors(monkeypatch)
    db_path = tmp_path / "cti.sqlite"
    now = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)

    first = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
        now=now,
    )
    second = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
        now=now + timedelta(hours=6),
    )

    assert (
        next(item for item in first if item.source == "PhishTank").status == "refreshed"
    )
    assert next(item for item in second if item.source == "PhishTank").status == "fresh"


def test_public_phishtank_refreshes_again_after_24_hours(
    tmp_path,
    monkeypatch,
):
    _patch_collectors(monkeypatch)
    db_path = tmp_path / "cti.sqlite"
    now = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)

    cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
        now=now,
    )
    outcomes = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
        now=now + timedelta(hours=24),
    )

    assert (
        next(item for item in outcomes if item.source == "PhishTank").status
        == "refreshed"
    )


def test_failed_source_preserves_previous_healthy_cache(tmp_path, monkeypatch):
    db_path = tmp_path / "cti.sqlite"
    old_time = datetime(2026, 9, 20, tzinfo=timezone.utc)
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("old.example", IOCType.DOMAIN, "ThreatFox")],
        refreshed_at=old_time,
    )

    class FailingThreatFox:
        def __init__(self, key: str) -> None:
            pass

        def fetch_full_iocs(self):
            raise ValueError("upstream unavailable")

    monkeypatch.setattr(cti_refresh, "ThreatFoxCollector", FailingThreatFox)
    monkeypatch.setattr(cti_refresh, "PhishTankCollector", FakePhishTankCollector)
    monkeypatch.setattr(cti_refresh, "SGBCollector", FakeSGBCollector)

    outcomes = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key="tf",
        urlhaus_key=None,
        force=True,
        now=datetime(2026, 9, 26, tzinfo=timezone.utc),
    )

    threatfox = next(item for item in outcomes if item.source == "ThreatFox")
    assert threatfox.status == "failed"
    assert [
        item.value for item in load_ioc_records(db_path, sources=["ThreatFox"])
    ] == ["old.example"]


@pytest.mark.parametrize("via_cli", [False, True])
def test_raw_failure_never_reaches_callbacks_results_or_cli(
    tmp_path, monkeypatch, capsys, via_cli
):
    _patch_collectors(monkeypatch)
    secret = "fixture-secret-value"
    private = "private-telemetry.example"

    class FailingThreatFox(FakeThreatFoxCollector):
        def fetch_full_iocs(self):
            raise ValueError(f"https://feed.example/{secret}/?ioc={private}")

    monkeypatch.setattr(cti_refresh, "ThreatFoxCollector", FailingThreatFox)
    db = tmp_path / "cti.sqlite"
    replace_source_records(
        db, "ThreatFox", [IOCRecord("old.example", IOCType.DOMAIN, "ThreatFox")]
    )
    if via_cli:
        spec = importlib.util.spec_from_file_location(
            "refresh_cli",
            Path(__file__).resolve().parents[1] / "scripts/refresh_cti_cache.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setenv("THREATFOX_AUTH_KEY", secret)
        monkeypatch.setenv("URLHAUS_AUTH_KEY", "fixture-urlhaus-key")
        assert module.main(["--db", str(db), "--force"]) == 1
        output = capsys.readouterr().out
    else:
        events = []
        outcomes = cti_refresh.refresh_configured_sources(
            db,
            threatfox_key=secret,
            urlhaus_key=None,
            force=True,
            progress=lambda *args: events.append(args),
        )
        output = repr(events) + repr(outcomes)
    assert secret not in output and private not in output
    assert "https://feed.example" not in output
    assert "ValueError" in output
    assert [item.value for item in load_ioc_records(db, sources=["ThreatFox"])] == [
        "old.example"
    ]


def test_missing_keys_skip_keyed_collectors_without_a_fallback(tmp_path, monkeypatch):
    _patch_collectors(monkeypatch)

    def unavailable(*args, **kwargs):
        raise AssertionError("No default or developer key may be used")

    monkeypatch.setattr(cti_refresh, "ThreatFoxCollector", unavailable)
    monkeypatch.setattr(cti_refresh, "URLhausCollector", unavailable)
    outcomes = cti_refresh.refresh_configured_sources(
        tmp_path / "cti.sqlite",
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
    )
    assert {item.source for item in outcomes} == {"PhishTank", "SGB"}


def test_fresh_source_is_skipped_without_fetching(tmp_path, monkeypatch):
    db_path = tmp_path / "cti.sqlite"
    now = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)
    replace_source_records(
        db_path,
        "ThreatFox",
        [IOCRecord("cached.example", IOCType.DOMAIN, "ThreatFox")],
        refreshed_at=now,
    )

    class ForbiddenThreatFox:
        def __init__(self, key: str) -> None:
            raise AssertionError("fresh source must not be fetched")

    monkeypatch.setattr(cti_refresh, "ThreatFoxCollector", ForbiddenThreatFox)
    monkeypatch.setattr(cti_refresh, "PhishTankCollector", FakePhishTankCollector)
    monkeypatch.setattr(cti_refresh, "SGBCollector", FakeSGBCollector)

    outcomes = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key="tf",
        urlhaus_key=None,
        stale_after=timedelta(hours=6),
        force=False,
        now=now,
    )

    threatfox = next(item for item in outcomes if item.source == "ThreatFox")
    assert threatfox.status == "fresh"


def test_incomplete_sgb_snapshot_is_rejected_and_old_cache_is_preserved(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "cti.sqlite"
    replace_source_records(
        db_path,
        "SGB",
        [IOCRecord("old-sgb.example", IOCType.DOMAIN, "SGB")],
    )

    class IncompleteSGB:
        def fetch_bounded_addresses(self, *, max_pages: int, progress=None):
            if progress is not None:
                progress(1, 1, 1000)
            return SimpleNamespace(
                records=(IOCRecord("partial.example", IOCType.DOMAIN, "SGB"),),
                pages_fetched=max_pages,
                reached_source_end=False,
            )

    monkeypatch.setattr(cti_refresh, "PhishTankCollector", FakePhishTankCollector)
    monkeypatch.setattr(cti_refresh, "SGBCollector", IncompleteSGB)

    outcomes = cti_refresh.refresh_configured_sources(
        db_path,
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
        now=datetime(2026, 9, 26, tzinfo=timezone.utc),
    )

    sgb = next(item for item in outcomes if item.source == "SGB")
    assert sgb.status == "failed"
    assert "increase --sgb-max-pages" in (sgb.detail or "")
    assert [item.value for item in load_ioc_records(db_path, sources=["SGB"])] == [
        "old-sgb.example"
    ]


def test_sgb_page_progress_is_forwarded(tmp_path, monkeypatch) -> None:
    events: list[tuple[str, str, str | None]] = []

    class FakeSGB:
        def fetch_bounded_addresses(self, *, max_pages: int, progress=None):
            if progress is not None:
                progress(1, 9999, 15000)
                progress(2, 15000, 15000)
            return SimpleNamespace(
                records=(IOCRecord("sgb.example", IOCType.DOMAIN, "SGB"),),
                pages_fetched=2,
                reached_source_end=True,
            )

    monkeypatch.setattr(cti_refresh, "PhishTankCollector", FakePhishTankCollector)
    monkeypatch.setattr(cti_refresh, "SGBCollector", FakeSGB)

    cti_refresh.refresh_configured_sources(
        tmp_path / "cti.sqlite",
        threatfox_key=None,
        urlhaus_key=None,
        force=True,
        progress=lambda source, stage, detail: events.append((source, stage, detail)),
        now=datetime(2026, 9, 26, tzinfo=timezone.utc),
    )

    assert ("SGB", "fetching", "page 1 · 9,999 / 15,000 raw records") in events
    assert ("SGB", "fetching", "page 2 · 15,000 / 15,000 raw records") in events
