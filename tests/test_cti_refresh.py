from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

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
    def fetch_bounded_addresses(self, *, max_pages: int):
        assert max_pages == 100
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

    assert next(
        item for item in first if item.source == "PhishTank"
    ).status == "refreshed"
    assert next(
        item for item in second if item.source == "PhishTank"
    ).status == "fresh"


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

    assert next(
        item for item in outcomes if item.source == "PhishTank"
    ).status == "refreshed"


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
    assert [item.value for item in load_ioc_records(db_path, sources=["ThreatFox"])] == [
        "old.example"
    ]


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
        def fetch_bounded_addresses(self, *, max_pages: int):
            return SimpleNamespace(
                records=(IOCRecord("partial.example", IOCType.DOMAIN, "SGB"),),
                reached_source_end=False,
            )

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
    assert [item.value for item in load_ioc_records(db_path, sources=["SGB"])] == [
        "old-sgb.example"
    ]
