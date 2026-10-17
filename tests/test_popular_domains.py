from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from scripts.lab.evaluate_dns_collector import NOW, log
from threatfusion import cti_cache, popular_domains, telemetry_collector as module
from threatfusion.connections import ConnectionRecord, analyze_connections
from threatfusion.dns import DNSEvent
from threatfusion.hybrid_assessment import HybridVerdict, assess_dns_domains
from threatfusion.matching import match_dns_events
from threatfusion.models import IOCRecord, IOCType
from threatfusion.ui_collector import read_snapshot

RULES = frozenset({"test", "dyn-host.test", "*.wild.test", "!www.wild.test"})
POPULAR = popular_domains.PopularSites(frozenset({"cdn-platform.test", "push-service.test", "dyn-host.test",
                                                  "www.wild.test"}), RULES)


@pytest.mark.parametrize("name, registrable", [
    ("files.cdn-platform.test.", "cdn-platform.test"), ("cdn-platform.test", "cdn-platform.test"),
    ("a.user1.dyn-host.test", "user1.dyn-host.test"), ("dyn-host.test", None), ("test", None),
    ("a.b.wild.test", "a.b.wild.test"), ("b.wild.test", None), ("x.www.wild.test", "www.wild.test"),
    ("a.example.unlisted", "example.unlisted"),
])
def test_registrable_domain_follows_the_public_suffix_algorithm(name, registrable):
    assert popular_domains.registrable_domain(name, RULES) == registrable


def test_popularity_is_decided_by_registrable_domain():
    assert popular_domains.is_popular("files.cdn-platform.test", POPULAR)
    assert not popular_domains.is_popular("cdn-platform.test.evil.test", POPULAR)
    # A user's own subdomain on a shared (dynamic DNS) platform is not popular.
    assert not popular_domains.is_popular("c2.user1.dyn-host.test", POPULAR)
    assert not popular_domains.is_popular("files.cdn-platform.test", popular_domains.PopularSites(POPULAR.domains))
    assert not popular_domains.is_popular("files.cdn-platform.test", popular_domains.EMPTY)


def test_store_load_and_staleness(tmp_path):
    db = tmp_path / "cti.sqlite"
    assert popular_domains.load_popular_domains(db) == popular_domains.EMPTY
    cti_cache.initialize_cti_cache(db)
    assert popular_domains.load_popular_domains(db) == popular_domains.EMPTY
    names = [f"site{i}.test" for i in range(popular_domains.MIN_DOMAINS)]
    rules = [f"suffix{i}.test" for i in range(popular_domains.MIN_SUFFIX_RULES)] + ["test"]
    for small in ((["a.test"], rules), (names, ["test"])):
        with pytest.raises(ValueError):
            popular_domains.store_popular_domains(db, "ABCD", *small, refreshed_at=NOW)
    assert popular_domains.store_popular_domains(db, "ABCD", names + ["SITE1.test"], rules, refreshed_at=NOW) == len(names)
    loaded = popular_domains.load_popular_domains(db)
    assert popular_domains.is_popular("www.site7.test", loaded)
    assert not popular_domains.popular_list_is_stale(db, now=NOW + timedelta(days=6))
    assert popular_domains.popular_list_is_stale(db, now=NOW + timedelta(days=7))
    # The CTI cache loader still sees no indicators from this table.
    assert cti_cache.load_ioc_records(db) == []


def _volume_events(name, count=60):
    start = NOW - timedelta(hours=2)
    return [DNSEvent(name, timestamp=start + timedelta(seconds=97 * i), client_ip="192.0.2.11",
                     query_type="A", response_ip=f"198.51.100.{i % 7 + 1}") for i in range(count)]


def _assess(events, indicators=()):
    matches = match_dns_events(events, list(indicators))
    return {a.domain: a for a in assess_dns_domains(events, matches, popular_domains=POPULAR)}


def test_popular_site_volume_and_listed_url_are_context_not_review():
    url = IOCRecord("https://files.cdn-platform.test/payload.bin", IOCType.URL, "URLhaus")
    events = _volume_events("files.cdn-platform.test") + _volume_events("unknown-cdn.test")
    result = _assess(events, [url])
    popular = result["files.cdn-platform.test"]
    assert popular.verdict is HybridVerdict.LOW
    assert {"popular_site", "url_hostname_ioc_context"} <= set(popular.reasons)
    assert result["unknown-cdn.test"].verdict is HybridVerdict.REVIEW


def test_exact_domain_indicator_on_a_popular_site_still_wins():
    events = _volume_events("files.cdn-platform.test")
    ioc = IOCRecord("files.cdn-platform.test", IOCType.DOMAIN, "ThreatFox")
    assert _assess(events, [ioc])["files.cdn-platform.test"].verdict is HybridVerdict.KNOWN_THREAT


def test_listed_url_on_an_unpopular_host_stays_review():
    events = [DNSEvent("payload-host.test", timestamp=NOW, client_ip="192.0.2.11", response_ip="198.51.100.4")]
    url = IOCRecord("http://payload-host.test/x", IOCType.URL, "URLhaus")
    assert _assess(events, [url])["payload-host.test"].verdict is HybridVerdict.REVIEW


def _long_session(responder):
    return ConnectionRecord("C" + responder[-1], NOW - timedelta(hours=3), "192.0.2.11", responder, 40000, 5228,
                            "tcp", 7200.0, 500, 900, "SF", 0)


def test_long_session_to_a_popular_destination_is_an_observation():
    records = (_long_session("198.51.100.1"), _long_session("198.51.100.2"))
    findings = {f.responder_ip: f for f in analyze_connections(records, frozenset({"198.51.100.1"}))}
    assert findings["198.51.100.1"].priority == "observe"
    assert "popular_site_destination" in findings["198.51.100.1"].reasons
    assert findings["198.51.100.2"].priority == "review"


def test_collector_uses_dns_names_to_mark_popular_destinations(tmp_path):
    source, state = tmp_path / "input", tmp_path / "private"
    source.mkdir()
    ts = int(NOW.timestamp()) - 9000
    (source / "dns.log").write_text(log([
        [ts, "Cd1", "192.0.2.11", 40000, "192.0.2.53", 53, "udp", 1, "mtalk.push-service.test", "A", "NOERROR", "198.51.100.1"],
        [ts, "Cd2", "192.0.2.11", 40001, "192.0.2.53", 53, "udp", 2, "rare-host.test", "A", "NOERROR", "198.51.100.2"],
    ]))
    fields = "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state missed_bytes".split()
    rows = [[ts + 1, f"Cc{i}", "192.0.2.11", 40010 + i, f"198.51.100.{i}", 5228, "tcp", 7200, 500, 900, "SF", 0]
            for i in (1, 2)]
    (source / "conn.log").write_text(
        "#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(fields) + "\n"
        + "".join("\t".join(map(str, r)) + "\n" for r in rows) + "#close\t2026-10-05-03-00-00\n")
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW, popular_domains=POPULAR)
        assert status["counts"]["review_groups"] == 1
        assert collector.tick(now=NOW, popular_domains=popular_domains.EMPTY)["counts"]["review_groups"] == 2
    by_names = {r["DNS names"]: r for r in read_snapshot(state)["findings"]}
    assert by_names["rare-host.test"]["Queue priority"] == "Review"


def test_refresh_job_is_opt_in_and_failure_keeps_the_previous_list(tmp_path):
    from threatfusion.cti_refresh import refresh_configured_sources

    db = tmp_path / "cti.sqlite"
    names = [f"site{i}.test" for i in range(popular_domains.MIN_DOMAINS)]
    rules = [f"suffix{i}.test" for i in range(popular_domains.MIN_SUFFIX_RULES)] + ["test"]
    cti_cache.initialize_cti_cache(db)
    popular_domains.store_popular_domains(db, "ABCD", names, rules, refreshed_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    import threatfusion.cti_refresh as refresh_module

    original = refresh_module._fetch_complete_sgb
    refresh_module._fetch_complete_sgb = lambda *a: [IOCRecord("sgb.test", IOCType.DOMAIN, "SGB")]
    try:
        plain = refresh_configured_sources(db, threatfox_key=None, urlhaus_key=None, force=True)
        assert [o.source for o in plain] == ["SGB"]
        outcomes = refresh_configured_sources(db, threatfox_key=None, urlhaus_key=None, force=True, popular_sites=True)
    finally:
        refresh_module._fetch_complete_sgb = original
    assert outcomes[-1].source == "Tranco" and outcomes[-1].status == "failed"  # network refused in tests
    assert len(popular_domains.load_popular_domains(db).domains) == len(names)


def test_listed_url_on_a_user_subdomain_of_a_shared_platform_stays_review():
    events = _volume_events("c2.user1.dyn-host.test")
    url = IOCRecord("http://c2.user1.dyn-host.test/gate.php", IOCType.URL, "URLhaus")
    assessed = _assess(events, [url])["c2.user1.dyn-host.test"]
    assert assessed.verdict is HybridVerdict.REVIEW and "popular_site" not in assessed.reasons


def test_public_suffix_list_parsing():
    text = "// comment\n\ncom\n*.ck\n!www.ck\n// ===BEGIN PRIVATE DOMAINS===\nduckdns.org\nçok.test\n"
    assert popular_domains.parse_public_suffix_list(text) == ["com", "*.ck", "!www.ck", "duckdns.org", "çok.test".encode("idna").decode()]
