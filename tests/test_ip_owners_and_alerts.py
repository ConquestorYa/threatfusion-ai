from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from threatfusion import cti_cache, ip_owners, notifications
from threatfusion.ui_simple_review import build_review_items, lookup_links

NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
TABLE = [
    "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.",
    "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE - Google LLC",
    "9.9.9.0\t9.9.9.255\t0\tNone\tNot routed",
    "2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE - Google LLC",
    "garbage line",
    "5.5.5.0\t5.5.5.9\t64500\tZZ\tEXAMPLE-NET",
]


def _db(tmp_path, monkeypatch, rows=None):
    db = tmp_path / "cti.sqlite"
    cti_cache.initialize_cti_cache(db)
    monkeypatch.setattr(ip_owners, "MIN_RANGES", 1)
    ip_owners.store_ip_owners(db, rows or ip_owners.parse_ip2asn(TABLE), refreshed_at=NOW)
    return db


def test_parse_skips_unrouted_and_invalid_rows_and_shortens_owners():
    rows = ip_owners.parse_ip2asn(TABLE)
    assert [(r[2], r[3], r[4]) for r in rows] == [(13335, "US", "Cloudflare, Inc."), (15169, "US", "Google LLC"),
                                                  (15169, "US", "Google LLC"), (64500, "", "EXAMPLE-NET")]


def test_lookup_finds_the_covering_range_for_ipv4_and_ipv6(tmp_path, monkeypatch):
    reader = ip_owners.IPOwnerReader(_db(tmp_path, monkeypatch))
    assert reader.lookup("8.8.8.8").label == "Google LLC · US"
    assert reader.lookup("2001:4860:4860::8888").asn == 15169
    assert reader.lookup("1.0.0.1").owner == "Cloudflare, Inc."
    assert reader.lookup("5.5.5.5").label == "EXAMPLE-NET"
    for missing in ("8.8.9.1", "9.9.9.9", "192.168.1.10", "10.0.0.1", "not an ip", "5.5.5.10"):
        assert reader.lookup(missing) is None
    reader.close()


def test_absent_table_means_no_owner_and_small_downloads_are_refused(tmp_path):
    db = tmp_path / "cti.sqlite"
    assert not ip_owners.IPOwnerReader(db)
    cti_cache.initialize_cti_cache(db)
    assert not ip_owners.IPOwnerReader(db) and ip_owners.IPOwnerReader(db).lookup("8.8.8.8") is None
    with pytest.raises(ValueError):
        ip_owners.store_ip_owners(db, ip_owners.parse_ip2asn(TABLE), refreshed_at=NOW)
    assert ip_owners.ip_owner_table_is_stale(db, now=NOW)


def test_staleness_and_refresh_failure_keeps_the_previous_table(tmp_path, monkeypatch):
    from threatfusion import cti_refresh
    from threatfusion.cti_refresh import refresh_configured_sources
    from threatfusion.models import IOCRecord, IOCType

    monkeypatch.setattr(cti_refresh, "_fetch_complete_sgb", lambda *a: [IOCRecord("sgb.test", IOCType.DOMAIN, "SGB")])
    db = _db(tmp_path, monkeypatch)
    assert not ip_owners.ip_owner_table_is_stale(db, now=NOW + timedelta(days=6))
    assert ip_owners.ip_owner_table_is_stale(db, now=NOW + timedelta(days=7))
    outcomes = refresh_configured_sources(db, threatfox_key=None, urlhaus_key=None, force=True, ip_owners=True,
                                          now=NOW + timedelta(days=8))
    assert outcomes[-1].source == "IP owners" and outcomes[-1].status == "failed"  # network refused in tests
    assert ip_owners.IPOwnerReader(db).lookup("8.8.8.8").asn == 15169
    fresh = refresh_configured_sources(db, threatfox_key=None, urlhaus_key=None, ip_owners=True,
                                       now=NOW + timedelta(days=1))
    assert fresh[-1].status == "fresh"


def test_lookup_links_for_names_and_addresses():
    assert [label for label, _ in lookup_links("x.example.test", "192.0.2.5")] == ["VirusTotal", "AbuseIPDB", "urlscan"]
    links = dict(lookup_links(None, "2001:db8::1"))
    assert links["AbuseIPDB"] == "https://www.abuseipdb.com/check/2001%3Adb8%3A%3A1"
    assert links["urlscan"].startswith("https://urlscan.io/ip/")
    assert dict(lookup_links("a b.test", None)) == {"VirusTotal": "https://www.virustotal.com/gui/search/a%20b.test",
                                                     "urlscan": "https://urlscan.io/domain/a%20b.test"}
    assert lookup_links(None, None) == []


VIEW = {
    "findings": [
        {"Originator": "192.0.2.10", "Responder": "198.51.100.7", "Responder port": 443, "Queue priority": "Review",
         "CTI match": True, "DNS names": "", "Evidence": "", "First observed": "2026-10-10T10:00:00+00:00"},
        {"Originator": "192.0.2.10", "Responder": "198.51.100.8", "Responder port": 443, "Queue priority": "Review",
         "CTI match": True, "DNS names": "bad.example.test", "Evidence": ""},
        {"Originator": "192.0.2.10", "Responder": "198.51.100.9", "Responder port": 443, "Queue priority": "Review",
         "CTI match": False, "DNS names": "", "Evidence": "Long bidirectional TCP session (at least 1 hour)"},
    ],
    "dns": {"report": {"findings": [
        {"Device": "192.0.2.10", "Target": "listed.example.test", "Queue priority": "Investigate",
         "Evidence": "Exact known-domain IOC match"},
        {"Device": "192.0.2.10", "Target": "busy.example.test", "Queue priority": "Review", "Evidence": "High DNS query volume"},
    ]}},
}


def test_review_rows_show_the_owner_and_outside_links(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    db = _db(tmp_path, monkeypatch, [(ip_owners._key("198.51.100.0"), ip_owners._key("198.51.100.255"), 64496, "NL",
                                      "Example Hosting")])
    # Documentation ranges are not global, so allow them for this rendering test only.
    script = (
        "from pathlib import Path\n"
        "from threatfusion import ip_owners\n"
        "from threatfusion.ui_simple_review import render_review_list\n"
        "from tests.test_ip_owners_and_alerts import VIEW\n"
        "reader = ip_owners.IPOwnerReader(Path(%r))\n"
        "lookup = lambda a: ip_owners.IPOwner(64496, 'Example Hosting', 'NL') if reader else None\n"
        "render_review_list(VIEW, ip_owner=lookup)\n" % str(db)
    )
    app = AppTest.from_string(script).run(timeout=15)
    assert not app.exception
    assert any(c.value == "Example Hosting · NL" for c in app.caption)
    labels = [b.proto.label for b in app.get("link_button")]
    assert {"VirusTotal", "AbuseIPDB", "urlscan"} <= set(labels)


def test_threat_alerts_only_for_threat_list_matches_and_never_show_ips():
    alerts = notifications.threat_alerts(VIEW)
    assert sorted(v or "" for v in alerts.values()) == ["", "bad.example.test", "listed.example.test"]
    title, body = notifications.message(list(alerts.values()), "tr")
    assert "198.51.100" not in body and "bir adres" in body and title.startswith("ThreatFusion")
    assert len(build_review_items(VIEW)) == 5  # the review list still shows everything


def test_each_match_notifies_once_and_state_is_private(tmp_path):
    sent = []
    path = tmp_path / notifications.NOTIFIED_FILE
    send = lambda title, body: sent.append(body) or True  # noqa: E731
    assert notifications.notify_new_threats(VIEW, path, send=send) == 3
    assert notifications.notify_new_threats(VIEW, path, send=send) == 0
    assert len(sent) == 1
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    more = {"findings": [], "dns": {"report": {"findings": [
        {"Target": "new.example.test", "Queue priority": "Investigate", "Evidence": "Exact known-domain IOC match"}]}}}
    assert notifications.notify_new_threats(more, path, send=send) == 1 and "new.example.test" in sent[-1]
    assert notifications.notify_new_threats({"findings": []}, tmp_path / "other.json", send=send) == 0


def test_failed_send_is_not_retried_every_poll(tmp_path):
    calls = []
    path = tmp_path / notifications.NOTIFIED_FILE
    assert notifications.notify_new_threats(VIEW, path, send=lambda t, b: calls.append(1) or False) == 3
    assert notifications.notify_new_threats(VIEW, path, send=lambda t, b: calls.append(1) or False) == 0
    assert calls == [1]


def test_message_caps_names():
    title, body = notifications.message(["a.test", "b.test", "c.test", "d.test", None], "en")
    assert body.startswith("5 new: a.test, b.test, c.test …")


def test_notifications_follow_the_language_chosen_in_the_app(tmp_path, monkeypatch):
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    assert notifications._language(tmp_path) == "en"
    notifications.remember_language(tmp_path, "tr")
    notifications.remember_language(tmp_path, "xx")
    assert notifications._language(tmp_path) == "tr"
    sent = []
    notifications.notify_new_threats(VIEW, tmp_path / notifications.NOTIFIED_FILE, send=lambda t, b: sent.append(t))
    assert sent == ["ThreatFusion: tehdit listesi eşleşmesi"]


def test_collector_loop_notifies_from_its_snapshot_once(tmp_path, monkeypatch):
    import json

    from threatfusion import telemetry_collector

    state = tmp_path / "collector"
    state.mkdir()
    (state / "connections.json").write_text(json.dumps(VIEW))
    sent = []
    monkeypatch.setattr(notifications, "desktop_available", lambda: True)
    monkeypatch.setattr(notifications, "_send", lambda title, body: sent.append(body) or True)
    monkeypatch.setattr(telemetry_collector, "_last_notified_snapshot", None)
    telemetry_collector._notify(state)
    telemetry_collector._notify(state)  # unchanged snapshot: not even re-read
    (state / "connections.json").write_text("not json")
    telemetry_collector._notify(state)  # a broken snapshot never raises
    assert len(sent) == 1 and (tmp_path / notifications.NOTIFIED_FILE).exists()


def test_a_name_marked_suspicious_notifies_when_seen_again_once_per_day(tmp_path):
    import json

    (tmp_path / notifications.LABELS_FILE).write_text(json.dumps({"labels": {
        "dns:busy.example.test": {"label": "suspicious", "at": "2026-10-10T09:00:00+00:00"},
        "connection:Host 004": {"label": "suspicious", "at": "2026-10-10T09:00:00+00:00"},
        "dns:old.example.test": {"label": "suspicious", "at": "2026-10-11T00:00:00+00:00"},
        "dns:other.example.test": {"label": "known", "at": "2026-10-10T09:00:00+00:00"}}}))
    view = {"findings": [], "dns": {"report": {"findings": [
        {"Target": "busy.example.test", "Queue priority": "Review", "Evidence": "", "Last observed": "2026-10-10T11:00:00+00:00"},
        {"Target": "old.example.test", "Queue priority": "Review", "Evidence": "", "Last observed": "2026-10-10T11:00:00+00:00"},
        {"Target": "other.example.test", "Queue priority": "Review", "Evidence": "", "Last observed": "2026-10-10T11:00:00+00:00"}]}}}
    sent = []
    path = tmp_path / notifications.NOTIFIED_FILE
    assert notifications.notify_new_threats(view, path, send=lambda t, b: sent.append((t, b))) == 1
    assert sent[0][0].startswith("ThreatFusion: seen again") and "busy.example.test" in sent[0][1]
    assert notifications.notify_new_threats(view, path, send=lambda t, b: sent.append((t, b))) == 0
    view["dns"]["report"]["findings"][0]["Last observed"] = "2026-10-11T08:00:00+00:00"
    assert notifications.notify_new_threats(view, path, send=lambda t, b: sent.append((t, b))) == 1  # next day
