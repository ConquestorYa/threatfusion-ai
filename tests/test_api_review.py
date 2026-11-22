"""Loopback FastAPI backend for the React "What to check" page."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests.test_simple_review import VIEW
from threatfusion.api import review as review_module
from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings, resolve_settings
from threatfusion.ui_simple_review import build_review_items, item_key, load_labels

ORIGIN = "http://127.0.0.1:8600"
WRITE_HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}


def _snapshot(updated_at=None, **status):
    collector = {"updated_at": (updated_at or datetime.now(timezone.utc)).isoformat(), "cti_indicators": 1,
                 "window_seconds": 86400, "counts": {"retained_records": 4, "review_groups": 2, "rejected_files": 0}}
    collector.update(status)
    return dict(VIEW, collector=collector)


@pytest.fixture
def state(tmp_path, monkeypatch):
    state_dir = tmp_path / "collector"
    state_dir.mkdir(mode=0o700)
    holder = {"snapshot": _snapshot()}
    monkeypatch.setattr(review_module, "_read", lambda root: (holder["snapshot"], holder["snapshot"]))
    holder["settings"] = ApiSettings(True, state_dir, None)
    return holder


@pytest.fixture
def client(state):
    return TestClient(create_app(lambda: state["settings"], environment={}), base_url="http://127.0.0.1:8600")


def test_items_match_the_streamlit_list_in_order_and_wording(client):
    body = client.get("/api/review").json()
    assert body["state"] == "ok" and not body["stale"] and not body["coverage_incomplete"]
    assert [item["key"] for item in body["items"]] == [item_key(item) for item in build_review_items(VIEW)]
    assert body["counts"] == {"to_check": 5, "suspicious": 0, "threat": 2, "known": 0}
    push = next(item for item in body["items"] if item["title"] == "push.example.test")
    assert push["label"] == "Long connection" and push["destination"] == {"host": "Host 002", "port": 5228}
    assert push["what"] == ["One connection stayed open for at least an hour."]
    assert push["facts"] == ["Same addresses as: alt.example.test"]
    assert [link["name"] for link in push["links"]] == ["VirusTotal", "urlscan"]


def test_turkish_wording_comes_from_the_shared_dictionary(client):
    body = client.get("/api/review", params={"lang": "tr"}).json()
    push = next(item for item in body["items"] if item["title"] == "push.example.test")
    assert push["label"] == "Uzun bağlantı" and push["destination"]["host"] == "Sistem 002"
    assert client.get("/api/i18n", params={"lang": "tr"}).json()["To check"] == "Bakılacak"
    assert client.get("/api/review", params={"lang": "de"}).status_code == 422


def test_marks_hide_known_pin_suspicious_keep_threats_and_persist(client, state):
    for key, mark in (("dns:cdn.example.test", "known"), ("attempt:Host 006", "suspicious"),
                      ("dns:listed.example.test", "known")):
        response = client.put("/api/review/marks", json={"key": key, "mark": mark}, headers=WRITE_HEADERS)
        assert response.status_code == 204
    body = client.get("/api/review").json()
    assert body["counts"] == {"to_check": 2, "suspicious": 1, "threat": 2, "known": 1}
    assert body["items"][0]["key"] == "attempt:Host 006" and body["items"][0]["mark"] == "suspicious"
    assert any(item["key"] == "dns:listed.example.test" for item in body["items"])  # threat stays visible
    assert [item["key"] for item in body["known"]] == ["dns:cdn.example.test"]
    path = state["settings"].state_dir.parent / "review-labels.json"
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert load_labels(path)["attempt:Host 006"]["label"] == "suspicious"  # same file as Streamlit
    client.put("/api/review/marks", json={"key": "dns:cdn.example.test", "mark": None}, headers=WRITE_HEADERS)
    assert client.get("/api/review").json()["counts"]["known"] == 0


def test_only_items_in_the_current_list_can_be_marked(client, state):
    response = client.put("/api/review/marks", json={"key": "dns:not-listed.test", "mark": "known"},
                          headers=WRITE_HEADERS)
    assert response.status_code == 404
    for body in ({"key": "dns:cdn.example.test", "mark": "bogus"},
                 {"key": "dns:cdn.example.test", "mark": "known", "extra": 1}, {"key": "", "mark": None}):
        assert client.put("/api/review/marks", json=body, headers=WRITE_HEADERS).status_code == 422
    assert not (state["settings"].state_dir.parent / "review-labels.json").exists()


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1.evil.example", "192.168.1.5:8600", "bad host"])
def test_foreign_host_headers_are_refused(client, host):
    assert client.get("/api/review", headers={"Host": host}).status_code == 403


@pytest.mark.parametrize("headers", [
    {},  # no Origin
    {"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
    {"Origin": "http://evil.example:8600"},
    {"Origin": "null"},
    {"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"},
    {"Origin": ORIGIN, "Sec-Fetch-Site": "same-site"},
])
def test_cross_site_writes_are_refused(client, state, headers):
    response = client.put("/api/review/marks", json={"key": "dns:cdn.example.test", "mark": "known"},
                          headers=headers)
    assert response.status_code == 403
    assert not (state["settings"].state_dir.parent / "review-labels.json").exists()


def test_writes_need_a_json_body(client, state):
    response = client.put("/api/review/marks", content=json.dumps({"key": "dns:cdn.example.test", "mark": "known"}),
                          headers={**WRITE_HEADERS, "Content-Type": "text/plain"})
    assert response.status_code == 403


def test_vite_dev_origin_is_accepted(client):
    response = client.put("/api/review/marks", json={"key": "dns:cdn.example.test", "mark": "unsure"},
                          headers={"Origin": "http://localhost:5173", "Sec-Fetch-Site": "same-origin"})
    assert response.status_code == 204


def test_security_headers_and_no_api_docs(client):
    response = client.get("/api/health")
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert "access-control-allow-origin" not in response.headers
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_stale_and_incomplete_snapshots_are_flagged(client, state):
    state["snapshot"] = _snapshot(datetime.now(timezone.utc) - timedelta(minutes=5), input_coverage_loss=True)
    body = client.get("/api/review").json()
    assert body["stale"] and body["coverage_incomplete"]


def test_missing_unreadable_and_unconfigured_states(state, monkeypatch, tmp_path):
    def missing(root):
        raise FileNotFoundError(root)

    def broken(root):
        raise ValueError("Unsupported collector snapshot")

    client = TestClient(create_app(lambda: state["settings"], environment={}), base_url=ORIGIN)
    monkeypatch.setattr(review_module, "_read", missing)
    assert client.get("/api/review").json() == {"state": "no_snapshot"}
    monkeypatch.setattr(review_module, "_read", broken)
    assert client.get("/api/review").json() == {"state": "unreadable"}
    off = TestClient(create_app(lambda: ApiSettings(False, None, None), environment={}), base_url=ORIGIN)
    assert off.get("/api/review").json() == {"state": "not_configured"}
    assert off.put("/api/review/marks", json={"key": "dns:x", "mark": None}, headers=WRITE_HEADERS).status_code == 404
    assert TestClient(create_app(lambda: state["settings"], environment={})).get("/api/health").status_code == 403


def test_settings_follow_the_streamlit_collector_rules(tmp_path):
    public = resolve_settings({"THREATFUSION_PUBLIC_MODE": "1", "THREATFUSION_CTI_ONLY": "1"})
    assert (public.collector_available, public.state_dir, public.public_mode) == (False, None, True)
    developer = resolve_settings({"THREATFUSION_COLLECTOR_STATE_DIR": str(tmp_path / "state"),
                                  "THREATFUSION_DB_PATH": str(tmp_path / "cti.sqlite")})
    assert (developer.collector_available, developer.state_dir, developer.cti_db_path) == (
        True, tmp_path / "state", tmp_path / "cti.sqlite")
    assert developer.public_mode is False and developer.cti_only is False  # ML lookup like Streamlit
    assert resolve_settings({}).state_dir is None


def test_real_collector_snapshot_produces_the_same_items(tmp_path):
    """End to end: a collector-written private snapshot through the real reader."""
    from scripts.lab.evaluate_dns_collector import NOW, cases, log
    from threatfusion import telemetry_collector
    from threatfusion.ui_collector import read_snapshot

    source, state_dir = tmp_path / "input", tmp_path / "private"
    source.mkdir()
    case = next(case for case in cases(20261051) if case["reviews"])
    (source / "dns.log").write_text(log(case["rows"], closed=True))
    with telemetry_collector.ZeekCollector(source, state_dir) as collector:
        collector.tick(now=NOW)
    expected = [item_key(item) for item in build_review_items(read_snapshot(state_dir))]
    assert expected
    body = review_module.review_response(ApiSettings(True, state_dir, None), "en", now=NOW)
    assert body["state"] == "ok" and [item["key"] for item in body["items"]] == expected


def test_demo_snapshot_is_valid_and_uses_documentation_ranges_only(tmp_path):
    import ipaddress
    import re

    from scripts.demo_review_snapshot import main
    from threatfusion.ui_collector import read_snapshot

    assert main([str(tmp_path / "demo")]) == 0
    state = tmp_path / "demo" / "collector"
    read_snapshot(state)  # passes the same validation as live data
    body = review_module.review_response(ApiSettings(True, state, None), "en")
    assert body["counts"]["threat"] == 1 and len(body["items"]) == 5
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    text = json.dumps(body)
    for address in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
        assert any(ipaddress.ip_address(address) in network for network in documentation), address
    names = [item["title"] for item in body["items"] if not re.fullmatch(r"[\d.]+", item["title"])]
    assert names and all(name.endswith(".test") for name in names)
