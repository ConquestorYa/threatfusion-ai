"""Quick lookup from the loopback API, built with the Streamlit page's helpers."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatfusion import i18n
from threatfusion.api import lookup as lookup_module
from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings

ORIGIN = "http://127.0.0.1:8600"
HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    from scripts.demo_review_snapshot import main

    root = tmp_path_factory.mktemp("lookup") / "demo"
    assert main([str(root)]) == 0
    return root


@pytest.fixture
def client(demo):
    settings = ApiSettings(True, demo / "collector", demo / "cti.sqlite", cti_only=True)
    return TestClient(create_app(lambda: settings, environment={}), base_url=ORIGIN)


def post(client, value, lang="en"):
    return client.post("/api/lookup", params={"lang": lang}, json={"value": value}, headers=HEADERS)


def test_known_threat_domain_with_evidence(client):
    body = post(client, "https://malicious.example.test/login").json()
    assert body["banner"]["kicker"] == "Known threat"
    assert body["evidence_state"]["heading"] == "Known threat intelligence matched"
    assert body["evidence"]["columns"][:4] == ["Source", "Match", "IOC type", "Indicator"]
    assert body["evidence"]["rows"][0][0] == "Synthetic demo"
    assert body["ml_card"] is None  # CTI-only: no model box
    assert [node["label"] for node in body["console"]] == ["Local threat intelligence", "Host shape context", "Decision"]
    assert body["registry"]["kind"] == "age" and body["registry"]["domain"] == "example.test"
    assert body["registry"]["result"] is None  # nothing sent until the button


def test_ip_lookup_shows_owner_block_and_http_warning(client):
    body = post(client, "http://203.0.113.7/x", lang="tr").json()
    assert body["banner"]["kicker"] == "Bilinen tehdit"
    assert body["notices"][0]["kind"] == "warning" and "HTTP" in body["notices"][0]["text"]
    assert body["registry"]["kind"] == "owner" and body["registry"]["owner"] is None
    assert [link["name"] for link in body["links"]] == ["VirusTotal", "AbuseIPDB", "urlscan"]


def test_low_risk_and_language_is_restored(client):
    body = post(client, "quiet.example.test", lang="tr").json()
    assert body["reasons"] == [i18n._TR["No cached CTI match was found."]]
    assert i18n.current_language() == "en"  # the per-request language does not leak


def test_invalid_and_oversized_input(client):
    assert post(client, "   ").json()["error"].startswith("Lookup input could not be analyzed")
    assert client.post("/api/lookup", json={"value": "x" * 5000}, headers=HEADERS).status_code == 422
    assert client.post("/api/lookup", json={"value": "a.test"}, headers={"Origin": "https://evil.example"}).status_code == 403


def test_status_matches_streamlit_notices(client, tmp_path):
    status = client.get("/api/lookup/status", params={"lang": "tr"}).json()
    assert status["ready"] and status["notices"] == [] and status["button"] == "Kontrol et"
    empty = TestClient(create_app(lambda: ApiSettings(False, None, tmp_path / "none.sqlite"), environment={}),
                       base_url=ORIGIN).get("/api/lookup/status").json()
    assert empty["notices"][0]["text"].startswith("CTI cache is empty")


def test_domain_age_only_on_request(client, monkeypatch):
    from datetime import datetime, timezone

    from threatfusion.domain_age import DomainAge

    calls = []

    def fake(domain, *, suffix_rules=frozenset(), **_):
        calls.append(domain)
        return DomainAge(domain, "found", datetime(2026, 11, 1, tzinfo=timezone.utc), 14, "Example Registrar")

    monkeypatch.setattr("threatfusion.domain_age.lookup_domain_age", fake)
    lookup_module._AGES.clear()
    body = client.post("/api/lookup/domain-age", json={"domain": "example.test"}, headers=HEADERS).json()
    assert calls == ["example.test"] and body["value"].startswith("Very new site")
    assert body["caption"].startswith("A very new site")
    again = post(client, "www.example.test").json()["registry"]["result"]  # cached, no second request
    assert again["value"] == body["value"] and calls == ["example.test"]
    lookup_module._AGES.clear()


def test_public_mode_has_no_registry_or_links(demo):
    settings = ApiSettings(False, None, demo / "cti.sqlite", public_mode=True)
    client = TestClient(create_app(lambda: settings, environment={}), base_url=ORIGIN)
    body = post(client, "malicious.example.test").json()
    assert body["registry"] is None and body["links"] == []
    assert client.post("/api/lookup/domain-age", json={"domain": "example.test"}, headers=HEADERS).status_code == 409


