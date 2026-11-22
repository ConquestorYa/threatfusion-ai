"""Analyze telemetry → Connection activity: the optional expected-connection JSON, as in Streamlit."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings

ORIGIN = "http://127.0.0.1:8600"
HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}
SAMPLE = Path(__file__).resolve().parents[1] / "data/samples/demo/conn.log"


def _rules() -> str:
    now = datetime.now(timezone.utc)
    rule = {"id": "synthetic-updater", "originator_ip": "192.0.2.22", "responder_ip": "198.51.100.30",
            "responder_port": 443, "protocol": "tcp", "valid_from": (now - timedelta(days=1)).isoformat(),
            "valid_until": (now + timedelta(days=1)).isoformat(), "max_connections": 1000,
            "max_duration_seconds": 86400, "max_originator_bytes": 10_000_000, "max_responder_bytes": 10_000_000}
    return json.dumps({"schema_version": 1, "rules": [rule]})


def _client(public: bool = False):
    settings = ApiSettings(True, None, None, public_mode=public, cti_only=True)
    return TestClient(create_app(lambda: settings, environment={}), base_url=ORIGIN)


def _recent_sample() -> bytes:
    """The demo conn.log moved to the last hours: declarations are valid for at most 30 days."""
    lines = SAMPLE.read_text().splitlines(keepends=True)
    rows = [line for line in lines if line[:1].isdigit()]
    shift = int(datetime.now(timezone.utc).timestamp()) - 8 * 3600 - min(int(row.split("\t", 1)[0]) for row in rows)
    moved = [f"{int(line.split(chr(9), 1)[0]) + shift}\t{line.split(chr(9), 1)[1]}" if line[:1].isdigit() else line
             for line in lines]
    return "".join(moved).encode()


def _upload(client):
    return client.post("/api/analyze", params={"format": "Auto-detect", "name": "conn.log"}, content=_recent_sample(),
                       headers={**HEADERS, "Content-Type": "application/octet-stream"}).json()


def test_declarations_hide_expected_reviews_until_included():
    client = _client()
    analysis = _upload(client)
    url = f"/api/analyze/{analysis['id']}/connections"
    before = client.get(url, params={"include_ips": True}).json()
    assert before["expected"]["rules"] == 0 and before["expected"]["include_label"] is None
    responder = before["columns"].index("Responder")
    assert "198.51.100.30" in [row[responder] for row in before["rows"]]
    saved = client.put(f"/api/analyze/{analysis['id']}/expected", json={"content": _rules()}, headers=HEADERS)
    assert saved.json() == {"rules": 1}
    after = client.get(url, params={"include_ips": True}).json()
    assert after["expected"]["include_label"] == "Include declared expected activity"
    assert "198.51.100.30" not in [row[responder] for row in after["rows"]]
    shown = client.get(url, params={"include_ips": True, "include_expected": True}).json()
    row = next(row for row in shown["rows"] if row[responder] == "198.51.100.30")
    assert row[shown["columns"].index("Declared expected")] is True
    report = client.get(f"/api/analyze/{analysis['id']}/download/connections").json()
    assert any(finding["Declared expected"] for finding in report["findings"])
    assert "synthetic-updater" not in json.dumps(report)  # the declaration id stays private, as in the CLI report


def test_invalid_file_applies_nothing_and_clears_previous_rules():
    client = _client()
    analysis = _upload(client)
    client.put(f"/api/analyze/{analysis['id']}/expected", json={"content": _rules()}, headers=HEADERS)
    bad = client.put(f"/api/analyze/{analysis['id']}/expected", json={"content": "{"}, headers=HEADERS)
    assert bad.status_code == 422 and bad.json()["detail"] == "Invalid expected-connection file. No declarations applied."
    assert client.get(f"/api/analyze/{analysis['id']}/connections").json()["expected"]["rules"] == 0
    too_big = client.put(f"/api/analyze/{analysis['id']}/expected", json={"content": " " * 70_000}, headers=HEADERS)
    assert too_big.status_code == 422
    cleared = client.put(f"/api/analyze/{analysis['id']}/expected", json={"content": None}, headers=HEADERS)
    assert cleared.json() == {"rules": 0}


def test_not_offered_in_public_mode():
    client = _client(public=True)
    analysis = _upload(client)
    assert client.get(f"/api/analyze/{analysis['id']}/connections").json()["expected"] is None
    assert client.put(f"/api/analyze/{analysis['id']}/expected", json={"content": _rules()},
                      headers=HEADERS).status_code == 404
