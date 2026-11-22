"""Experimental ML (behavior model, new destinations) from the loopback API, compared with Streamlit."""
from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings, resolve_settings

ORIGIN = "http://127.0.0.1:8600"
HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}
ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")


def _install(tmp_path, *, model: bool):
    from scripts.demo_review_snapshot import main

    root = tmp_path / "install"
    assert main(["--managed", *(["--behavior-model"] if model else []), str(root)]) == 0
    return root


def _client(root):
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(root), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    return TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)


@pytest.fixture
def global_destinations(monkeypatch):
    """The demo uses documentation addresses, which the model never scores; score them here."""
    from threatfusion import ml_behavior

    monkeypatch.setattr(ml_behavior, "scorable", lambda responder, port, protocol: bool(responder) and port != 53)


def test_not_configured_without_a_collector():
    client = TestClient(create_app(lambda: ApiSettings(False, None, None), environment={}), base_url=ORIGIN)
    assert client.get("/api/behavior").json() == {"state": "not_configured"}
    response = client.put("/api/behavior/marks", json={"key": "ml:x:443", "mark": "known"}, headers=HEADERS)
    assert response.status_code == 404


def test_learning_state_without_a_model(tmp_path):
    body = _client(_install(tmp_path, model=False)).get("/api/behavior", params={"lang": "tr"}).json()
    assert body["state"] == "ok"
    assert body["caption"].startswith("Deneysel")
    assert body["model"]["state"] == "learning"
    assert len(body["model"]["captions"]) == 1 and body["model"]["captions"][0] != body["model"]["title"]
    assert body["new"]["state"] == "ok" and body["new"]["guide"].startswith("**Bu nedir?**")


def test_model_cards_scores_and_evaluation(tmp_path, global_destinations):
    from threatfusion import ml_local

    root = _install(tmp_path, model=True)
    body = _client(root).get("/api/behavior").json()
    model = body["model"]
    assert model["state"] == "ok"
    recipe = json.loads(ml_local.RECIPE_EVALUATION.read_text())["eval"]
    assert model["metrics"][2]["value"] == f"%{round(recipe['malware_capture_recall'] * 100)}"
    assert model["metrics"][3]["value"] == recipe["normal_flagged_per_unit_day"]
    titles = {card["title"] for card in model["cards"]}
    assert "198.51.100.20" in titles  # 60 connections every 5 minutes: a steady rhythm
    card = next(card for card in model["cards"] if card["title"] == "198.51.100.20")
    assert card["key"] == "ml:198.51.100.20:443" and card["score"] == "95/100" and card["level"] == "High"
    assert card["destination"] == "198.51.100.20:443/tcp" and card["device"] == "192.0.2.10"
    assert "Repeats at steady intervals" in card["why"]
    assert len(card["rhythm"]["times"]) == 60 and not ISO_TIME.search(card["rhythm"]["caption"])
    assert card["command"] == "ss -tunp dst 198.51.100.20"
    assert {link["name"] for link in card["links"]} >= {"VirusTotal", "AbuseIPDB"}
    assert model["heading"] == f"{len(model['cards'])} connection(s) stand out"
    assert model["model_caption"].startswith("Model synthetic-demo") and not ISO_TIME.search(model["model_caption"])


def test_marks_hide_known_cards_and_refuse_unknown_keys(tmp_path, global_destinations):
    root = _install(tmp_path, model=True)
    client = _client(root)
    key = "ml:198.51.100.20:443"
    assert client.put("/api/behavior/marks", json={"key": key, "mark": "known"}, headers=HEADERS).status_code == 204
    labels = json.loads((root / "review-labels.json").read_text())["labels"]
    assert labels[key]["label"] == "known"
    model = client.get("/api/behavior").json()["model"]
    assert key not in {card["key"] for card in model["cards"]}
    assert model["captions"] == ["1 you marked as known are hidden."]
    assert client.put("/api/behavior/marks", json={"key": key, "mark": None}, headers=HEADERS).status_code == 204
    for wrong in ("ml:other.test:443", "new:198.51.100.20:443", "connection:x"):
        response = client.put("/api/behavior/marks", json={"key": wrong, "mark": "known"}, headers=HEADERS)
        assert response.status_code == 404
    # Writes need the loopback origin like every other mark.
    assert client.put("/api/behavior/marks", json={"key": key, "mark": "known"}).status_code == 403


def test_turkish_wording(tmp_path, global_destinations):
    model = _client(_install(tmp_path, model=True)).get("/api/behavior", params={"lang": "tr"}).json()["model"]
    card = model["cards"][0]
    assert (card["score_label"], card["level"], card["advice_title"]) == ("Davranış puanı", "Yüksek", "Ne yapmalıyım?")
    assert "Düzenli aralıklarla tekrarlıyor" in card["why"]


def test_lookup_behavior_card(tmp_path, global_destinations):
    client = _client(_install(tmp_path, model=True))
    body = client.post("/api/lookup", json={"value": "198.51.100.20"}, headers=HEADERS).json()
    assert body["behavior"]["title"] == "Behavior on this computer (experimental ML)"
    assert [card["destination"] for card in body["behavior"]["cards"]] == ["198.51.100.20:443/tcp"]
    quiet = client.post("/api/lookup", json={"value": "quiet.example.test"}, headers=HEADERS).json()["behavior"]
    assert quiet["cards"] == [] and quiet["empty"].startswith("This computer did not talk to it often enough")


def test_lookup_without_a_model_has_no_behavior_block(tmp_path):
    body = _client(_install(tmp_path, model=False)).post("/api/lookup", json={"value": "198.51.100.20"},
                                                        headers=HEADERS).json()
    assert body["behavior"] is None


def test_details_dns_score_column(tmp_path, monkeypatch):
    from threatfusion.api import behavior

    client = _client(_install(tmp_path, model=True))
    plain = client.get("/api/details").json()["dns"]
    assert "Behavior score (ML)" not in plain["columns"]  # no scored name: no column, as in Streamlit
    target = plain["rows"][0][plain["columns"].index("Target")]
    monkeypatch.setattr(behavior, "dns_scores", lambda settings: {target: (91, "High")})
    dns = client.get("/api/details", params={"lang": "tr"}).json()["dns"]
    assert dns["rows"][0][dns["columns"].index("Davranış puanı (ML)")] == "91 · Yüksek"


def test_streamlit_parity_for_the_metrics(tmp_path, global_destinations):
    """Render the real Streamlit Experimental ML tab and compare its numbers with the API."""
    from streamlit.testing.v1 import AppTest

    root = _install(tmp_path, model=True)
    script = (
        "from pathlib import Path\n"
        "from threatfusion.ui_behavior import render_behavior_tab\n"
        f"render_behavior_tab(Path({str(root / 'collector')!r}))\n"
    )
    app = AppTest.from_string(script).run(timeout=60)
    assert not app.exception
    model = _client(root).get("/api/behavior").json()["model"]
    assert [str(metric.value) for metric in app.metric if metric.label != "Behavior score"] == \
        [str(metric["value"]) for metric in model["metrics"]]
    assert [metric.value for metric in app.metric if metric.label == "Behavior score"] == \
        [card["score"] for card in model["cards"]]
