"""Model evaluation page from the loopback API: visibility rule and content, compared with Streamlit."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings, resolve_settings

ORIGIN = "http://127.0.0.1:8600"


def _managed(tmp_path, *, model: bool):
    from scripts.demo_review_snapshot import main

    root = tmp_path / "install"
    assert main(["--managed", *(["--behavior-model"] if model else []), str(root)]) == 0
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(root), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    return root, TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)


def _lexical(path):
    settings = ApiSettings(False, None, None, cti_only=False, evaluation_report_path=path)
    return TestClient(create_app(lambda: settings, environment={}), base_url=ORIGIN)


@pytest.fixture
def holdout_report(tmp_path):
    from test_evaluation_dashboard import report

    from threatfusion.ml_evaluation_report import write_frozen_holdout_report

    path = tmp_path / "final_holdout.json"
    write_frozen_holdout_report(report(), path)
    return path


def test_hidden_in_cti_only_mode_without_the_behavior_model(tmp_path):
    _root, client = _managed(tmp_path, model=False)
    assert client.get("/api/app").json()["evaluation_available"] is False
    assert client.get("/api/evaluation").json() == {"state": "hidden"}


def test_behavior_model_report(tmp_path):
    import json

    from threatfusion import ml_local

    _root, client = _managed(tmp_path, model=True)
    assert client.get("/api/app").json()["evaluation_available"] is True
    body = client.get("/api/evaluation").json()
    report = body["report"]
    assert body["state"] == "ok" and report["kind"] == "behavior" and report["state"] == "ok"
    recipe = json.loads(ml_local.RECIPE_EVALUATION.read_text())
    assert [m["value"] for m in report["metrics"]] == [
        f"%{round(recipe['eval']['malware_capture_recall'] * 100)}",
        f"%{round(recipe['eval']['malware_group_recall'] * 100)}",
        recipe["eval"]["normal_flagged_per_unit_day"], 80]
    assert report["verdict"]["kind"] == ("success" if recipe["pass"] else "warning")
    assert report["declared"]["columns"] == ["Test", "Result", "Limit", "Passed"]
    assert [row[3] for row in report["declared"]["rows"]] == [
        bool(recipe["checks"][key]) for key in recipe["checks"] if key.startswith("T")][:len(report["declared"]["rows"])]
    assert report["importance"]["bars"] == [{"label": "Steady rhythm", "value": 1.0}]
    assert report["importance"]["columns"] == ["Feature", "Importance"]
    assert report["limits"].startswith("- The malware recordings")


def test_behavior_report_in_turkish(tmp_path):
    _root, client = _managed(tmp_path, model=True)
    report = client.get("/api/evaluation", params={"lang": "tr"}).json()["report"]
    assert report["title"] == "Deneysel davranış modeli"
    assert report["importance"]["bars"][0]["label"] == "Düzenli ritim"
    assert report["declared"]["columns"] == ["Test", "Sonuç", "Sınır", "Geçti"]


def test_lexical_report_not_evaluated(tmp_path):
    client = _lexical(tmp_path / "missing.json")
    assert client.get("/api/app").json()["evaluation_available"] is True
    report = client.get("/api/evaluation").json()["report"]
    assert report["kind"] == "lexical" and report["state"] == "not_evaluated" and report["guide_open"] is True
    assert report["title"] == "Final holdout not evaluated"
    assert report["command"].startswith("python scripts/evaluate_ml_final_holdout.py")


def test_lexical_report_unreadable(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{")
    report = _lexical(path).get("/api/evaluation").json()["report"]
    assert report["state"] == "unreadable" and report["error"] == "The final holdout report could not be loaded."




def test_lexical_report_values_and_formatting(holdout_report):
    report = _lexical(holdout_report).get("/api/evaluation").json()["report"]
    assert report["state"] == "ok" and report["model"] == "Model: model-a"
    assert [m["value"] for m in report["metrics"]] == [140, 20, 120, 20, 100]
    assert report["chart"]["groups"][0] == {"label": "High", "values": [0.4, 0.05]}
    operating = dict(zip(report["operating"]["columns"], report["operating"]["rows"][0]))
    assert operating["Operating point"] == "High" and operating["Threshold"] == "0.800000"
    assert operating["Recall"] == "40.00%" and operating["False-positive rate"] == "5.00%"
    assert report["sources"]["rows"] and report["protocol"][0].startswith("Protocol: fresh-collection disjoint holdout")
