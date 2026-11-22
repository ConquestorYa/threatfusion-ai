"""Analysis history from the loopback API: visibility, runs, comparison and analyst decisions."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import resolve_settings

ORIGIN = "http://127.0.0.1:8600"
HEADERS = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin"}
UPLOAD = {**HEADERS, "Content-Type": "application/octet-stream"}
SAMPLES = Path(__file__).resolve().parents[1] / "data/samples/demo"


@pytest.fixture
def dev(tmp_path):
    from scripts.demo_review_snapshot import main

    root = tmp_path / "dev"
    assert main(["--history-model", str(root)]) == 0
    env = {"THREATFUSION_CTI_ONLY": "0", "THREATFUSION_MODEL_DIR": str(root / "models/demo-synthetic"),
           "THREATFUSION_DB_PATH": str(root / "cti.sqlite"), "THREATFUSION_COLLECTOR_STATE_DIR": str(root / "collector"),
           "THREATFUSION_EVALUATION_REPORT": str(root / "missing.json")}
    return root, TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)


def _analyze(client, name="dns.log"):
    return client.post("/api/analyze", params={"format": "Auto-detect", "name": name},
                       content=(SAMPLES / name).read_bytes(), headers=UPLOAD).json()


def _save(client, analysis):
    response = client.post(f"/api/analyze/{analysis['id']}/save", json={}, headers=HEADERS)
    assert response.status_code == 200
    return response.json()["message"]


def test_disabled_in_the_managed_cti_only_installation(tmp_path):
    from scripts.demo_review_snapshot import main

    root = tmp_path / "install"
    assert main(["--managed", str(root)]) == 0
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(root), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    client = TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)
    assert client.get("/api/app").json()["history_available"] is False
    assert client.get("/api/history").json() == {"state": "disabled"}
    analysis = _analyze(client)
    assert analysis["export"]["save"] is None and analysis["suppressed_label"] is None
    domain = analysis["investigation"]["domains"][0]
    assert client.get(f"/api/analyze/{analysis['id']}/domain", params={"name": domain}).json()["policy"] is None
    assert client.post(f"/api/analyze/{analysis['id']}/save", json={}, headers=HEADERS).status_code == 404
    assert client.put("/api/history/1/feedback", json={"domain": domain, "label": "Benign"},
                      headers=HEADERS).status_code == 404
    assert client.put("/api/analyze/suppression", json={"domain": domain, "reason": "x"},
                      headers=HEADERS).status_code == 404


def test_save_then_list_compare_and_inspect(dev):
    _root, client = dev
    assert client.get("/api/app").json()["history_available"] is True
    empty = client.get("/api/history").json()
    assert empty["state"] == "empty" and empty["title"] == "No saved analyses yet"
    analysis = _analyze(client)
    assert analysis["export"]["save"] == "Save aggregate analysis history"
    assert _save(client, analysis).startswith("Analysis #1 saved with reproducibility metadata.")
    first = client.get("/api/history").json()
    assert first["state"] == "ok" and first["run_ids"] == [1] and first["run"] == 1
    assert first["runs"]["columns"] == ["Run ID", "Created at", "Domains", "Known Threat", "High Risk", "Review"]
    assert first["comparison"]["caption"].startswith("No earlier saved analysis exists.")
    assert first["metadata"]["checksum"] and first["metadata"]["thresholds"].startswith("Frozen thresholds: High ")
    assert first["findings"]["columns"][0] == "Domain" and "malicious.example.test" in first["findings"]["domains"]
    assert set(first["findings"]["feedback"]) == {"Not reviewed"}
    assert _save(client, _analyze(client, "dns_queries.csv")).startswith("Analysis #2 saved")
    second = client.get("/api/history").json()
    assert second["run_ids"] == [2, 1] and second["run"] == 2
    assert second["comparison"]["caption"] == "Comparing run #2 with previous run #1."
    assert client.get("/api/history", params={"run": 1}).json()["run"] == 1


def test_single_and_bulk_feedback(dev):
    _root, client = dev
    _save(client, _analyze(client))
    history = client.get("/api/history").json()
    domains = history["findings"]["domains"]
    response = client.put("/api/history/1/feedback", json={"domain": domains[0], "label": "Confirmed Threat",
                                                           "note": "checked"}, headers=HEADERS)
    assert response.status_code == 204
    current = client.get("/api/history").json()["review"]["current"]
    assert current[domains[0]] == {"label": "Confirmed Threat", "note": "checked"}
    bulk = client.put("/api/history/1/feedback/bulk", json={"domains": domains[1:3], "label": "Benign", "note": "",
                                                            "confirm": True}, headers=HEADERS)
    assert bulk.json() == {"count": 2}
    feedback = client.get("/api/history").json()["findings"]["feedback"]
    assert feedback[:3] == ["Confirmed Threat", "Benign", "Benign"]
    # A domain from another run, an unknown label, a missing confirmation or run: refused.
    assert client.put("/api/history/1/feedback", json={"domain": "other.test", "label": "Benign"},
                      headers=HEADERS).status_code == 422
    assert client.put("/api/history/1/feedback", json={"domain": domains[0], "label": "benign"},
                      headers=HEADERS).status_code == 422
    assert client.put("/api/history/1/feedback/bulk", json={"domains": domains, "label": "Benign", "confirm": False},
                      headers=HEADERS).status_code == 422
    assert client.put("/api/history/9/feedback", json={"domain": domains[0], "label": "Benign"},
                      headers=HEADERS).status_code == 404
    # Writes need the loopback origin.
    assert client.put("/api/history/1/feedback", json={"domain": domains[0], "label": "Benign"}).status_code == 403


def test_delete_and_retention_need_confirmation(dev):
    _root, client = dev
    for _ in range(3):
        _save(client, _analyze(client))
    assert client.post("/api/history/3/delete", json={"confirm": False}, headers=HEADERS).status_code == 422
    assert client.post("/api/history/3/delete", json={"confirm": True}, headers=HEADERS).json() == {"deleted": True}
    assert client.get("/api/history").json()["run_ids"] == [2, 1]
    kept = client.post("/api/history/retention", json={"keep_latest": 1, "confirm": True}, headers=HEADERS).json()
    assert kept == {"message": "Deleted older saved runs: #1"}
    again = client.post("/api/history/retention", json={"keep_latest": 1, "confirm": True}, headers=HEADERS).json()
    assert again == {"message": "No saved runs were old enough to delete."}


def test_suppression_hides_priority_findings_until_included(dev):
    _root, client = dev
    analysis = _analyze(client)
    domain = analysis["priority"][0]["domain"]
    assert client.put("/api/analyze/suppression", json={"domain": domain, "reason": "known updater", "expiry_days": 3},
                      headers=HEADERS).status_code == 204
    overview = client.get(f"/api/analyze/{analysis['id']}").json()
    assert overview["suppressed_label"] == "Include 1 locally suppressed finding(s)"
    assert domain not in [row["domain"] for row in overview["priority"]]
    included = client.get(f"/api/analyze/{analysis['id']}", params={"include_suppressed": True}).json()
    assert domain in [row["domain"] for row in included["priority"]]
    policy = client.get(f"/api/analyze/{analysis['id']}/domain", params={"name": domain}).json()["policy"]
    assert policy["suppressed"].startswith("Locally suppressed from the priority queue · known updater · ")
    assert client.put("/api/analyze/suppression", json={"domain": domain, "reason": "  "},
                      headers=HEADERS).status_code == 422
    assert client.post("/api/analyze/suppression/remove", json={"domain": domain}, headers=HEADERS).status_code == 204
    assert client.get(f"/api/analyze/{analysis['id']}").json()["suppressed_label"] is None


def test_previous_review_shows_in_a_new_analysis(dev):
    _root, client = dev
    analysis = _analyze(client)
    _save(client, analysis)
    domain = analysis["investigation"]["domains"][0]
    client.put("/api/history/1/feedback", json={"domain": domain, "label": "Benign", "note": "lab"}, headers=HEADERS)
    fresh = _analyze(client)
    policy = client.get(f"/api/analyze/{fresh['id']}/domain", params={"name": domain}).json()["policy"]
    assert policy["previous"].startswith("Previous analyst review: Benign · ") and policy["previous"].endswith(" · lab")


def test_runs_table_matches_streamlit(dev):
    from streamlit.testing.v1 import AppTest

    root, client = dev
    _save(client, _analyze(client))
    script = ("from pathlib import Path\nfrom threatfusion.ui_history import _show_history\n"
              f"_show_history(Path({str(root / 'cti.sqlite')!r}))\n")
    app = AppTest.from_string(script).run(timeout=30)
    assert not app.exception
    history = client.get("/api/history").json()
    runs = app.dataframe[0].value
    assert list(runs.columns) == history["runs"]["columns"]
    assert [[str(v) for v in row] for row in runs.values.tolist()] == \
        [[str(v) for v in row] for row in history["runs"]["rows"]]
    findings = app.dataframe[-1].value
    assert findings["Domain"].tolist() == history["findings"]["domains"]
