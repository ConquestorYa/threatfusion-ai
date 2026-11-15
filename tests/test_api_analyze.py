"""Analyze telemetry (upload) from the loopback API with the demo samples."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatfusion.api import analyze as analyze_module
from threatfusion.api.app import create_app
from threatfusion.api.settings import resolve_settings

ORIGIN = "http://127.0.0.1:8600"
UPLOAD = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "Content-Type": "application/octet-stream"}
SAMPLES = Path(__file__).resolve().parents[1] / "data/samples/demo"


@pytest.fixture(scope="module")
def install(tmp_path_factory):
    from scripts.demo_review_snapshot import main

    root = tmp_path_factory.mktemp("analyze") / "install"
    assert main(["--managed", str(root)]) == 0
    return root


@pytest.fixture
def client(install):
    env = {"THREATFUSION_LOCAL_INSTALL_DIR": str(install), "THREATFUSION_LOCAL_LOOPBACK": "1"}
    return TestClient(create_app(lambda: resolve_settings(env), environment={}), base_url=ORIGIN)


def upload(client, name, content=None, *, fmt="Auto-detect", lang="en", headers=UPLOAD):
    body = (SAMPLES / name).read_bytes() if content is None else content
    return client.post("/api/analyze", params={"format": fmt, "name": name, "lang": lang}, content=body, headers=headers)


def test_samples_are_synthetic_documentation_data_only():
    import ipaddress
    import re

    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    # The publish guard lets exactly these files into Git (DEC-104).
    assert sorted(path.name for path in SAMPLES.iterdir()) == ["conn.log", "dns.log", "dns_queries.csv"]
    for path in SAMPLES.iterdir():
        text = path.read_text()
        for address in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
            assert any(ipaddress.ip_address(address) in net for net in documentation), (path.name, address)
        assert all(name.endswith(".test") for name in re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:test|com|net|org)\b", text))


def test_dns_log_finds_the_listed_name_and_regular_lookups(client):
    body = upload(client, "dns.log").json()
    assert body["input_quality"][0].startswith("Detected input: Zeek dns.log")
    assert [(p["domain"], p["verdict"]) for p in body["priority"]] == [("malicious.example.test", "Known Threat")]
    assert {m["label"]: m["value"] for m in body["metrics"]}["Known Threat"] == 1
    devices = client.get(f"/api/analyze/{body['id']}/devices").json()
    reviewed = {row[devices["columns"].index("Target")]: row[devices["columns"].index("Queue priority")] for row in devices["rows"]}
    assert reviewed == {"malicious.example.test": "Investigate", "updates.example.test": "Review"}
    detail = client.get(f"/api/analyze/{body['id']}/domain", params={"name": "malicious.example.test"}).json()
    assert detail["verdict"] == "Known Threat" and detail["primary"]["summary"].endswith("Synthetic demo · phishing")


def test_conn_log_finds_threat_list_regular_repeats_and_failed_attempts(client):
    body = upload(client, "conn.log").json()
    connections = client.get(f"/api/analyze/{body['id']}/connections").json()
    columns = connections["columns"]
    rows = {row[columns.index("Responder")]: row for row in connections["rows"]}
    assert len(rows) == 2 and all(name.startswith("Host ") for name in rows)  # aliases by default, as in Streamlit
    evidence = [row[columns.index("Evidence")] for row in connections["rows"]]
    assert "Sustained periodic successful TCP connections" in evidence
    assert any(row[columns.index("CTI match")] is True for row in connections["rows"])
    assert connections["attempts"]["rows"][0][connections["attempts"]["columns"].index("Pattern")] == "Failed attempts across multiple ports"
    with_ips = client.get(f"/api/analyze/{body['id']}/connections", params={"include_ips": True}).json()
    assert any(row[with_ips["columns"].index("Responder")] == "203.0.113.7" for row in with_ips["rows"])
    timeline = client.get(f"/api/analyze/{body['id']}/connection-timeline",
                          params={"group": connections["groups"][0]["group"]}).json()
    assert timeline["chart"]["kind"] == "line"


def test_csv_gives_the_same_story_as_the_dns_log(client):
    body = upload(client, "dns_queries.csv").json()
    assert body["input_quality"][0].startswith("Detected input: Delimited DNS table")
    assert [(p["domain"], p["verdict"]) for p in body["priority"]] == [("malicious.example.test", "Known Threat")]


def test_tables_and_reports_come_from_the_existing_functions(client, install):
    from threatfusion.cti_cache import load_ioc_records
    from threatfusion.dashboard import assessment_rows
    from threatfusion.reporting import build_analysis_report
    from threatfusion.runtime_analysis import analyze_dns_upload_with_diagnostics

    body = upload(client, "dns.log").json()
    result, _, _ = analyze_dns_upload_with_diagnostics(
        (SAMPLES / "dns.log").read_bytes(), "dns.log",
        load_ioc_records(install / "runtime/cti/threatfusion.sqlite"), None)
    assert body["findings"]["domains"] == [row["Domain"] for row in assessment_rows(result)]
    report = client.get(f"/api/analyze/{body['id']}/download/json")
    assert report.headers["content-disposition"] == 'attachment; filename="threatfusion_analysis.json"'
    expected = build_analysis_report(result, model_name="cti_only_ml_disabled", include_target_ips=False).json_text
    import json
    strip = lambda text: {k: v for k, v in json.loads(text).items() if k not in {"generated_at"}}  # noqa: E731
    assert strip(report.text) == strip(expected)
    assert "192.0.2." not in report.text  # aggregate exports keep no client IPs


def test_upload_limits_types_and_encoding(client, monkeypatch):
    assert upload(client, "notes.exe", b"x").status_code == 415
    assert upload(client, "dns.log", b"x", fmt="Generic DNS CSV").status_code == 415  # .log is not a CSV
    assert upload(client, "dns.log", b"\xff\xfe\x00bad", fmt="Zeek dns.log").json()["detail"] == "Telemetry input must use UTF-8 encoding."
    assert upload(client, "dns.log", b"x", fmt="Nonsense").status_code == 422
    monkeypatch.setattr(analyze_module, "MAX_UPLOAD_BYTES", 1024)
    assert upload(client, "dns.log").status_code == 413  # streamed body over the cap
    big = client.post("/api/analyze", params={"format": "Auto-detect", "name": "a.csv"}, content=b"x",
                      headers={**UPLOAD, "Content-Length": str(10**12)})
    assert big.status_code == 413
    garbage = upload(client, "data.csv", b"\x00\x01\x02")
    assert garbage.status_code == 422 and garbage.json()["detail"].startswith("DNS telemetry could not be analyzed")


def test_cross_site_uploads_and_downloads_are_refused(client):
    for headers in ({**UPLOAD, "Origin": "https://evil.example"},
                    {**UPLOAD, "Sec-Fetch-Site": "cross-site"},
                    {**UPLOAD, "Content-Type": "multipart/form-data; boundary=x"},
                    {**UPLOAD, "Content-Type": "text/plain"}):
        assert upload(client, "dns.log", headers=headers).status_code == 403
    analysis = upload(client, "dns.log").json()["id"]
    assert client.get(f"/api/analyze/{analysis}/download/json", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/analyze/status", headers={"Host": "evil.example"}).status_code == 403
    # Only the content type of this one endpoint is relaxed.
    assert client.put("/api/review/marks", content=b"{}", headers=UPLOAD).status_code == 403


def test_nothing_is_written_and_a_new_upload_replaces_the_old(client, install):
    before = sorted(str(p) for p in install.rglob("*"))
    first = upload(client, "dns.log").json()["id"]
    second = upload(client, "conn.log").json()["id"]
    assert sorted(str(p) for p in install.rglob("*")) == before  # in memory only
    assert client.get(f"/api/analyze/{first}").status_code == 404
    assert client.get(f"/api/analyze/{second}").status_code == 200
    assert client.get("/api/analyze/" + "0" * 32).status_code == 404


def test_turkish_wording_and_status(client):
    status = client.get("/api/analyze/status", params={"lang": "tr"}).json()
    assert status["ready"] and status["notices"] == [] and status["analyze"] == "Analiz et"
    body = upload(client, "dns.log", lang="tr").json()
    assert body["priority"][0]["verdict_label"] == "Bilinen Tehdit"
    assert body["tabs"]["findings"] == "Domain bulguları"
