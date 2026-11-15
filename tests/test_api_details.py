"""Details tab and timelines from the loopback API, compared with Streamlit."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from threatfusion.api.app import create_app
from threatfusion.api.settings import ApiSettings

ORIGIN = "http://127.0.0.1:8600"


@pytest.fixture(scope="module")
def state(tmp_path_factory):
    from scripts.demo_review_snapshot import main

    root = tmp_path_factory.mktemp("details") / "demo"
    assert main([str(root)]) == 0
    return root / "collector"


@pytest.fixture
def client(state):
    return TestClient(create_app(lambda: ApiSettings(True, state, None), environment={}), base_url=ORIGIN)


def test_details_mirror_the_streamlit_blocks(client, state):
    from threatfusion.ui_collector import read_snapshot

    payload = read_snapshot(state)
    body = client.get("/api/details").json()
    counts = payload["collector"]["counts"]
    assert body["state"] == "ok" and body["revision"] == payload["collector"]["selection_revision"]
    assert [m["value"] for m in body["metrics"]] == [counts["retained_records"], counts["review_groups"],
                                                      counts["rejected_files"], counts["attempt_review_groups"]]
    assert body["review_summary"]["metrics"][0] == {"label": "Original TCP reviews", "value": 2}
    connections = body["connections"]
    assert connections["total"] == 3  # two behavior reviews + one CTI group
    assert connections["columns"][:3] == ["Group", "Originator", "Responder"]
    assert {row[1] for row in connections["rows"]} <= {"192.0.2.10", "192.0.2.11"}  # local view: real IPs
    assert [g["group"] for g in connections["groups"]] == [row[0] for row in connections["rows"]]
    assert body["attempts"]["title"] == "TCP attempt reviews" and len(body["attempts"]["rows"]) == 1
    assert body["dns"]["investigation"]["domains"][0]["target"] == "updates.test"
    assert body["downloads"]["full"] is None
    assert body["downloads"]["snapshot"]["file"] == "threatfusion_collected_connections.json"


def test_filters_and_aliases(client):
    everything = client.get("/api/details", params={"reviews_only": False}).json()["connections"]
    assert everything["total"] >= 3
    aliases = client.get("/api/details", params={"local_ips": False, "lang": "tr"}).json()["connections"]
    assert all(row[1].startswith("Sistem ") for row in aliases["rows"])
    assert aliases["columns"][:3] == ["Grup", "Başlatan", "Yanıtlayan"]


def test_streamlit_parity_for_the_tables(state, monkeypatch):
    """Render the real Streamlit Details tab and compare its tables with the API."""
    from streamlit.testing.v1 import AppTest

    script = (
        "from pathlib import Path\n"
        "from threatfusion import ui_collector\n"
        f"state = Path({str(state)!r})\n"
        "payload = ui_collector.read_snapshot(state)\n"
        "status = payload['collector']\n"
        "ui_collector._render_details(state, payload, status, status['counts'],\n"
        "                             local_view=ui_collector._local_view(state, payload))\n"
    )
    app = AppTest.from_string(script).run(timeout=30)
    assert not app.exception
    frames = [frame.value for frame in app.dataframe]
    client = TestClient(create_app(lambda: ApiSettings(True, state, None), environment={}), base_url=ORIGIN)
    body = client.get("/api/details").json()
    # Order on the page: connections, timeline of the first group, attempts, DNS, DNS timeline.
    connections, timeline, attempts, dns = frames[0], frames[1], frames[2], frames[3]
    assert list(connections.columns) == body["connections"]["columns"]
    streamlit_rows = connections.astype(object).where(connections.notna(), None).values.tolist()
    assert [[str(v) for v in row] for row in streamlit_rows] == [[str(v) for v in row] for row in body["connections"]["rows"]]
    first_group = body["connections"]["groups"][0]["group"]
    ours = client.get("/api/details/connection-timeline", params={"group": first_group}).json()["table"]
    assert list(timeline.columns) == ours["columns"]
    assert timeline.astype(str).values.tolist() == [[str(v) for v in row] for row in ours["rows"]]
    assert list(attempts.columns) == body["attempts"]["columns"]
    # Streamlit adds the experimental ML column only when a local model exists.
    assert [c for c in dns.columns if c != "Behavior score (ML)"] == body["dns"]["columns"]


def test_connection_timeline_and_guidance(client, state):
    from threatfusion.ui_collector import read_snapshot

    payload = read_snapshot(state)
    cti_group = next(row["Group"] for row in payload["findings"] if row["CTI match"])
    body = client.get("/api/details/connection-timeline", params={"group": cti_group}).json()
    kinds = [block["kind"] for block in body["guidance"]]
    assert kinds[0] == "heading" and "warning" in kinds  # CTI takes precedence
    timeline = next(item for item in payload["timelines"]["groups"] if item["group"] == cti_group)
    assert [p["v"] for p in body["chart"]["points"]] == [b["connections"] for b in timeline["buckets"]]
    assert body["chart"]["kind"] == "line" and body["table"]["columns"][0] == "UTC bucket start"
    assert client.get("/api/details/connection-timeline", params={"group": 999}).status_code == 404


def test_dns_timeline(client):
    body = client.get("/api/details/dns-timeline", params={"group": 1, "lang": "tr"}).json()
    assert body["chart"]["kind"] == "bar" and body["guidance"][0]["text"].startswith("Seçilen sorgunun kanıtı")
    assert client.get("/api/details/dns-timeline", params={"group": 42}).status_code == 404


def test_downloads_match_streamlit_and_refuse_cross_site(client, state):
    from threatfusion.ui_collector import read_snapshot

    response = client.get("/api/details/download/snapshot")
    assert response.status_code == 200
    assert response.content == json.dumps(read_snapshot(state), indent=2).encode()  # aliases, not local IPs
    assert "attachment" in response.headers["content-disposition"]
    assert client.get("/api/details/download/full").status_code == 404  # not a bounded snapshot
    refused = client.get("/api/details/download/snapshot", headers={"Sec-Fetch-Site": "cross-site"})
    assert refused.status_code == 403
    assert client.get("/api/details/download/snapshot", headers={"Host": "evil.example"}).status_code == 403


def test_states_without_a_snapshot(tmp_path):
    off = TestClient(create_app(lambda: ApiSettings(False, None, None), environment={}), base_url=ORIGIN)
    assert off.get("/api/details").json() == {"state": "not_configured"}
    missing = TestClient(create_app(lambda: ApiSettings(True, tmp_path / "none", None), environment={}), base_url=ORIGIN)
    assert missing.get("/api/details").json()["state"] in {"no_snapshot", "unreadable"}
    assert missing.get("/api/details/connection-timeline", params={"group": 1}).status_code in {404, 409}
