from __future__ import annotations

from datetime import datetime, timezone

from streamlit.testing.v1 import AppTest

from threatfusion.ui_simple_review import build_review_items


def _dns(device, target, evidence, priority="Review", shared=""):
    return {"Device": device, "Target": target, "Queue priority": priority, "Evidence": evidence,
            "First observed": "2026-10-10T10:00:00+00:00", "Last observed": "2026-10-10T11:00:00+00:00",
            "Same addresses as": shared}


VIEW = {
    "findings": [
        {"Originator": "Host 001", "Responder": "Host 002", "Responder port": 5228, "Queue priority": "Review",
         "CTI match": False, "Declared expected": False, "DNS names": "push.example.test, alt.example.test",
         "Evidence": "Long bidirectional TCP session (at least 1 hour)",
         "First observed": "2026-10-10T10:00:00+00:00", "Last observed": "2026-10-10T10:00:00+00:00"},
        {"Originator": "Host 001", "Responder": "Host 003", "Responder port": 443, "Queue priority": "Observe",
         "CTI match": True, "Declared expected": False, "DNS names": "", "Evidence": ""},
        {"Originator": "Host 001", "Responder": "Host 004", "Responder port": 443, "Queue priority": "Review",
         "CTI match": False, "Declared expected": True, "DNS names": "", "Evidence": ""},
        {"Originator": "Host 001", "Responder": "Host 005", "Responder port": 443, "Queue priority": "Observe",
         "CTI match": False, "Declared expected": False, "DNS names": "popular.example.test",
         "Evidence": "Long bidirectional TCP session (at least 1 hour); All DNS names for this address are popular sites: context, not a verdict"},
    ],
    "dns": {"report": {"findings": [
        _dns("Device 001", "cdn.example.test", "High DNS query volume; Multiple response IPs observed"),
        _dns("Device 002", "cdn.example.test", "High DNS query volume", shared="origin.example.test"),
        _dns("Device 001", "listed.example.test", "Exact known-domain IOC match", priority="Investigate"),
        _dns("Device 001", "_googlecast._tcp.local", "High DNS query volume", priority="Observe"),
    ]}},
    "attempts": {"findings": [{"Queue priority": "Review", "Originator": "Host 001", "Responder": "Host 006",
                                "Distinct ports": 25, "Failed attempts": 40}]},
}


def test_items_are_grouped_ordered_and_plain():
    items = build_review_items(VIEW)
    titles = [item["title"] for item in items]
    assert titles == ["Host 003", "listed.example.test", "push.example.test", "cdn.example.test", "Host 006"]
    threat_conn, threat_dns, conn, dns, attempt = items
    assert threat_conn["threat"] and threat_conn["unnamed"] and threat_conn["advice"] == "threat"
    assert threat_dns["threat"] and threat_dns["what"] == ["This name is on a threat list."]
    assert conn["also"] == ["alt.example.test"] and conn["what"] == ["One connection stayed open for at least an hour."]
    assert dns["devices"] == ["Device 001", "Device 002"] and dns["also"] == ["origin.example.test"]
    assert dns["what"] == ["This name was looked up very often.", "It pointed to many different addresses."]
    assert attempt["kind"] == "attempt" and attempt["where"] == ("attempts", 25, 40)


def test_empty_snapshot_has_no_items():
    assert build_review_items({"findings": []}) == []


def test_review_tab_renders_in_both_languages(monkeypatch):
    from threatfusion import ui_collector

    snapshot = dict(VIEW, collector={"updated_at": datetime.now(timezone.utc).isoformat(), "cti_indicators": 1,
                                     "window_seconds": 86400,
                                     "counts": {"retained_records": 4, "review_groups": 2, "rejected_files": 0}})
    monkeypatch.setattr(ui_collector, "read_snapshot", lambda root: snapshot)
    script = ("from pathlib import Path\nfrom threatfusion.ui_simple_review import render_review_list\n"
              "from threatfusion import ui_collector\n"
              "render_review_list(ui_collector.read_snapshot(Path('/x')))\n")
    app = AppTest.from_string(script).run(timeout=15)
    assert not app.exception
    assert any(m.label == "To check" and m.value == "5" for m in app.metric)
    assert any("Long connection" in md.value for md in app.markdown)
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=15)
    assert not app.exception
    assert any("Uzun bağlantı" in md.value for md in app.markdown)


def test_semicolon_label_stays_one_sentence_and_sources_are_listed():
    view = {"findings": [], "dns": {"report": {"findings": [dict(
        _dns("Device 001", "x.example.test", "High DNS query volume; Sustained periodic DNS; inspect expected software activity"),
        **{"Known CTI sources": "ThreatFox, URLhaus"})]}}}
    (item,) = build_review_items(view)
    assert item["what"] == ["This name was looked up very often.", "It was looked up at very regular intervals."]
    assert item["sources"] == ["ThreatFox", "URLhaus"]


def test_short_labels_and_metrics():
    items = {item["title"]: item for item in build_review_items(VIEW)}
    assert items["push.example.test"]["label"] == "Long connection"
    assert items["cdn.example.test"]["label"] == "Frequent lookups"
    assert items["cdn.example.test"]["metric"] == ("{count} lookups", {"count": 0})
    assert items["Host 006"]["metric"][1] == {"ports": 25, "failed": 40}


def test_labels_persist_privately_and_older_hidden_items_count_as_known(tmp_path):
    from threatfusion.ui_simple_review import item_key, load_labels, save_hidden, save_label

    path, legacy = tmp_path / "review-labels.json", tmp_path / "review-hidden.json"
    assert load_labels(path) == {}
    items = build_review_items(VIEW)
    save_label(path, item_key(items[2]), "suspicious")
    save_label(path, item_key(items[3]), "unsure")
    save_label(path, item_key(items[3]), "bogus")  # unknown labels are ignored
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    save_hidden(legacy, {item_key(items[4])})
    labels = load_labels(path, legacy)
    assert {k: v["label"] for k, v in labels.items()} == {
        item_key(items[2]): "suspicious", item_key(items[3]): "unsure", item_key(items[4]): "known"}
    save_label(path, item_key(items[2]), None)
    assert item_key(items[2]) not in load_labels(path)
    path.write_text("not json")
    assert load_labels(path) == {}


_LIST_SCRIPT = (
    "import streamlit as st\nfrom pathlib import Path\n"
    "from threatfusion.ui_simple_review import render_review_list\n"
    "from tests.test_simple_review import VIEW\n"
    "@st.fragment\ndef page():\n    render_review_list(VIEW, labels_path=Path({path!r}))\npage()\n"
)


def test_one_click_labels_hide_known_pin_suspicious_and_keep_threats(tmp_path):
    from threatfusion.ui_simple_review import load_labels

    path = tmp_path / "review-labels.json"
    app = AppTest.from_string(_LIST_SCRIPT.format(path=str(path))).run(timeout=15)
    assert not app.exception
    metrics = lambda: {m.label: m.value for m in app.metric}  # noqa: E731
    assert metrics() == {"To check": "5", "Suspicious": "0", "On a threat list": "2", "Known": "0"}
    app.button(key="label-known-dns:cdn.example.test").click().run(timeout=15)
    app.button(key="label-suspicious-attempt:Host 006").click().run(timeout=15)
    app.button(key="label-known-dns:listed.example.test").click().run(timeout=15)  # a threat stays visible
    assert not app.exception
    assert metrics() == {"To check": "2", "Suspicious": "1", "On a threat list": "2", "Known": "1"}
    first = next(md.value for md in app.markdown if md.value.startswith(("🔴", "🟡")))
    assert "Host 006" in first and "Suspicious" in first  # suspicious is pinned on top
    assert {k: v["label"] for k, v in load_labels(path).items()} == {
        "dns:cdn.example.test": "known", "attempt:Host 006": "suspicious", "dns:listed.example.test": "known"}
    app.button(key="label-suspicious-attempt:Host 006").click().run(timeout=15)  # click again: unmark
    app.button(key="unhide-dns:cdn.example.test").click().run(timeout=15)
    assert metrics()["Suspicious"] == "0" and metrics()["Known"] == "0"
