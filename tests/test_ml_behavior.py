from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
from streamlit.testing.v1 import AppTest

from threatfusion import ml_behavior as mb
from threatfusion import telemetry_collector as collector_module

FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "missed_bytes")


def _connections(responder="1.1.1.1", count=30, step=60.0, port=443, protocol="tcp", start=1_000_000.0):
    return [mb.Connection(start + i * step, "10.0.0.2", responder, port, protocol, 0.4, 120, 300, "SF")
            for i in range(count)]


def test_groups_keep_internet_destinations_only():
    rows = (_connections() + _connections("224.0.0.251", port=5353, protocol="udp")
            + _connections("192.168.1.1", port=53, protocol="udp") + _connections("8.8.8.8", count=3))
    groups = mb.build_groups(rows, {"1.1.1.1": {"one.one.one.one"}}, lambda name: True)
    assert [(g.responder, g.connections) for g in groups] == [("1.1.1.1", 30)]
    features = groups[0].features
    assert set(features) == set(mb.FEATURES) | {"popular_name"}
    assert "popular_name" not in mb.FEATURES  # schema 1 learned it as a shortcut
    assert features["interval_regular_share"] == 1.0 and features["has_name"] == 1.0
    assert features["popular_name"] == 1.0 and features["port_web"] == 1.0
    assert features["name_entropy"] > 1.5 and features["name_digit_share"] == 0.0


def test_dns_resolver_traffic_is_out_of_scope():
    rows = _connections("8.8.8.8", port=53, protocol="udp") + _connections("9.9.9.9", port=853)
    assert mb.build_groups(rows, {}, lambda name: False) == []


def test_random_looking_names_score_higher_than_words():
    plain, = mb.name_randomness(["www.example.com"])[:1]
    random_, digits = mb.name_randomness(["www.example.com", "x7k2q9vz4m1p.top"])
    assert random_ > plain and digits > 0.3
    assert mb.name_randomness([]) == (0.0, 0.0)


def test_groups_split_into_two_windows_from_the_newest_connection():
    day = mb.WINDOW_SECONDS
    rows = _connections(start=0.0) + _connections(start=1.5 * day) + _connections(start=3 * day)
    groups = mb.build_groups(rows, {}, lambda name: False)
    end = 3 * day + 29 * 60
    assert len(groups) == 2  # the oldest batch falls outside the two windows
    assert {g.window_end for g in groups} == {end, end - day}


def test_reasons_describe_regular_unnamed_beacons():
    beacon, = mb.build_groups(_connections(port=8081), {}, lambda name: False)
    assert {"regular", "same_size", "no_name", "unusual_port", "small"} <= set(mb.reasons(beacon.features))


def _one_split_model(evaluation):
    """Regular timing scores 0.9, anything else 0.1."""
    split = mb.FEATURES.index("interval_regular_share")
    tree = {"left": [1, -1, -1], "right": [2, -1, -1], "feature": [split, 0, 0],
            "threshold": [0.5, 0.0, 0.0], "value": [0.5, 0.1, 0.9]}
    return {"kind": mb.MODEL_KIND, "schema_version": mb.SCHEMA_VERSION, "features": list(mb.FEATURES),
            "model_id": "test-model", "trained_at": "2026-10-14T00:00:00Z", "threshold": 0.5,
            "evaluation": evaluation, "trees": [tree]}


def _forest():
    rng = np.random.default_rng(1)
    X = rng.random((300, len(mb.FEATURES)))
    y = (X[:, mb.FEATURES.index("interval_regular_share")] > 0.5).astype(int)
    return RandomForestClassifier(n_estimators=15, min_samples_leaf=2, random_state=1).fit(X, y), X


def test_json_forest_scores_like_scikit_learn():
    forest, X = _forest()
    model = mb.BehaviorModel(mb.forest_payload(forest, 0.5, model_id="m", trained_at="t", evaluation={}))
    expected = forest.predict_proba(X)[:, 1]
    assert max(abs(model.score(dict(zip(mb.FEATURES, row))) - p) for row, p in zip(X, expected)) < 1e-5


def test_foreign_or_malformed_models_are_rejected(tmp_path):
    forest, _ = _forest()
    payload = mb.forest_payload(forest, 0.5, model_id="m", trained_at="t", evaluation={})
    for broken in ({**payload, "kind": "pickle"}, {**payload, "features": ["a"]},
                   {**payload, "trees": [{**payload["trees"][0], "left": [0]}]}):
        with pytest.raises(ValueError):
            mb.BehaviorModel(broken)
    big = tmp_path / "model.json"
    big.write_bytes(b" " * (mb.MAX_MODEL_BYTES + 1))
    with pytest.raises(ValueError):
        mb.BehaviorModel.load(big)


@pytest.mark.skipif(os.name != "posix", reason="Linux collector contract")
def test_experimental_tab_shows_flagged_groups_and_saves_marks(tmp_path):
    source, state = tmp_path / "source", tmp_path / "collector"
    source.mkdir()
    now = datetime.now(timezone.utc)
    base = int(now.timestamp()) - 9000
    rows = [[base + i * 300, f"C{i}", "192.0.2.1", 40000 + i, "1.1.1.1", 8081, "tcp", 0.3, 90, 40, "SF", 0]
            for i in range(25)]
    rows += [[base + offset, f"D{i}", "192.0.2.1", 41000 + i, "8.8.8.8", 443, "tcp", i * 3.1, 900 + i * 37,
              50000 + i * 911, "SF", 0] for i, offset in enumerate((0, 40, 900, 1000, 4000, 7000))]
    (source / "conn.log").write_text("#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n"
                                     + "".join("\t".join(map(str, row)) + "\n" for row in rows)
                                     + "#close\t2026-10-14-00-00-00\n")
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=now)
    (tmp_path / "ml").mkdir()
    payload = _one_split_model({"grade": "development: test", "eval": {"malware_capture_recall": 0.6,
                                                                      "normal_flagged_per_unit_day": 0.4}})
    (tmp_path / "ml" / "behavior-model.json").write_text(json.dumps(payload))
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_behavior import render_behavior_tab\n"
        f"render_behavior_tab(Path({str(state)!r}))\n"
    ).run(timeout=20)
    assert not app.exception
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Stands out"] == "1" and metrics["Destinations checked"] == "2"
    assert metrics["Caught in testing"] == "%60"
    assert any("1.1.1.1" in m.value for m in app.markdown)
    app.button(key="ml-suspicious-ml:1.1.1.1:8081").click().run(timeout=20)
    labels = json.loads((tmp_path / "review-labels.json").read_text())["labels"]
    assert labels["ml:1.1.1.1:8081"]["label"] == "suspicious"
    app.button(key="ml-known-ml:1.1.1.1:8081").click().run(timeout=20)
    assert not app.exception
    assert {m.label: m.value for m in app.metric}["Stands out"] == "0"


def test_tab_explains_when_no_model_exists(tmp_path):
    (tmp_path / "collector").mkdir()
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_behavior import render_behavior_tab\n"
        f"render_behavior_tab(Path({str(tmp_path / 'collector')!r}))\n"
    ).run(timeout=15)
    assert not app.exception and any("No behavior model" in c.value for c in app.caption)
    assert any("New for this computer" in m.value for m in app.markdown)


def test_model_evaluation_page_reports_the_measured_results(tmp_path):
    (tmp_path / "ml").mkdir()
    evaluation = {"grade": "development: test", "pass": True, "checks": {"E1": True},
                  "eval": {"malware_capture_recall": 0.62, "malware_group_recall": 0.41, "malware_captures": 50,
                           "normal_unit_days": 30, "normal_flagged_per_unit_day": 0.5},
                  "dev": {"malware_capture_recall": 0.7, "malware_captures": 30},
                  "importance": [["interval_regular_share", 0.3], ["has_name", 0.2]]}
    (tmp_path / "ml" / "behavior-model.json").write_text(json.dumps(_one_split_model(evaluation)))
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_behavior import render_behavior_evaluation\n"
        f"render_behavior_evaluation(Path({str(tmp_path)!r}))\n"
    ).run(timeout=15)
    assert not app.exception
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Caught in testing"] == "%62" and metrics["Score line"] == "50"
    assert app.success and app.dataframe[0].value.iloc[0]["Caught"] == "%62"


def _collector_with_beacon(tmp_path):
    source, state = tmp_path / "source", tmp_path / "collector"
    source.mkdir()
    now = datetime.now(timezone.utc)
    base = int(now.timestamp()) - 9000
    rows = [[base + i * 300, f"C{i}", "192.0.2.1", 40000 + i, "1.1.1.1", 8081, "tcp", 0.3, 90, 40, "SF", 0]
            for i in range(25)]
    (source / "conn.log").write_text("#separator \\x09\n#path\tconn\n#fields\t" + "\t".join(FIELDS) + "\n"
                                     + "".join("\t".join(map(str, row)) + "\n" for row in rows)
                                     + "#close\t2026-10-14-00-00-00\n")
    with collector_module.ZeekCollector(source, state) as collector:
        collector.tick(now=now)
    (tmp_path / "ml").mkdir()
    (tmp_path / "ml" / "behavior-model.json").write_text(json.dumps(_one_split_model({})))
    return state


def test_levels_follow_the_model_line():
    from threatfusion.ui_behavior import level
    assert level(0.95, 0.9) == "High" and level(0.7, 0.9) == "Medium" and level(0.2, 0.9) == "Low"


def test_quick_lookup_shows_behavior_for_a_destination_this_computer_talked_to(tmp_path):
    state = _collector_with_beacon(tmp_path)
    script = ("from pathlib import Path\nfrom threatfusion.ui_behavior import render_lookup_behavior\n"
              f"render_lookup_behavior(None, {{address!r}}, Path({str(state)!r}))\n")
    seen = AppTest.from_string(script.format(address="1.1.1.1")).run(timeout=20)
    assert not seen.exception
    assert {m.label: m.value for m in seen.metric}["Behavior score"] == "90/100"
    unseen = AppTest.from_string(script.format(address="9.9.9.9")).run(timeout=20)
    assert not unseen.exception and not unseen.metric
    assert any("did not talk to it often enough" in c.value for c in unseen.caption)
    no_model = AppTest.from_string(
        "from threatfusion.ui_behavior import render_lookup_behavior\nrender_lookup_behavior('a.test', None, None)\n"
    ).run(timeout=15)
    assert not no_model.exception and not no_model.markdown


def test_name_scores_take_the_strongest_group_per_name():
    from threatfusion.ui_behavior import name_scores
    model = mb.BehaviorModel({**_one_split_model({}), "threshold": 0.8})
    rows = [{"score": 0.9, "names": ["a.test"]}, {"score": 0.6, "names": ["a.test", "b.test"]}]
    assert name_scores((model, rows)) == {"a.test": (90, "High"), "b.test": (60, "Medium")}
    assert name_scores(None) == {}


def test_new_destination_with_a_steady_rhythm_is_listed_after_learning(tmp_path):
    from threatfusion.baseline import Baseline
    state = _collector_with_beacon(tmp_path)
    (tmp_path / "ml" / "behavior-model.json").unlink()
    today = int(datetime.now(timezone.utc).timestamp() // 86400)
    history = Baseline()
    history.update([mb.Connection((today - d) * 86400 + 100, "192.0.2.1", "8.8.4.4", 443, "tcp", 0.1, 1, 1, "SF")
                    for d in (3, 4, 5)], {})
    history.save(tmp_path / "ml" / "baseline.json")
    script = ("from pathlib import Path\nfrom threatfusion.ui_behavior import render_behavior_tab\n"
              f"render_behavior_tab(Path({str(state)!r}))\n")
    app = AppTest.from_string(script).run(timeout=20)
    assert not app.exception
    assert any("1.1.1.1" in m.value for m in app.markdown)
    assert {m.label: m.value for m in app.metric}["Rhythm"].endswith("/100")
    app.button(key="new-known-new:1.1.1.1:8081").click().run(timeout=20)
    assert not app.exception and not any(m.value.startswith("#### 1.1.1.1") for m in app.markdown)
    # The memory now includes the beacon, so it stays known on later days.
    assert "ip:1.1.1.1" in Baseline.load(tmp_path / "ml" / "baseline.json").devices["192.0.2.1"]["seen"]


def test_new_destinations_wait_for_three_days_of_history(tmp_path):
    state = _collector_with_beacon(tmp_path)
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_new_destinations import render_new_destinations\n"
        f"render_new_destinations(Path({str(state)!r}))\n").run(timeout=20)
    assert not app.exception and "Learning what is normal" in app.info[0].value


def test_learning_is_shown_even_when_a_device_has_no_rhythm_groups(tmp_path):
    from threatfusion.baseline import Baseline
    state = _collector_with_beacon(tmp_path)
    today = int(datetime.now(timezone.utc).timestamp() // 86400)
    history = Baseline()
    history.update([mb.Connection((today - d) * 86400 + 100, "192.0.2.1", "1.1.1.1", 8081, "tcp", 0.1, 1, 1, "SF")
                    for d in (3, 4, 5)], {})
    history.save(tmp_path / "ml" / "baseline.json")
    app = AppTest.from_string(
        "from pathlib import Path\nfrom threatfusion.ui_new_destinations import render_new_destinations\n"
        f"render_new_destinations(Path({str(state)!r}))\n").run(timeout=20)
    # The only device has history and its beacon is known: nothing new, no learning notice.
    assert not app.exception and not app.info and app.success


def test_marks_apply_to_the_whole_site_and_addresses_of_one_site_share_a_card(tmp_path):
    from threatfusion.ui_new_destinations import group_by_site, marked_sites
    from threatfusion.baseline import simple_registrable
    rows = [{"device": "d", "address": a, "port": 443, "domain": "cdn.test" if a != "9.9.9.9" else None, "score": s}
            for a, s in (("1.1.1.1", 0.9), ("2.2.2.2", 0.95), ("9.9.9.9", 0.85))]
    cards = group_by_site(rows)
    assert [(c["address"], c["others"]) for c in cards] == [("2.2.2.2", ["1.1.1.1:443"]), ("9.9.9.9", [])]
    labels = {"connection:api.cdn.test": {"label": "known"}, "new:evil.example:8080": {"label": "suspicious"},
              "dns:8.8.8.8": {"label": "known"}, "ml:1.2.3.4:443": {"label": "suspicious"}}
    assert marked_sites(labels, simple_registrable) == ({"cdn.test"}, {"evil.example"})


def test_a_site_marked_known_on_another_list_hides_its_new_entry(tmp_path):
    from threatfusion.baseline import Baseline
    from threatfusion.ui_simple_review import save_label
    state = _collector_with_beacon(tmp_path)
    today = int(datetime.now(timezone.utc).timestamp() // 86400)
    history = Baseline()
    history.update([mb.Connection((today - d) * 86400 + 100, "192.0.2.1", "8.8.4.4", 443, "tcp", 0.1, 1, 1, "SF")
                    for d in (3, 4, 5)], {})
    history.save(tmp_path / "ml" / "baseline.json")
    save_label(tmp_path / "review-labels.json", "connection:1.1.1.1", "known")  # an IP title: not a site
    script = ("from pathlib import Path\nfrom threatfusion.ui_new_destinations import render_new_destinations\n"
              f"render_new_destinations(Path({str(state)!r}))\n")
    app = AppTest.from_string(script).run(timeout=20)
    assert not app.exception and any(m.value.startswith("#### 1.1.1.1") for m in app.markdown)
