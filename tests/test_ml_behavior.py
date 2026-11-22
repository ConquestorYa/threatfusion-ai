from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier
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


def test_name_scores_take_the_strongest_group_per_name():
    from threatfusion.ui_behavior import name_scores
    model = mb.BehaviorModel({**_one_split_model({}), "threshold": 0.8})
    rows = [{"score": 0.9, "names": ["a.test"]}, {"score": 0.6, "names": ["a.test", "b.test"]}]
    assert name_scores((model, rows)) == {"a.test": (90, "High"), "b.test": (60, "Medium")}
    assert name_scores(None) == {}


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


def test_declared_tests_table_shows_each_result_limit_and_outcome():
    from threatfusion.ui_behavior import declared_test_rows
    tests = {"sme_family_recall": 0.5714, "mcfp_capture_recall": 0.55, "mta_recent_capture_recall": 0.17,
             "benign": {"mcfp_normal_eval": 0.33, "user_eval": 0.0},
             "synthetic": {"0.0": {"recall": 0.08}, "0.1": {"recall": 0.27}, "0.5": {"recall": 0.9}}}
    checks = {"T1_sme_family_recall": True, "T2_mcfp_capture_recall": True, "T3_mta_recent_capture_recall": False,
              "T4_benign_flags": True, "T5_synthetic_low_jitter": False}
    rows = declared_test_rows(tests, checks)
    assert [r["Result"] for r in rows] == ["%57", "%55", "%17", "0.33 / 0.0", "%8"]
    assert [r["Passed"] for r in rows] == ["✅", "✅", "❌", "✅", "❌"]
