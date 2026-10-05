from __future__ import annotations

import gzip
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from streamlit.testing.v1 import AppTest

from scripts.lab.evaluate_dns_collector import FIELDS, NOW, cases, log
from threatfusion import telemetry_collector as module
from threatfusion.dns_zeek import parse_zeek_dns_log, parse_zeek_dns_transactions
from threatfusion.models import IOCRecord, IOCType
from threatfusion.ui_collector import read_snapshot


def test_experiment_path_guard_resolves_parent_traversal_and_links(tmp_path):
    from scripts.lab.evaluate_dns_collector import private_root
    from pathlib import Path

    repo = Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="outside"):
        private_root(repo.parent / "missing" / ".." / repo.name / "should-not-exist")
    link = tmp_path / "alias"
    try:
        link.symlink_to(repo, target_is_directory=True)
    except OSError:
        pytest.skip("Platform does not permit symlinks")
    with pytest.raises(ValueError):
        private_root(link / "should-not-exist")
    assert not (repo / "should-not-exist").exists()


@pytest.fixture
def paths(tmp_path):
    if os.name != "posix":
        pytest.skip("Linux collector contract")
    source = tmp_path / "input"
    source.mkdir()
    return source, tmp_path / "private"


@pytest.mark.parametrize("case", cases(20261051), ids=lambda case: case["name"])
def test_predeclared_dns_operational_controls(paths, case):
    source, state = paths
    content = log(case["rows"], closed=case.get("closed", True))
    (source / "dns.log").write_text(content)
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
        assert status["counts"]["analyzed_dns_events"] == case["events"]
        assert status["counts"]["dns_review_groups"] == case["reviews"]
        assert status["counts"]["rejected_files"] == case.get("rejected", 0)
        snapshot = read_snapshot(state)
        assert snapshot["dns"]["coverage"]["conflicting_transactions"] == case.get(
            "conflicts", 0
        )
        (source / "dns.copy.log.gz").write_bytes(gzip.compress(content.encode()))
        replay = collector.tick(now=NOW)
        assert replay["counts"]["new_records"] == 0
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 0
    assert (
        read_snapshot(state)["dns"]["report"]["findings"]
        == snapshot["dns"]["report"]["findings"]
    )
    exported = (state / "connections.json").read_text()
    for private_value in (
        "192.0.2.11",
        "192.0.2.53",
        "198.51.100.9",
        "C20261051",
        str(source),
        "source_row_hash",
        "transaction_id",
    ):
        assert private_value not in exported


@pytest.mark.parametrize(
    "field,value",
    [
        ("ts", "NaN"),
        ("ts", "-"),
        ("uid", "-"),
        ("uid", "x" * 257),
        ("id.orig_h", "bad"),
        ("id.resp_h", "bad"),
        ("id.orig_p", "0"),
        ("id.resp_p", "65536"),
        ("trans_id", "65536"),
        ("trans_id", "-1"),
        ("trans_id", "١"),
        ("proto", "icmp"),
        ("qtype_name", "-"),
        ("query", "-"),
    ],
)
def test_strict_collection_rejects_ambiguous_identity(field, value):
    row = list(cases(1)[0]["rows"][0])
    row[FIELDS.index(field)] = value
    with pytest.raises(ValueError):
        parse_zeek_dns_transactions(log([row]))


def test_upload_stays_permissive_while_collection_requires_transaction_identity():
    content = "#fields\tts\tquery\n1700000000\tnormal.test\n"
    assert parse_zeek_dns_log(content)[0].query_name == "normal.test"
    with pytest.raises(ValueError):
        parse_zeek_dns_transactions(content)


@pytest.mark.parametrize(
    "transform",
    [
        lambda text: text.replace("#path\tdns", "#path\tconn"),
        lambda text: text.replace("#fields\tts\tuid", "#fields\tts\tts"),
        lambda text: text.replace("\tNOERROR\t198.51.100.9", "\tNOERROR"),
    ],
)
def test_strict_collection_rejects_malformed_headers_and_rows(transform):
    with pytest.raises(ValueError):
        parse_zeek_dns_transactions(transform(log(cases(1)[0]["rows"][:1])))


def test_same_first_answer_but_changed_full_row_is_conflicting(paths):
    source, state = paths
    row = cases(7)[0]["rows"][0]
    second = list(row)
    row[-1] = "198.51.100.9,203.0.113.1"
    second[-1] = "198.51.100.9,203.0.113.2"
    (source / "dns.a.log").write_text(log([row]))
    (source / "dns.b.log").write_text(log([second]))
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
    assert status["counts"]["retained_dns_records"] == 2
    assert status["counts"]["analyzed_dns_events"] == 0
    assert read_snapshot(state)["dns"]["coverage"]["excluded_records"] == 2


def test_cti_reload_is_scoped_to_observed_client_and_answer(paths):
    source, state = paths
    row = list(cases(9)[0]["rows"][0])
    other = list(row)
    other[1], other[2], other[-1] = "Cother", "192.0.2.12", "203.0.113.9"
    (source / "dns.log").write_text(log([row, other]))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        assert all(
            not row["Known CTI sources"]
            for row in read_snapshot(state)["dns"]["report"]["findings"]
        )
        status = collector.tick(
            now=NOW,
            indicators=[IOCRecord("198.51.100.9", IOCType.IPV4, "Synthetic answer")],
        )
        rows = read_snapshot(state)["dns"]["report"]["findings"]
        assert status["counts"]["new_records"] == 0
        assert sum(bool(row["Known CTI sources"]) for row in rows) == 1
        collector.tick(
            now=NOW,
            indicators=[IOCRecord("updates.test", IOCType.DOMAIN, "Synthetic domain")],
        )
        assert all(
            row["Queue priority"] == "Investigate"
            for row in read_snapshot(state)["dns"]["report"]["findings"]
        )


def conn_log():
    fields = "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\tmissed_bytes"
    return f"#path\tconn\n#fields\t{fields}\n{int(NOW.timestamp()) - 4000}\tCconn\t192.0.2.1\t40000\t198.51.100.1\t443\ttcp\t4000\t100\t200\tSF\t0\n#close\tclosed\n"


def test_mixed_logs_preserve_original_connection_results(paths):
    source, state = paths
    (source / "conn.log").write_text(conn_log())
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        old = read_snapshot(state)
        (source / "dns.log").write_text(log(cases(5)[0]["rows"]))
        status = collector.tick(now=NOW)
        mixed = read_snapshot(state)
    assert status["counts"]["retained_records"] == 1
    assert status["counts"]["retained_dns_records"] == 20
    assert status["counts"]["retained_total_records"] == 21
    assert all(mixed[key] == old[key] for key in ("findings", "attempts", "timelines"))


def test_v1_state_upgrade_backs_up_and_preserves_evidence_and_checkpoints(paths):
    source, state = paths
    (source / "conn.log").write_text(conn_log())
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    with sqlite3.connect(state / "collector.sqlite") as db:
        db.executescript("""
            ALTER TABLE records RENAME TO new_records;
            CREATE TABLE records(hash TEXT PRIMARY KEY, timestamp REAL, ingested REAL NOT NULL, payload TEXT NOT NULL);
            INSERT INTO records SELECT hash,timestamp,ingested,payload FROM new_records;
            DROP TABLE new_records;
            PRAGMA user_version=1;
        """)
        original = db.execute("SELECT * FROM records").fetchall()
        checkpoints = db.execute("SELECT * FROM files").fetchall()
    (source / "dns.log").write_text(log(cases(5)[0]["rows"][:1]))
    with module.ZeekCollector(source, state) as collector:
        status = collector.tick(now=NOW)
        assert collector.db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert (
            collector.db.execute(
                "SELECT hash,timestamp,ingested,payload FROM records WHERE kind='conn'"
            ).fetchall()
            == original
        )
    assert status["counts"]["new_connection_records"] == 0
    assert status["counts"]["new_dns_records"] == 1
    (backup,) = state.glob("collector.schema1-*.sqlite")
    assert backup.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(backup) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT * FROM records").fetchall() == original
        assert db.execute("SELECT * FROM files").fetchall() == checkpoints


def test_crash_after_dns_checkpoint_rebuilds_snapshot(paths, monkeypatch):
    source, state = paths
    (source / "dns.log").write_text(log(cases(3)[0]["rows"][:2]))
    atomic = module._atomic
    monkeypatch.setattr(
        module, "_atomic", lambda *args: (_ for _ in ()).throw(OSError("write failure"))
    )
    with module.ZeekCollector(source, state) as collector:
        with pytest.raises(OSError):
            collector.tick(now=NOW)
    monkeypatch.setattr(module, "_atomic", atomic)
    with module.ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 0
    assert read_snapshot(state)["dns"]["coverage"]["analyzed_events"] == 2


def test_shared_capacity_and_dns_name_budget_are_explicit(paths, monkeypatch):
    source, state = paths
    rows = cases(2)[0]["rows"][:3]
    for i, row in enumerate(rows):
        row[8] = f"service{i}.test"
    (source / "dns.log").write_text(log(rows))
    (source / "conn.log").write_text(conn_log())
    monkeypatch.setattr(module, "MAX_DNS_NAMES", 2)
    with module.ZeekCollector(source, state, max_records=3) as collector:
        status = collector.tick(now=NOW)
        assert status["counts"]["retained_total_records"] <= 3
        assert status["capacity_coverage_loss"]
        assert len(read_snapshot(state)["dns"]["report"]["findings"]) == 2
        expired = collector.tick(now=NOW + timedelta(days=2))
        assert expired["counts"]["retained_total_records"] == 0
        assert expired["counts"]["new_records"] == 0


def test_dns_snapshot_cap_and_priority_order(paths):
    source, state = paths
    rows = []
    for i in range(1002):
        row = list(cases(i)[0]["rows"][0])
        row[8] = f"service{i}.test"
        rows.append(row)
    (source / "dns.log").write_text(log(rows))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(
            now=NOW,
            indicators=[IOCRecord("service1001.test", IOCType.DOMAIN, "Synthetic")],
        )
    block = read_snapshot(state)["dns"]
    assert block["total_findings"] == 1002 and block["omitted_findings"] == 2
    assert len(block["report"]["findings"]) == 1000
    assert block["report"]["findings"][0]["Queue priority"] == "Investigate"


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda p: p["dns"].update(policy="other"),
        lambda p: p["dns"].update(omitted_findings=1),
        lambda p: p["dns"]["coverage"].update(excluded_records=1),
        lambda p: p["dns"]["coverage"]["transports"].update(tcp=True),
        lambda p: p["dns"]["report"]["privacy"].update(client_ip_values_included=True),
        lambda p: p["dns"]["report"]["findings"][0].update(Device="192.0.2.11"),
        lambda p: p["dns"]["report"]["findings"][0].update(**{"Telemetry events": 21}),
        lambda p: p["dns"]["report"]["findings"][0].update(
            **{"First observed": "2026-01-01T12:00:00"}
        ),
        lambda p: p["collector"]["counts"].update(retained_total_records=True),
        lambda p: p.pop("dns"),
    ],
)
def test_corrupt_collector_dns_blocks_are_rejected(paths, corrupt):
    source, state = paths
    (source / "dns.log").write_text(log(cases(1)[0]["rows"]))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    payload = read_snapshot(state)
    corrupt(payload)
    (state / "connections.json").write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        read_snapshot(state)


def test_collector_dns_ui_bilingual_filters_and_public_boundary(paths):
    source, state = paths
    rows = cases(1)[0]["rows"]
    offset = int(datetime.now(timezone.utc).timestamp() - NOW.timestamp())
    for row in rows:
        row[0] += offset
    (source / "dns.log").write_text(log(rows))
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=datetime.now(timezone.utc))
    program = "from pathlib import Path\nfrom threatfusion.ui_collector import render_collector\n"
    app = AppTest.from_string(
        program + f"render_collector(Path({str(state)!r}), public_mode=False)\n"
    ).run(timeout=20)
    assert not app.exception
    assert app.dataframe[0].value.iloc[0]["Target"] == "updates.test"
    assert app.dataframe[0].value.iloc[0]["Device"] == "Device 001"
    app.session_state["language_selector"] = "🇹🇷 Türkçe"
    app.run(timeout=20)
    assert not app.exception
    assert any(
        metric.label == "Analiz edilen DNS işlemleri" and metric.value == "20"
        for metric in app.metric
    )
    assert app.dataframe[0].value.iloc[0]["Cihaz"] == "Cihaz 001"
    public = AppTest.from_string(
        program + f"render_collector(Path({str(state)!r}), public_mode=True)\n"
    ).run(timeout=20)
    assert not public.exception and not public.metric and not public.dataframe


def test_old_snapshot_without_dns_stays_readable(paths):
    source, state = paths
    with module.ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
    payload = read_snapshot(state)
    payload.pop("dns")
    payload["collector"]["policy"] = "closed-zeek-collector-v1"
    (state / "connections.json").write_text(json.dumps(payload))
    assert "dns" not in read_snapshot(state)
