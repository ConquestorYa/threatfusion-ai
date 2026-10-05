"""Declared preparation/coverage contracts; no detector threshold changes."""
import gzip
import json
import os
import shutil
import subprocess
import sys
from datetime import timedelta

import pytest
from streamlit.testing.v1 import AppTest

from scripts.lab.evaluate_dns_collector import NOW, cases, log
from scripts.lab.verify_log_preparation import expected_payloads
from tests.test_connections import log as conn_log, row as conn_row
from threatfusion import log_preparation as module
from threatfusion import telemetry_collector as collector_module
from threatfusion.expected_connections import parse_expected_connections
from threatfusion.ui_collector import read_snapshot

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private atomic Linux preparation/collector contract")


def connection_text(count=6):
    return conn_log(*(conn_row(uid=f"C{i}", ts=NOW.timestamp() - 7200 + i) for i in range(count))) + "#close\tfixture\n"


def test_bounded_shards_preserve_every_row_and_original_input(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "MAX_SHARD_ROWS", 2)
    source = tmp_path / "original.log"
    raw = connection_text().encode()
    source.write_bytes(raw)
    bundle = tmp_path / "bundle"
    result = module.prepare_file(source, bundle)
    assert result["source_rows"] == result["accepted_rows"] == 6 and result["shard_files"] == 3
    assert source.read_bytes() == raw
    data = module.read_bundle(bundle)
    assert data["source_sha256"] == module.hashlib.sha256(raw).hexdigest()
    assert sum(s["rows"] for s in data["shards"]) == 6
    with collector_module.ZeekCollector(bundle, tmp_path / "state") as collector:
        first = collector.tick(now=NOW)
        assert first["counts"]["retained_records"] == 6
        assert first["preparation"]["pending_files"] == 0 and not first["input_coverage_loss"]
    with collector_module.ZeekCollector(bundle, tmp_path / "state") as collector:
        assert collector.tick(now=NOW)["counts"]["new_records"] == 0
    assert bundle.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in bundle.iterdir())


def test_retention_oracle_preserves_sql_hash_tie_order():
    records = collector_module.parse_zeek_conn_log_with_diagnostics(conn_log(*(conn_row(uid=f"C{i}", ts=NOW.timestamp()) for i in range(4)))).connections
    all_rows = expected_payloads(records, (), 4)
    assert expected_payloads(records, (), 1) == [min(all_rows)]


@pytest.mark.parametrize("transform", [
    lambda raw: raw.replace(b"#close\tfixture\n", b""),
    lambda raw: raw + b"new data\n",
    lambda raw: raw.replace(b"\ttcp\t", b"\tinvalid_transportx\t"),
    lambda raw: raw + b"\xff",
])
def test_invalid_or_active_sources_never_publish_a_prefix(tmp_path, transform, monkeypatch):
    monkeypatch.setattr(module, "MAX_SHARD_ROWS", 1)
    source = tmp_path / "source.log"
    raw = transform(connection_text().encode())
    source.write_bytes(raw)
    with pytest.raises((ValueError, UnicodeError)):
        module.prepare_file(source, tmp_path / "bundle")
    assert source.read_bytes() == raw and not (tmp_path / "bundle").exists()
    assert not list(tmp_path.glob(module.STAGING + "*"))


@pytest.mark.parametrize("budget", ["MAX_SOURCE_BYTES", "MAX_SOURCE_ROWS", "MAX_LINE_BYTES", "MAX_SHARDS"])
def test_preparation_work_bounds_abort_without_publication(tmp_path, monkeypatch, budget):
    monkeypatch.setattr(module, budget, 1)
    source = tmp_path / "source.log"
    source.write_text(connection_text())
    if budget == "MAX_SHARDS":
        monkeypatch.setattr(module, "MAX_SHARD_ROWS", 1)
    with pytest.raises(ValueError):
        module.prepare_file(source, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_gzip_and_plain_sources_create_identical_shards_and_deduplicate(tmp_path):
    source = tmp_path / "source.log"
    raw = connection_text().encode()
    source.write_bytes(raw)
    compressed = tmp_path / "source.log.gz"
    compressed.write_bytes(gzip.compress(raw))
    root = tmp_path / "input"
    root.mkdir()
    for file, name in [(source, "plain"), (compressed, "gzip")]:
        module.prepare_file(file, root / name)
    assert module.read_bundle(root / "plain")["shards"] == module.read_bundle(root / "gzip")["shards"]
    with collector_module.ZeekCollector(root, tmp_path / "state") as collector:
        status = collector.tick(now=NOW)
    assert status["counts"]["retained_records"] == 6 and status["counts"]["duplicate_files"] == 1


def test_corrupt_gzip_cannot_publish_completed_prefix(tmp_path):
    source = tmp_path / "source.log.gz"
    source.write_bytes(gzip.compress(connection_text().encode())[:-3])
    with pytest.raises(EOFError):
        module.prepare_file(source, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_existing_destination_and_publication_race_never_replace_user_data(tmp_path, monkeypatch):
    source = tmp_path / "source.log"
    source.write_text(connection_text())
    destination = tmp_path / "bundle"
    original = module.publish
    def race(stage, output):
        output.mkdir()
        (output / "user.txt").write_text("preserve")
        original(stage, output)
    monkeypatch.setattr(module, "publish", race)
    with pytest.raises(OSError):
        module.prepare_file(source, destination)
    assert (destination / "user.txt").read_text() == "preserve"
    with pytest.raises(ValueError):
        module.prepare_file(source, destination)


def test_links_special_files_and_git_outputs_are_rejected(tmp_path):
    source = tmp_path / "source.log"
    source.write_text(connection_text())
    link = tmp_path / "link.log"
    link.symlink_to(source)
    fifo = tmp_path / "fifo.log"
    os.mkfifo(fifo)
    for input_file in (link, fifo):
        with pytest.raises((ValueError, OSError)):
            module.prepare_file(input_file, tmp_path / "bundle")
    repo = tmp_path / "checkout"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / ".git/HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git/objects").mkdir()
    with pytest.raises(ValueError, match="outside Git"):
        module.prepare_file(source, repo / "private")


def test_missing_dns_is_strict_by_default_and_explicitly_quarantined(tmp_path):
    rows = [list(r) for r in cases(7)[0]["rows"][:3]]
    rows[1][8] = "-"
    rows[2][9] = "-"
    source = tmp_path / "dns.log"
    source.write_text(log(rows))
    with pytest.raises(ValueError, match="quarantine"):
        module.prepare_file(source, tmp_path / "strict")
    result = module.prepare_file(source, tmp_path / "bundle", quarantine_incomplete_dns=True)
    assert (result["source_rows"], result["accepted_rows"], result["quarantined_rows"]) == (3, 1, 2)
    quarantine = [json.loads(line) for line in (tmp_path / "bundle/quarantine.jsonl").read_text().splitlines()]
    assert {q["reason"] for q in quarantine} == {"missing_query", "missing_query_type"}
    assert all(module.base64.b64decode(q["row_base64"]).endswith(b"\n") for q in quarantine)
    with collector_module.ZeekCollector(tmp_path / "bundle", tmp_path / "state") as collector:
        status = collector.tick(now=NOW)
    assert status["counts"]["analyzed_dns_events"] == 1
    assert status["input_coverage_loss"] and status["preparation"]["quarantined_rows"] == 2
    exported = (tmp_path / "state/connections.json").read_text()
    assert "row_base64" not in exported and "source_sha256" not in exported


def test_quarantine_does_not_bypass_other_invalid_dns_metadata(tmp_path):
    rows = [list(cases(7)[0]["rows"][0])]
    rows[0][8], rows[0][2] = "-", "invalid-ip"
    source = tmp_path / "dns.log"
    source.write_text(log(rows))
    with pytest.raises(ValueError):
        module.prepare_file(source, tmp_path / "bundle", quarantine_incomplete_dns=True)
    assert not (tmp_path / "bundle").exists()


def test_numeric_only_missing_query_type_can_be_explicitly_quarantined(tmp_path):
    rows = [list(cases(7)[0]["rows"][0])]
    rows[0][9] = "-"
    source = tmp_path / "dns.log"
    source.write_text(log(rows).replace("qtype_name", "qtype"))
    result = module.prepare_file(source, tmp_path / "bundle", quarantine_incomplete_dns=True)
    assert result["quarantine_reasons"]["missing_query_type"] == 1


def test_source_changed_after_validation_never_publishes(tmp_path, monkeypatch):
    source = tmp_path / "source.log"
    source.write_text(connection_text())
    original = module.parse_zeek_conn_log_with_diagnostics
    def change_source(content):
        result = original(content)
        source.write_text(connection_text(1))
        return result
    monkeypatch.setattr(module, "parse_zeek_conn_log_with_diagnostics", change_source)
    with pytest.raises(ValueError, match="Source changed"):
        module.prepare_file(source, tmp_path / "bundle")
    assert not (tmp_path / "bundle").exists()


def test_invalid_empty_header_cannot_become_a_prepared_bundle(tmp_path):
    source = tmp_path / "dns.log"
    source.write_text("#separator \\x09\n#path\tdns\n#fields\tts\tuid\n#close\tfixture\n")
    with pytest.raises(ValueError):
        module.prepare_file(source, tmp_path / "bundle")


def test_all_quarantined_bundle_stays_visible_without_any_shard(tmp_path):
    rows = [list(cases(7)[0]["rows"][0])]
    rows[0][8] = "-"
    source = tmp_path / "dns.log"
    source.write_text(log(rows))
    root = tmp_path / "input"
    root.mkdir()
    module.prepare_file(source, root / "bundle", quarantine_incomplete_dns=True)
    with collector_module.ZeekCollector(root, tmp_path / "state") as collector:
        status = collector.tick(now=NOW)
    assert status["counts"]["retained_dns_records"] == 0
    assert status["preparation"]["quarantined_rows"] == 1 and status["input_coverage_loss"]


@pytest.mark.parametrize("tamper", ["shard", "manifest", "quarantine", "missing_shard"])
def test_changed_prepared_evidence_cannot_be_silently_imported(tmp_path, tamper):
    source = tmp_path / "source.log"
    source.write_text(connection_text())
    bundle = tmp_path / "bundle"
    module.prepare_file(source, bundle)
    if tamper == "shard":
        p = bundle / "conn.prepared-000001.log"
        p.write_bytes(p.read_bytes().replace(b"198.51.100.1", b"198.51.100.2"))
    elif tamper == "manifest":
        data = json.loads((bundle / module.MANIFEST).read_text())
        data["source_rows"] += 1
        (bundle / module.MANIFEST).write_text(json.dumps(data))
    elif tamper == "quarantine":
        (bundle / "quarantine.jsonl").write_text("changed")
    else:
        (bundle / "conn.prepared-000001.log").unlink()
    with collector_module.ZeekCollector(bundle, tmp_path / "state") as collector:
        if tamper == "shard":
            status = collector.tick(now=NOW)
            assert status["counts"]["rejected_files"] == 1 and status["input_coverage_loss"]
        else:
            with pytest.raises(ValueError):
                collector.tick(now=NOW)
        assert collector.db.execute("SELECT count(*) FROM records").fetchone()[0] == 0


def test_prepared_capacity_and_quarantine_disable_expectations_with_original_reviews(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    source = tmp_path / "source.log"
    source.write_text(connection_text(6))
    module.prepare_file(source, root / "connections")
    rules = parse_expected_connections(json.dumps({"schema_version": 1, "rules": [{
        "id": "updater", "originator_ip": "192.0.2.1", "responder_ip": "198.51.100.1", "responder_port": 443,
        "protocol": "tcp", "valid_from": (NOW-timedelta(days=1)).isoformat(), "valid_until": (NOW+timedelta(days=1)).isoformat(),
        "max_connections": 10, "max_duration_seconds": 5000,
        "max_originator_bytes": 10000, "max_responder_bytes": 10000}]}))
    state = tmp_path / "state"
    with collector_module.ZeekCollector(root, state, max_records=2) as collector:
        status = collector.tick(now=NOW, rules=rules)
    assert status["preparation"]["source_rows"] == 6 and status["counts"]["retained_records"] == 2
    assert status["capacity_coverage_loss"] and not read_snapshot(state)["findings"][0]["Declared expected"]
    assert read_snapshot(state)["findings"][0]["Queue priority"] == "Review"


def test_staging_directory_is_never_a_collector_input(tmp_path):
    stage = tmp_path / (module.STAGING + "partial")
    stage.mkdir()
    (stage / "conn.log").write_text(connection_text())
    assert list(collector_module._candidates(tmp_path)) == []


def test_quarantine_alone_disables_expectations_and_survives_restart(tmp_path):
    root = tmp_path / "input"
    root.mkdir()
    source = tmp_path / "source.log"
    source.write_text(connection_text(1))
    module.prepare_file(source, root / "connections")
    rules = parse_expected_connections(json.dumps({"schema_version": 1, "rules": [{
        "id": "updater", "originator_ip": "192.0.2.1", "responder_ip": "198.51.100.1", "responder_port": 443,
        "protocol": "tcp", "valid_from": (NOW-timedelta(days=1)).isoformat(), "valid_until": (NOW+timedelta(days=1)).isoformat(),
        "max_connections": 10, "max_duration_seconds": 5000,
        "max_originator_bytes": 10000, "max_responder_bytes": 10000}]}))
    state = tmp_path / "state"
    with collector_module.ZeekCollector(root, state) as collector:
        assert not collector.tick(now=NOW, rules=rules)["input_coverage_loss"]
        assert read_snapshot(state)["findings"][0]["Declared expected"]
        rows = [list(cases(7)[0]["rows"][0])]
        rows[0][8] = "-"
        source.write_text(log(rows))
        module.prepare_file(source, root / "dns", quarantine_incomplete_dns=True)
        status = collector.tick(now=NOW, rules=rules)
        assert status["input_coverage_loss"] and not status["capacity_coverage_loss"]
        assert not read_snapshot(state)["findings"][0]["Declared expected"]
        shutil.rmtree(root / "dns")
    with collector_module.ZeekCollector(root, state) as collector:
        assert collector.tick(now=NOW+timedelta(seconds=1), rules=rules)["input_coverage_loss"]
        assert not read_snapshot(state)["findings"][0]["Declared expected"]


@pytest.mark.parametrize("language", ["en", "tr"])
def test_local_ui_shows_quarantine_counts_and_public_view_stays_empty(tmp_path, language):
    source = tmp_path / "dns.log"
    rows = [list(cases(7)[0]["rows"][0])]
    rows[0][8] = "-"
    source.write_text(log(rows))
    module.prepare_file(source, tmp_path / "bundle", quarantine_incomplete_dns=True)
    state = tmp_path / "state"
    with collector_module.ZeekCollector(tmp_path / "bundle", state) as collector:
        collector.tick(now=NOW)
    label = "🇹🇷 Türkçe" if language == "tr" else "🇬🇧 English"
    code = f'from pathlib import Path\nimport streamlit as st\nfrom threatfusion.ui_collector import render_collector\nst.session_state["language_selector"]={label!r}\nrender_collector(Path({str(state)!r}), public_mode=False)'
    app = AppTest.from_string(code).run()
    assert not app.exception
    captions = " ".join(element.value for element in app.caption)
    assert ("quarantined DNS rows: 1" if language == "en" else "karantinadaki DNS satırları: 1") in captions
    app = AppTest.from_string(code.replace("public_mode=False", "public_mode=True")).run()
    assert not app.exception and not app.caption and not app.warning and not app.metric


def test_cli_failure_never_echoes_private_input_content(tmp_path):
    source = tmp_path / "sensitive.log"
    source.write_text("sensitive.example API_KEY=fixture-secret")
    result = subprocess.run([sys.executable, "-m", "threatfusion.log_preparation", "--input", str(source),
                             "--output-dir", str(tmp_path / "bundle")], capture_output=True, text=True)
    assert result.returncode == 2 and "sensitive.example" not in result.stderr and "fixture-secret" not in result.stderr
