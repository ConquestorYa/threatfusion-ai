"""Independent multi-day retention and private process/recovery controls."""
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
from pathlib import Path
from datetime import timedelta

import pytest

from scripts.lab.measure_multiday import RetentionOracle, Worker, candidate, log, parsed_payloads, reconcile, verify_freeze
from tests.test_telemetry_collector import NOW
from threatfusion.telemetry_collector import ZeekCollector


def test_oracle_retains_cutoff_ties_and_capacity_order_without_resurrection():
    oracle = RetentionOracle(window=10, limit=2)
    oracle.ingest({'c': (100, 100, 'conn', 'old'), 'b': (110, 110, 'conn', 'b'),
                   'a': (110, 110, 'dns', 'a')}, 110)
    assert oracle.expected() == [('a', 'dns', 'a'), ('b', 'conn', 'b')]
    oracle.prune(120)
    assert len(oracle.rows) == 2  # Exact ingestion cutoff remains eligible.
    oracle.prune(121)
    assert oracle.expected() == []
    oracle.ingest({'d': (99, 121, 'conn', 'late')}, 121)
    assert oracle.expected() == []  # Persistent event watermark cannot regress.


def test_oracle_mixed_early_duplicate_does_not_refresh_ingestion_lifetime():
    oracle = RetentionOracle(window=10)
    first = {'a': (100, 100, 'dns', 'unchanged')}
    oracle.ingest(first, 100)
    oracle.ingest({'a': (100, 109, 'dns', 'unchanged'), 'b': (105, 109, 'conn', 'new')}, 109)
    oracle.prune(111)
    assert oracle.expected() == [('b', 'conn', 'new')]


@pytest.mark.skipif(os.name != 'posix', reason='Private Linux multi-day collector')
def test_independent_oracle_reconciles_rotation_capacity_expiry_and_idle_restart(tmp_path):
    source, state = tmp_path / 'input', tmp_path / 'state'
    source.mkdir(mode=0o700)
    rows = [[NOW.timestamp()-100+i, f'C{i}', '192.0.2.1', 40000, f'198.51.100.{i+1}',
             443, 'tcp', 1.0, 100, 200, 'SF', 0] for i in range(3)]
    path = source / 'conn.000.log'
    path.write_text(log('conn', rows))
    oracle = RetentionOracle(limit=2)
    oracle.ingest(parsed_payloads(path, 'conn', NOW.timestamp()), NOW.timestamp())
    with ZeekCollector(source, state, max_records=2) as collector:
        status = collector.tick(now=NOW)
        assert status['counts']['trimmed_records'] == 1
    reconcile(tmp_path, oracle)
    with ZeekCollector(source, state, max_records=2) as collector:
        assert collector.tick(now=NOW)['counts']['new_records'] == 0
        expired = collector.tick(now=NOW+timedelta(days=2))
    oracle.prune((NOW+timedelta(days=2)).timestamp())
    reconcile(tmp_path, oracle)
    assert expired['counts']['retained_total_records'] == 0


@pytest.mark.skipif(os.name != 'posix', reason='Own Linux worker process contract')
def test_worker_reports_own_process_memory_and_recovers_after_own_sigkill(tmp_path):
    (tmp_path / 'input').mkdir(mode=0o700)
    child = Worker(tmp_path, 0)
    try:
        first = child.tick(NOW, False)
        assert first['worker_high_water_rss_bytes'] > 0
        assert child.rss and child.disk
        assert first['status']['counts']['retained_total_records'] == 0
    finally:
        child.close(kill=True)
    replacement = Worker(tmp_path, 1)
    try:
        repeated = replacement.tick(NOW, False)
        assert repeated['status']['counts']['new_records'] == 0
        assert repeated['status']['selection_revision'] == first['status']['selection_revision']
    finally:
        replacement.close()
    with sqlite3.connect(tmp_path / 'state/collector.sqlite') as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'


@pytest.mark.skipif(os.name != 'posix', reason='Protected Linux source contract')
@pytest.mark.parametrize('special', ['link', 'fifo'])
def test_private_special_source_never_reads_or_exports_unrelated_data(tmp_path, special):
    source = tmp_path / 'input'
    source.mkdir(mode=0o700)
    unrelated = tmp_path / 'private.txt'
    unrelated.write_text('PRIVATE never read or exported')
    path = source / 'conn.special.log'
    if special == 'link':
        path.symlink_to(unrelated)
    else:
        os.mkfifo(path, mode=0o600)
    with ZeekCollector(source, tmp_path / 'state') as collector:
        status = collector.tick(now=NOW)
    assert status['counts']['rejected_files'] == 1 and status['counts']['retained_total_records'] == 0
    assert unrelated.read_text() == 'PRIVATE never read or exported'
    assert 'PRIVATE' not in json.dumps(status)
    assert 'PRIVATE' not in (tmp_path / 'state/connections.json').read_text()


@pytest.mark.skipif(os.name != 'posix', reason='Linux worker process sampling')
def test_sampler_handles_atomic_disappearance_and_does_not_follow_links(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir()
    stage = state / 'stage'
    stage.write_bytes(b'synthetic')
    unrelated = tmp_path / 'unrelated'
    unrelated.write_bytes(b'x'*100)
    (state / 'link').symlink_to(unrelated)
    original = Path.lstat
    def vanished(self):
        if self == stage:
            self.unlink()
        return original(self)
    monkeypatch.setattr(Path, 'lstat', vanished)
    monitor = Worker.__new__(Worker)
    monitor.root = tmp_path
    monitor.child = type('OwnProbe', (), {'pid': os.getpid()})()
    monitor.rss, monitor.disk = [], []
    monitor.sample()
    assert monitor.rss and monitor.disk == [0]
    assert unrelated.read_bytes() == b'x'*100


@pytest.mark.parametrize('altered', ['plan', 'source', 'candidate'])
def test_final_freeze_rejects_changed_declaration_source_or_candidate(tmp_path, altered):
    (tmp_path / 'fixtures').mkdir()
    source = tmp_path / 'fixtures' / 'conn.log'
    source.write_text('synthetic')
    plan = tmp_path / 'plan.json'
    plan.write_text('{}\n')
    (tmp_path / 'plan.sha256').write_text(hashlib.sha256(plan.read_bytes()).hexdigest()+'\n')
    freeze = candidate(tmp_path)
    frozen = tmp_path / 'candidate-freeze.json'
    frozen.write_text(json.dumps(freeze))
    hashes = {'conn.log': hashlib.sha256(source.read_bytes()).hexdigest()}
    verify_freeze(tmp_path, hashes)
    if altered == 'plan':
        plan.write_text('{"changed":true}\n')
    elif altered == 'source':
        source.write_text('changed')
    else:
        freeze['runtime'] = {}
        frozen.write_text(json.dumps(freeze))
    with pytest.raises(ValueError, match='changed'):
        verify_freeze(tmp_path, hashes)
