"""Real SQLite page exhaustion in owned synthetic state, never host disk fill."""
from __future__ import annotations

import gzip
import ipaddress
import json
import os
import sqlite3

import pytest

from scripts.lab.measure_multiday import log
from tests.test_telemetry_collector import NOW
from threatfusion.collector_reports import read_archive
from threatfusion.telemetry_collector import ZeekCollector
from threatfusion.ui_collector import read_snapshot

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Private Linux SQLite budget contract')


@pytest.mark.parametrize('initial', [3, 1001])
def test_actual_sqlite_full_rolls_back_file_and_preserves_previous_export_then_recovers(tmp_path, initial):
    source, state = tmp_path / 'input', tmp_path / 'state'
    source.mkdir(mode=0o700)
    base = int(ipaddress.IPv6Address('2001:db8::1'))
    def records(start, count):
        return [[NOW.timestamp()-100+i/10000, f'Cspace-{i}', '192.0.2.1', 40000,
                 str(ipaddress.IPv6Address(base+i)), 443, 'tcp', 1.0, 100, 200, 'SF', 0]
                for i in range(start, start+count)]
    (source / 'conn.initial.log').write_text(log('conn', records(0, initial)))
    with ZeekCollector(source, state) as collector:
        collector.tick(now=NOW)
        before = (state / 'connections.json').read_bytes()
        snapshot = read_snapshot(state)
        reference = snapshot.get('full_report')
        archive = read_archive(state, reference) if reference else None
        (source / 'conn.new.log').write_text(log('conn', records(initial, 1200)))
        pages = collector.db.execute('PRAGMA page_count').fetchone()[0]
        assert collector.db.execute(f'PRAGMA max_page_count={pages}').fetchone()[0] == pages
        with pytest.raises(sqlite3.OperationalError) as stopped:
            collector.tick(now=NOW)
        assert stopped.value.sqlite_errorcode == sqlite3.SQLITE_FULL
        assert collector.db.execute('SELECT count(*) FROM records').fetchone()[0] == initial
        assert collector.db.execute('SELECT count(*) FROM files').fetchone()[0] == 1
        assert not collector.db.execute("SELECT 1 FROM paths WHERE path='conn.new.log'").fetchone()
        assert collector.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert (state / 'connections.json').read_bytes() == before
        if reference:
            assert read_archive(state, reference) == archive
        collector.db.execute('PRAGMA max_page_count=1000000')
        repaired = collector.tick(now=NOW)
        assert repaired['counts']['new_records'] == 1200
        assert repaired['counts']['retained_records'] == initial+1200
        assert repaired['counts']['rejected_files'] == 0
    with ZeekCollector(source, state) as collector:
        assert collector.tick(now=NOW)['counts']['new_records'] == 0
        assert collector.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    snapshot = read_snapshot(state)
    full = json.loads(gzip.decompress(read_archive(state, snapshot['full_report'])))
    assert len(full['findings']) == initial+1200
    assert full['privacy']['endpoint_ips_included'] is False
    assert 'Cspace-' not in json.dumps(full)
