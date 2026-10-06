"""Private accelerated multi-day collection, independent retention and worker RSS.

Requires a separately frozen multiday-collector-v1 plan outside Git. Generates
reserved-address/.test fixtures only; no packets, acquisition or ML tuning.
72 event hours do not constitute a 72-hour wall-clock soak.
"""
from __future__ import annotations

import argparse
import gc
import gzip
import hashlib
import ipaddress
import json
import os
import selectors
import shutil
import signal
import stat
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new

REPO = Path(__file__).resolve().parents[2]
CONN_FIELDS = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes resp_bytes conn_state missed_bytes'.split()
DNS_FIELDS = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id query qtype_name rcode_name answers'.split()
KEYS = ('findings', 'timelines', 'attempts', 'dns')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprints():
    return {'runtime': {str(p.relative_to(REPO)): sha(p) for p in sorted((REPO / 'src/threatfusion').glob('*.py'))},
            'method': sha(Path(__file__)), 'tests': sha(REPO / 'tests/test_multiday_collector.py')}


def candidate(root):
    return fingerprints() | {'plan_sha256': sha(root / 'plan.json')}


def verify_freeze(root, hashes):
    if (candidate(root) != json.loads((root / 'candidate-freeze.json').read_text())
        or sha(root / 'plan.json') != (root / 'plan.sha256').read_text().strip()
        or any(sha(root / 'fixtures' / p) != h for p, h in hashes.items())):
        raise ValueError('Declaration, candidate, method or immutable sources changed')


def load_plan(root):
    if sha(root / 'plan.json') != (root / 'plan.sha256').read_text().strip():
        raise ValueError('Multi-day declaration changed')
    plan = json.loads((root / 'plan.json').read_text())
    if (plan['protocol'] != 'multiday-collector-v1' or plan['permitted_runtime_changes'] != []
        or plan['baseline_runtime'] != fingerprints()['runtime'] or plan['hours'] != 72
        or plan['connections_per_hour'] != 3200 or plan['dns_per_hour'] != 1800
        or plan['record_limit'] != 100000 or plan['window_seconds'] != 86400
        or plan['kill_after_hours'] != [24, 48] or plan['cti_change_hour'] != 36):
        raise ValueError('Multi-day scope differs from the frozen declaration')
    return plan


def log(kind, rows, closed=True):
    fields = CONN_FIELDS if kind == 'conn' else DNS_FIELDS
    return '#separator \\x09\n#path\t' + kind + '\n#fields\t' + '\t'.join(fields) + '\n' + ''.join(
        '\t'.join(map(str, row)) + '\n' for row in rows) + ('#close\tcontrolled\n' if closed else '')


def fixture_rows(plan, hour, kind):
    base = datetime.fromisoformat(plan['event_start']) + timedelta(hours=hour)
    count = plan['connections_per_hour'] if kind == 'conn' else plan['dns_per_hour']
    address = int(ipaddress.IPv6Address('2001:db8::1'))
    rows = []
    for index in range(count):
        timestamp = base + timedelta(seconds=index * 1600 / count)
        common = [timestamp.timestamp(), f'Cmulti-{kind}-{hour}-{index}', f'192.0.2.{1+index%12}', 40000+index]
        if kind == 'conn':
            # Repeated endpoints plus a rotating destination set exercise both
            # grouped evidence and a partial connection snapshot.
            target = '198.51.100.77' if index == 0 else str(ipaddress.IPv6Address(address + (hour % 24)*3200 + index))
            rows.append(common + [target, 443, 'tcp', 1.0, 100, 200, 'SF', 0])
        else:
            name = 'monitor.test' if index == 0 else f'update{index%120}.test'
            rows.append(common + ['192.0.2.53', 53, 'tcp' if index%2 else 'udp', index, name, 'A', 'NOERROR', '198.51.100.9'])
    return rows


def prepare(root, plan):
    fixtures = private_root(root / 'fixtures')
    hashes = {}
    for hour in range(plan['hours']):
        for kind in ('conn', 'dns'):
            path = fixtures / f'{kind}.{hour:03d}.log'
            path.write_text(log(kind, fixture_rows(plan, hour, kind)))
            path.chmod(0o600)
            hashes[path.name] = sha(path)
    write_new(root / 'source-freeze.json', {'files': hashes, 'total_rows': plan['hours'] * 5000})
    write_new(root / 'candidate-freeze.json', candidate(root))
    return hashes


def parsed_payloads(path, kind, ingested):
    """Share production parsing, independently model retention/hash/order policy."""
    from dataclasses import asdict
    from threatfusion.dns_collection import transaction_payload
    from threatfusion.dns_zeek import parse_zeek_dns_transactions
    from threatfusion.network_telemetry import parse_zeek_conn_log_with_diagnostics

    records = parse_zeek_dns_transactions(path.read_text()) if kind == 'dns' else parse_zeek_conn_log_with_diagnostics(path.read_text()).connections
    result = {}
    for record in records:
        if kind == 'dns':
            payload, timestamp = transaction_payload(record), record.event.timestamp
        else:
            values = asdict(record)
            timestamp = record.timestamp
            values['timestamp'] = timestamp.isoformat()
            payload = json.dumps(values, sort_keys=True, separators=(',', ':'))
        result[hashlib.sha256(payload.encode()).hexdigest()] = (timestamp.timestamp(), ingested, kind, payload)
    return result


class RetentionOracle:
    """Independent event/ingestion cutoff and stable capacity tie ordering."""
    def __init__(self, window=86400, limit=100000):
        self.window, self.limit = window, limit
        self.rows = {}
        self.watermark = float('-inf')

    def prune(self, epoch):
        self.watermark = max(self.watermark, max((row[0] for row in self.rows.values()), default=float('-inf')))
        eligible = [(key, row) for key, row in self.rows.items()
                    if row[0] >= self.watermark-self.window and row[1] >= epoch-self.window]
        ordered = sorted(eligible, key=lambda item: (-item[1][0], item[0]))
        self.rows = dict(ordered[:self.limit])

    def ingest(self, payloads, epoch):
        for key, row in payloads.items():
            self.rows.setdefault(key, row)
        self.prune(epoch)

    def expected(self):
        return sorted((key, row[2], row[3]) for key, row in self.rows.items())


def indicators(changed):
    from threatfusion.models import IOCRecord, IOCType
    return (IOCRecord('2001:db8::2' if changed else '198.51.100.77', IOCType.IPV6 if changed else IOCType.IPV4, 'Synthetic'),
            IOCRecord('monitor.test', IOCType.DOMAIN, 'Synthetic'))


def worker(root):
    import resource
    from threatfusion.telemetry_collector import ZeekCollector

    with ZeekCollector(root / 'input', root / 'state') as collector:
        print(json.dumps({'ready': os.getpid()}), flush=True)
        for line in sys.stdin:
            command = json.loads(line)
            if command['action'] == 'stop':
                break
            if command['action'] != 'tick':
                raise ValueError('Unsupported private worker command')
            started = time.perf_counter()
            status = collector.tick(now=datetime.fromisoformat(command['now']), indicators=indicators(command['changed']))
            print(json.dumps({'status': status, 'wall_seconds': time.perf_counter()-started,
                              'worker_high_water_rss_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024}), flush=True)


class Worker:
    def __init__(self, root, segment):
        self.root = root
        self.stderr = (root / f'worker-{segment}.stderr').open('xb')
        self.child = subprocess.Popen([sys.executable, '-m', 'scripts.lab.measure_multiday', '--root', str(root), '--worker'],
                                      cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.child.stdout, selectors.EVENT_READ)
        self.rss, self.disk = [], []
        try:
            if self.read(timeout=60) != {'ready': self.child.pid}:
                raise ValueError('Unexpected private worker handshake')
        except BaseException:
            if self.child.poll() is None:
                self.child.kill()
                self.child.wait(timeout=10)
            self.close()
            raise

    def sample(self):
        try:
            for line in Path(f'/proc/{self.child.pid}/status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    self.rss.append(int(line.split()[1])*1024)
        except (FileNotFoundError, ProcessLookupError):
            pass
        state = self.root / 'state'
        size = 0
        if state.exists():
            for path in state.iterdir():
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue  # Atomic rename/removal between inventory and stat.
                if stat.S_ISREG(info.st_mode):
                    size += info.st_size
        self.disk.append(size)

    def read(self, timeout):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            self.sample()
            if self.selector.select(timeout=0.05):
                line = self.child.stdout.readline()
                if not line:
                    raise ValueError('Collector worker exited; inspect private stderr')
                return json.loads(line)
        raise TimeoutError('Declared collector worker response deadline exceeded')

    def tick(self, now, changed):
        self.child.stdin.write(json.dumps({'action': 'tick', 'now': now.isoformat(), 'changed': changed})+'\n')
        self.child.stdin.flush()
        return self.read(timeout=120)

    def close(self, kill=False):
        try:
            if self.child.poll() is None:
                if kill:
                    self.child.kill()  # Only this explicitly spawned own child.
                else:
                    self.child.stdin.write('{"action":"stop"}\n')
                    self.child.stdin.flush()
                self.child.wait(timeout=10)
            if kill and self.child.returncode != -signal.SIGKILL:
                raise ValueError('Declared own-worker interruption failed')
        finally:
            if self.child.poll() is None:
                self.child.kill()
                self.child.wait(timeout=10)
            self.selector.close()
            self.child.stdin.close()
            self.child.stdout.close()
            self.stderr.close()


def reconcile(root, oracle):
    with sqlite3.connect(f'file:{root / "state/collector.sqlite"}?mode=ro', uri=True) as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Private state integrity failed')
        actual = sorted(db.execute('SELECT hash,kind,payload FROM records'))
    if actual != oracle.expected():
        raise ValueError('Retained state differs from independent window oracle')


def full_evidence(root, oracle, now, changed):
    from threatfusion.connections import ConnectionRecord
    from threatfusion.collector_reports import read_archive
    from threatfusion.dns_collection import build_dns_snapshot
    from threatfusion.reporting import connection_report_payload
    from threatfusion.runtime_analysis import analyze_connection_records
    from threatfusion.ui_collector import read_snapshot

    snapshot = read_snapshot(root / 'state')
    full = json.loads(gzip.decompress(read_archive(root / 'state', snapshot['full_report']))) if 'full_report' in snapshot else snapshot
    connections, dns = [], []
    # Collector analysis orders equal timestamps by ascending hash.
    for _, row in sorted(oracle.rows.items(), key=lambda item: (item[1][0], item[0])):
        if row[2] == 'dns':
            dns.append(row[3])
        else:
            values = json.loads(row[3])
            values['timestamp'] = datetime.fromisoformat(values['timestamp'])
            connections.append(ConnectionRecord(**values))
    expected = connection_report_payload(analyze_connection_records(connections, indicators(changed)), generated_at=now, evaluated_at=now)
    expected['dns'] = build_dns_snapshot(dns, indicators(changed), generated_at=now)
    expected = json.loads(json.dumps(expected))
    if any(full[key] != expected[key] for key in KEYS):
        raise ValueError('Full retained export differs from offline evidence')
    return {'full_groups': len(full['findings']), 'snapshot_groups': len(snapshot['findings']),
            'omitted_groups': snapshot.get('connection_coverage', {}).get('omitted_groups', 0),
            'cti_groups': sum(row['CTI match'] for row in full['findings'])}


def quantile(values, q):
    ordered = sorted(values)
    return ordered[int((len(ordered)-1)*q)]


def assess(scans, samples, limits):
    main = [r for r in scans if r['phase'] == 'hour']
    idle = [r['wall_seconds'] for r in scans if r['phase'] == 'idle' and r['hour'] >= 24]
    rss = max(r['worker_high_water_rss_bytes'] for r in scans)
    disk = max(max(worker['disk']) for worker in samples)
    rss_windows = [quantile([r['idle_rss_bytes'] for r in scans if r['phase']=='idle' and lo <= r['hour'] < hi], 0.5)
                   for lo, hi in ((25, 48), (49, 72))]
    state_windows = [max(r['state_bytes'] for r in main if lo <= r['hour'] < hi) for lo, hi in ((24, 48), (48, 72))]
    measures = {'worker_high_water_rss_bytes': rss, 'peak_sampled_state_bytes': disk,
                'hour_tick_max_seconds': max(r['wall_seconds'] for r in main),
                'warm_idle_p95_seconds': quantile(idle, 0.95), 'warm_idle_median_seconds': quantile(idle, 0.5),
                'last_segment_idle_rss_ratio': rss_windows[1]/rss_windows[0],
                'state_last_day_ratio': state_windows[1]/state_windows[0]}
    checks = dict(zip(measures, (rss <= limits['worker_peak_sampled_rss_bytes'], disk <= limits['worker_peak_state_bytes'],
                  measures['hour_tick_max_seconds'] <= limits['hour_tick_max_seconds'],
                  measures['warm_idle_p95_seconds'] <= limits['warm_idle_p95_max_seconds'],
                  measures['warm_idle_median_seconds'] <= limits['warm_idle_median_max_seconds'],
                  measures['last_segment_idle_rss_ratio'] <= limits['last_segment_idle_rss_vs_previous_max_ratio'],
                  measures['state_last_day_ratio'] <= limits['state_last_day_vs_first_full_window_max_ratio'])))
    return {'measurements': measures, 'predeclared_checks': checks, 'engineering_limits_passed': all(checks.values())}


def evaluate(root):
    plan = load_plan(root)
    hashes = prepare(root, plan)
    amendment = root / 'amendment.json'
    if amendment.exists() and hashes != json.loads(amendment.read_text())['source_files_sha256']:
        raise ValueError('Amended replay changed original source bytes')
    private_root(root / 'input')
    oracle = RetentionOracle()
    scans, samples, checkpoints, recoveries = [], [], [], []
    current = Worker(root, 0)
    segment = 0
    try:
        for hour in range(plan['hours']):
            now = datetime.fromisoformat(plan['event_start']) + timedelta(hours=hour, seconds=1800)
            changed = hour >= plan['cti_change_hour']
            oracle.prune(now.timestamp())
            for kind in ('conn', 'dns'):
                path = root / 'fixtures' / f'{kind}.{hour:03d}.log'
                shutil.copyfile(path, root / 'input' / path.name)
                (root / 'input' / path.name).chmod(0o600)
                oracle.ingest(parsed_payloads(path, kind, now.timestamp()), now.timestamp())
            result = current.tick(now, changed)
            if result['status']['counts']['new_records'] != 5000 or result['status']['counts']['rejected_files']:
                raise ValueError('Hourly source conservation/rejection failed')
            reconcile(root, oracle)
            current.sample()
            scans.append(result | {'phase': 'hour', 'hour': hour, 'state_bytes': current.disk[-1]})
            idle = current.tick(now + timedelta(seconds=plan['idle_seconds']), changed)
            oracle.prune((now + timedelta(seconds=plan['idle_seconds'])).timestamp())
            reconcile(root, oracle)
            if idle['status']['counts']['new_records'] or idle['status']['scan']['analysis_recomputed'] or not idle['status']['scan']['archive_reused']:
                raise ValueError('Idle reuse/new-record contract failed')
            current.sample()
            scans.append(idle | {'phase': 'idle', 'hour': hour, 'idle_rss_bytes': current.rss[-1]})
            if hour in plan['checkpoint_hours']:
                checkpoints.append({'hour': hour, **full_evidence(root, oracle, now, changed)})
                gc.collect()
            if hour in plan['kill_after_hours']:
                # An unfinished file must remain deferred across idle termination.
                path = root / 'input' / f'conn.open-{hour}.log'
                rows = fixture_rows(plan, hour, 'conn')[:60]
                for index, row in enumerate(rows):
                    row[1] = f'Cclosed-late-{hour}-{index}'
                path.write_text(log('conn', rows, closed=False))
                path.chmod(0o600)
                open_scan = current.tick(now, changed)
                if open_scan['status']['counts']['new_records'] or open_scan['status']['counts']['open_files'] != 1:
                    raise ValueError('Open log was imported')
                before = (root / 'state/connections.json').read_bytes()
                revision = json.loads(before)['collector']['selection_revision']
                current.close(kill=True)
                samples.append({'rss': current.rss, 'disk': current.disk})
                segment += 1
                current = Worker(root, segment)
                if (root / 'state/connections.json').read_bytes() != before:
                    raise ValueError('Interrupted idle worker changed published evidence')
                restart = current.tick(now, changed)
                if restart['status']['counts']['new_records'] or restart['status']['selection_revision'] != revision:
                    raise ValueError('Restart duplicated records or changed mapping')
                path.write_text(log('conn', rows))
                oracle.ingest(parsed_payloads(path, 'conn', now.timestamp()), now.timestamp())
                closed = current.tick(now, changed)
                if closed['status']['counts']['new_records'] != 60:
                    raise ValueError('Closed deferred rows did not import exactly once')
                reconcile(root, oracle)
                copy = root / 'input' / f'conn.copy-{hour}.log.gz'
                copy.write_bytes(gzip.compress(path.read_bytes()))
                copy.chmod(0o600)
                renamed = root / 'input' / f'conn.renamed-{hour}.log'
                path.rename(renamed)
                duplicate = current.tick(now, changed)
                if duplicate['status']['counts']['new_records'] or duplicate['status']['counts']['duplicate_files'] != 2:
                    raise ValueError('Rename/gzip resurrected or duplicated evidence')
                reconcile(root, oracle)
                recoveries.append({'hour': hour, 'own_child_exit': -9, 'published_snapshot_preserved': True,
                                   'restart_new_records': 0, 'late_closed_rows': 60, 'rename_gzip_duplicates': 2})
            write_new(root / f'checkpoint-{hour:03d}.json', {'hour': hour, 'retained': len(oracle.rows), 'phase_contracts_passed': True})
        # Present unchanged source paths keep checkpoints, not expired evidence.
        later = now + timedelta(days=8)
        expired = current.tick(later, True)
        oracle.prune(later.timestamp())
        reconcile(root, oracle)
        if expired['status']['counts']['retained_total_records'] or expired['status']['counts']['new_records']:
            raise ValueError('Expired source evidence resurrected')
        for path in (root / 'input').iterdir():
            path.unlink()  # Only these generated fixture copies, never originals.
        clean = current.tick(later + timedelta(days=8), True)
        with sqlite3.connect(root / 'state/collector.sqlite') as db:
            remaining = {table: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0] for table in ('records', 'files', 'paths')}
        if any(remaining.values()) or list((root / 'state').glob('connections.full-*.json.gz')):
            raise ValueError('Expired private ledger/archive cleanup failed')
        current.sample()
        cleanup = {'counts': remaining, 'state_bytes': current.disk[-1], 'intact_archives_removed': True,
                   'active_sources_did_not_resurrect': True, 'status': clean['status']}
    finally:
        current.close()
        samples.append({'rss': current.rss, 'disk': current.disk})
    verify_freeze(root, hashes)
    assessment = assess(scans, samples, plan['engineering_acceptance'])
    write_new(root / 'scans.json', scans)
    write_new(root / 'resource-samples.json', samples)
    summary = {'protocol': plan['protocol'], 'event_hours': plan['hours'], 'source_rows': plan['hours']*5000,
               'late_closed_rows': 120, 'retention_oracle_every_scan': True, 'full_export_checkpoints': checkpoints,
               'recoveries': recoveries, 'cleanup': cleanup, **assessment,
               'rss_scope': 'Own collector worker, excluding parent fixture/oracle/full-report calculations; OS high-water plus 50ms sampling.',
               'wall_clock_soak': False, 'new_detection_evidence': False, 'runtime_changed': False}
    write_new(root / 'summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.root)
    worker(root) if args.worker else evaluate(root)
