"""Private real wall-clock soak: collector CLI, local web app and a CTI cache copy.

Declare first (`--declare`), then run (`--run`) in the same root outside Git.
Synthetic completed Zeek logs with reserved addresses and `.test` names are
rotated in real time; no packets, destinations or feeds are contacted. The CTI
cache is a private SQLite backup copy of the developer's existing cache, read
through a read-only connection and never modified. Results are engineering
evidence for one host/workload, not detection efficacy or enterprise sizing.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import socket
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.measure_multiday import log

REPO = Path(__file__).resolve().parents[2]
PROTOCOL = 'wallclock-soak-v1'
SOURCE_CACHE = REPO / 'data/threatfusion.sqlite'
SOAK_TARGET = '198.51.100.200'
FULL = {'duration_seconds': 21600, 'rotation_seconds': 300, 'connections_per_rotation': 1000,
        'dns_per_rotation': 600, 'poll_seconds': 10, 'sample_seconds': 10, 'fresh_session_seconds': 900,
        'cti_change_seconds': 10800}
SMOKE = {'duration_seconds': 240, 'rotation_seconds': 40, 'connections_per_rotation': 200,
         'dns_per_rotation': 100, 'poll_seconds': 10, 'sample_seconds': 5, 'fresh_session_seconds': 60,
         'cti_change_seconds': 120}
LIMITS = {'collector_rss_max_bytes': 1610612736, 'web_rss_max_bytes': 2147483648,
          'state_max_bytes': 536870912, 'snapshot_age_max_seconds': 60,
          'fragment_gap_max_seconds': 60, 'fresh_session_max_seconds': 60,
          'cti_change_visible_max_seconds': 60, 'rss_last_vs_second_hour_max_ratio': 1.25,
          'fd_growth_max': 16, 'thread_growth_max': 16, 'record_limit': 100000}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as file:
        for chunk in iter(lambda: file.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprints():
    return {'runtime': {str(p.relative_to(REPO)): sha(p) for p in sorted((REPO / 'src/threatfusion').glob('*.py'))},
            'app': sha(REPO / 'streamlit_app.py'), 'method': sha(Path(__file__))}


def declare(root, smoke=False):
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    dirty = subprocess.check_output(['git', 'status', '--porcelain', '--', 'src', 'streamlit_app.py', 'scripts'],
                                    cwd=REPO, text=True).splitlines()
    plan = {'protocol': PROTOCOL, 'method_smoke': smoke, 'baseline_commit': head, 'uncommitted_paths': dirty,
            'candidate': fingerprints(), 'workload': SMOKE if smoke else FULL, 'acceptance': LIMITS,
            'source_cache_sha256': sha(SOURCE_CACHE),
            'scope': ('Real wall-clock on one host; collector CLI plus local Streamlit with one persistent '
                      'auto-refreshing collector view and periodic fresh sessions; private copy of the existing '
                      'CTI cache. Not 72 hours, enterprise traffic, browser rendering cost or detection efficacy.')}
    raw = json.dumps(plan, indent=2) + '\n'
    for name, value in (('plan.json', raw), ('plan.sha256', hashlib.sha256(raw.encode()).hexdigest() + '\n')):
        with (root / name).open('x') as file:
            file.write(value)
        (root / name).chmod(0o600)
    print(json.dumps({'declared': PROTOCOL, 'method_smoke': smoke, 'plan_sha256': sha(root / 'plan.json')}))


def load_plan(root):
    if sha(root / 'plan.json') != (root / 'plan.sha256').read_text().strip():
        raise ValueError('Soak declaration changed')
    plan = json.loads((root / 'plan.json').read_text())
    if plan['protocol'] != PROTOCOL or plan['candidate'] != fingerprints() or plan['acceptance'] != LIMITS:
        raise ValueError('Candidate, method or acceptance differs from the declaration')
    if plan['workload'] != (SMOKE if plan['method_smoke'] else FULL):
        raise ValueError('Workload differs from the declaration')
    return plan


def rows(kind, rotation, count, end):
    start = end - timedelta(seconds=280)
    result = []
    for index in range(count):
        timestamp = (start + timedelta(seconds=index * 270 / count)).timestamp()
        common = [timestamp, f'Csoak-{kind}-{rotation}-{index}', f'192.0.2.{1 + index % 12}', 40000 + index % 20000]
        if kind == 'conn':
            target = SOAK_TARGET if index % 100 == 0 else f'203.0.113.{1 + index % 200}'
            result.append(common + [target, 443, 'tcp', 1.0, 100, 200, 'SF', 0])
        else:
            result.append(common + ['192.0.2.53', 53, 'udp', index % 65536, f'service{index % 120}.soak.test',
                                    'A', 'NOERROR', '198.51.100.9'])
    return result


def rss(pid):
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
    except (FileNotFoundError, ProcessLookupError):
        return None


def threads(pid):
    try:
        return len(os.listdir(f'/proc/{pid}/task'))
    except FileNotFoundError:
        return None


def fds(pid):
    try:
        return len(os.listdir(f'/proc/{pid}/fd'))
    except FileNotFoundError:
        return None


def state_bytes(state):
    total = 0
    for path in state.iterdir():
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue  # Atomic replacement between inventory and stat.
        if path.is_file():
            total += info.st_size
    return total


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def copy_cache(source, target):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as original, sqlite3.connect(target) as copy:
        original.backup(copy)
    target.chmod(0o600)


async def session(port, persistent, record, stop):
    """Emulate one browser tab: render, open Collected connections, follow fragment reruns."""
    import websockets
    from streamlit.proto.BackMsg_pb2 import BackMsg
    from streamlit.proto.ForwardMsg_pb2 import ForwardMsg

    started = time.monotonic()
    async with websockets.connect(f'ws://127.0.0.1:{port}/_stcore/stream', origin=f'http://127.0.0.1:{port}',
                                  subprotocols=['streamlit'], open_timeout=30, max_size=64 * 1024 * 1024,
                                  ping_interval=20) as connection:
        async def rerun(button=None, fragment=None):
            message = BackMsg()
            message.rerun_script.SetInParent()
            if button:
                widget = message.rerun_script.widget_states.widgets.add()
                widget.id, widget.trigger_value = button, True
            if fragment:
                message.rerun_script.fragment_id = fragment
            await connection.send(message.SerializeToString())

        await rerun()
        button, clicked, page_seen = None, False, False
        due = {}  # Each fragment reruns on its own interval, as in the browser.
        while not stop.is_set():
            soonest = min(due.values(), default=time.monotonic() + 1)
            timeout = max(0.05, min(1.0, soonest - time.monotonic()))
            try:
                raw = await asyncio.wait_for(connection.recv(), timeout=timeout)
            except asyncio.TimeoutError:
                raw = None
            if raw is not None:
                reply = ForwardMsg()
                reply.ParseFromString(raw)
                kind = reply.WhichOneof('type')
                if kind == 'delta' and reply.delta.HasField('new_element'):
                    element = reply.delta.new_element
                    if element.HasField('exception'):
                        record('exception', None)
                    if element.HasField('button') and 'nav_collector' in element.button.id:
                        button = element.button.id
                    if element.HasField('markdown'):
                        if clicked and '<h1>Collected connections</h1>' in element.markdown.body:
                            page_seen = True
                        if page_seen and 'Collector snapshot' in element.markdown.body:
                            record('collector_view', None)
                elif kind == 'auto_rerun':
                    due[reply.auto_rerun.fragment_id] = time.monotonic() + reply.auto_rerun.interval
                elif kind == 'script_finished':
                    finished = reply.script_finished
                    if finished == ForwardMsg.FINISHED_WITH_COMPILE_ERROR:
                        record('exception', None)
                    elif finished == ForwardMsg.FINISHED_SUCCESSFULLY:
                        if button and not clicked:
                            clicked = True
                            await rerun(button=button)
                        elif page_seen and not persistent:
                            record('fresh_rendered', time.monotonic() - started)
                            return
            if persistent and page_seen:
                for fragment, when in list(due.items()):
                    if time.monotonic() >= when:
                        await rerun(fragment=fragment)
                        due[fragment] = time.monotonic() + 10


def run_session(port, persistent, events, stop):
    def record(kind, value):
        events.append({'at': time.time(), 'kind': kind, 'value': value, 'persistent': persistent})
    try:
        asyncio.run(asyncio.wait_for(session(port, persistent, record, stop), None if persistent else 120))
    except Exception as error:  # Recorded as an outcome, never hidden.
        record('error', f'{type(error).__name__}: {str(error)[:200]}')


def quantile(values, q):
    ordered = sorted(values)
    return ordered[int((len(ordered) - 1) * q)] if ordered else None


def evaluate(root):
    from threatfusion.cti_cache import replace_source_records
    from threatfusion.local_setup import prepare_local_environment, streamlit_command
    from threatfusion.models import IOCRecord, IOCType

    plan = load_plan(root)
    if (root / 'summary.json').exists():
        raise ValueError('Receipts exist; declare an amendment into a new root')
    work = plan['workload']
    install, state, source = root / 'install', root / 'state', private_root(root / 'input')
    copy_cache(SOURCE_CACHE, install / 'runtime/cti/threatfusion.sqlite')
    environment = prepare_local_environment(install, 'cti-only', os.environ)
    cache = Path(environment['THREATFUSION_DB_PATH'])
    environment |= {'THREATFUSION_COLLECTOR_STATE_DIR': str(state), 'PYTHONPATH': str(REPO / 'src')}
    port = free_port()
    collector_out = (root / 'collector.stdout').open('xb')
    collector_err = (root / 'collector.stderr').open('xb')
    collector = subprocess.Popen([sys.executable, '-m', 'threatfusion.telemetry_collector', '--input-dir', str(source),
                                  '--state-dir', str(state), '--db', str(cache), '--poll-seconds', str(work['poll_seconds'])],
                                 cwd=REPO, env=environment, stdout=collector_out, stderr=collector_err)
    web_err = (root / 'web.stderr').open('xb')
    web = subprocess.Popen(streamlit_command(REPO, port), cwd=REPO, env=environment,
                           stdout=web_err, stderr=web_err, start_new_session=True)
    stop = threading.Event()
    events, samples, rotations, cti_change = [], [], [], {}
    threads_started = []
    generated = 0
    persistent = None
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=1):
                    break
            except OSError:
                time.sleep(0.5)
        time.sleep(3)
        persistent = threading.Thread(target=run_session, args=(port, True, events, stop), daemon=True)
        persistent.start()
        start = time.monotonic()
        next_rotation = next_sample = next_fresh = start
        rotation = 0
        while time.monotonic() - start < work['duration_seconds']:
            now = time.monotonic()
            if now >= next_rotation:
                end = datetime.now(timezone.utc)
                for kind, count in (('conn', work['connections_per_rotation']), ('dns', work['dns_per_rotation'])):
                    path = source / f'{kind}.{rotation:04d}.log'
                    temporary = source / f'.{kind}.{rotation:04d}.tmp'
                    temporary.write_text(log(kind, rows(kind, rotation, count, end)))
                    temporary.chmod(0o600)
                    temporary.rename(path)  # Complete and closed before it becomes a candidate.
                    generated += count
                rotations.append({'rotation': rotation, 'at': time.time(), 'generated_total': generated})
                rotation += 1
                next_rotation += work['rotation_seconds']
            if not cti_change and now - start >= work['cti_change_seconds']:
                replace_source_records(cache, 'SyntheticSoak', [IOCRecord(SOAK_TARGET, IOCType.IPV4, 'SyntheticSoak')])
                cti_change = {'at': time.time(), 'visible_at': None}
            if now >= next_fresh:
                fresh = threading.Thread(target=run_session, args=(port, False, events, stop), daemon=True)
                fresh.start()
                threads_started.append(fresh)
                next_fresh += work['fresh_session_seconds']
            if now >= next_sample:
                sample = {'at': time.time(), 'collector_alive': collector.poll() is None, 'web_alive': web.poll() is None,
                          'collector_rss': rss(collector.pid), 'web_rss': rss(web.pid),
                          'collector_fds': fds(collector.pid), 'web_fds': fds(web.pid),
                          'collector_threads': threads(collector.pid), 'web_threads': threads(web.pid),
                          'state_bytes': state_bytes(state) if state.exists() else 0}
                try:
                    status = json.loads((state / 'status.json').read_text())
                    sample |= {'snapshot_age': time.time() - datetime.fromisoformat(status['updated_at']).timestamp(),
                               'retained_total': status['counts']['retained_total_records'],
                               'capacity_loss': status['capacity_coverage_loss'], 'cti_indicators': status['cti_indicators'],
                               'cti_reload_deferred': status.get('cti_reload_deferred'),
                               'input_loss': status['input_coverage_loss']}
                    if cti_change and cti_change['visible_at'] is None:
                        report = json.loads((state / 'connections.json').read_text())
                        if any(row.get('CTI match') for row in report['findings']):
                            cti_change['visible_at'] = time.time()
                except (FileNotFoundError, json.JSONDecodeError, KeyError):
                    pass
                samples.append(sample)
                next_sample += work['sample_seconds']
            time.sleep(0.2)
        # Let the final rotation be scanned before stopping.
        time.sleep(work['poll_seconds'] * 3)
    finally:
        stop.set()
        # Close every emulated tab before stopping the web process, so its
        # own shutdown is not recorded as a session failure.
        for thread in threads_started + ([persistent] if persistent else []):
            thread.join(timeout=30)
        if collector.poll() is None:
            collector.send_signal(signal.SIGTERM)  # Only this explicitly spawned own child.
        if web.poll() is None:
            os.killpg(web.pid, signal.SIGTERM)  # Own Streamlit session group only.
        for child in (collector, web):
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
        for handle in (collector_out, collector_err, web_err):
            handle.close()
    load_plan(root)
    summary = assess(root, plan, samples, events, rotations, cti_change, generated, collector.returncode)
    write_new(root / 'samples.json', samples)
    write_new(root / 'events.json', events)
    write_new(root / 'rotations.json', rotations)
    write_new(root / 'summary.json', summary)
    print(json.dumps(summary))


def assess(root, plan, samples, events, rotations, cti_change, generated, collector_exit):
    work, limits = plan['workload'], plan['acceptance']
    ticks = [json.loads(line) for line in (root / 'collector.stdout').read_text().splitlines() if line.startswith('{')]
    imported = sum(tick['new_records'] for tick in ticks)
    rejected = sum(tick['rejected_files'] for tick in ticks)
    start = samples[0]['at'] if samples else 0
    hour = 3600 if not plan['method_smoke'] else work['duration_seconds'] / 6

    def window(key, lo, hi):
        return [s[key] for s in samples if s.get(key) is not None and lo <= (s['at'] - start) / hour < hi]
    last = int(work['duration_seconds'] / hour) - 1
    measures = {
        'collector_rss_max': max((s['collector_rss'] or 0) for s in samples),
        'web_rss_max': max((s['web_rss'] or 0) for s in samples),
        'state_max': max(s['state_bytes'] for s in samples),
        'snapshot_age_max': max((s.get('snapshot_age', 0) for s in samples[3:]), default=None),
        'collector_rss_ratio': statistics.median(window('collector_rss', last, last + 1)) / statistics.median(window('collector_rss', 1, 2)),
        'web_rss_ratio': statistics.median(window('web_rss', last, last + 1)) / statistics.median(window('web_rss', 1, 2)),
        'collector_fd_growth': max(window('collector_fds', last, last + 1)) - max(window('collector_fds', 1, 2)),
        'web_fd_growth': max(window('web_fds', last, last + 1)) - max(window('web_fds', 1, 2)),
        'collector_thread_growth': max(window('collector_threads', last, last + 1)) - max(window('collector_threads', 1, 2)),
        'web_thread_growth': max(window('web_threads', last, last + 1)) - max(window('web_threads', 1, 2)),
    }
    # Diagnostic declared after the method smoke showed a one-time CTI reload
    # high-water step. It never replaces the predeclared growth check above.
    after = int(work['cti_change_seconds'] / hour) + 1
    measures['diagnostic_post_reload_collector_rss_ratio'] = (
        statistics.median(window('collector_rss', last, last + 1)) / statistics.median(window('collector_rss', after, after + 1))
        if after < last else None)
    persistent = sorted(e['at'] for e in events if e['persistent'] and e['kind'] == 'collector_view')
    gaps = [b - a for a, b in zip(persistent, persistent[1:])]
    fresh = [e['value'] for e in events if not e['persistent'] and e['kind'] == 'fresh_rendered']
    fresh_started = (work['duration_seconds'] + work['fresh_session_seconds'] - 1) // work['fresh_session_seconds']
    final = next((s for s in reversed(samples) if 'retained_total' in s), {})
    capacity_expected = generated > limits['record_limit']
    measures |= {'persistent_fragment_gap_max': max(gaps, default=None), 'persistent_reruns': len(persistent),
                 'fresh_sessions_rendered': len(fresh), 'fresh_sessions_declared': fresh_started,
                 'fresh_session_max_seconds': max(fresh, default=None),
                 'exceptions': sum(e['kind'] == 'exception' for e in events),
                 'session_errors': [e['value'] for e in events if e['kind'] == 'error'],
                 'cti_change_visible_seconds': (cti_change['visible_at'] - cti_change['at'])
                 if cti_change.get('visible_at') else None,
                 'generated': generated, 'imported': imported, 'rejected_files': rejected,
                 'final_retained': final.get('retained_total'), 'final_capacity_loss': final.get('capacity_loss'),
                 'cti_reload_deferred_samples': sum(bool(s.get('cti_reload_deferred')) for s in samples),
                 'collector_exit': collector_exit}
    checks = {
        'processes_alive_every_sample': all(s['collector_alive'] and s['web_alive'] for s in samples),
        'collector_rss': measures['collector_rss_max'] <= limits['collector_rss_max_bytes'],
        'web_rss': measures['web_rss_max'] <= limits['web_rss_max_bytes'],
        'state_bytes': measures['state_max'] <= limits['state_max_bytes'],
        'snapshot_age': measures['snapshot_age_max'] is not None and measures['snapshot_age_max'] <= limits['snapshot_age_max_seconds'],
        'rss_growth': max(measures['collector_rss_ratio'], measures['web_rss_ratio']) <= limits['rss_last_vs_second_hour_max_ratio'],
        'fd_growth': max(measures['collector_fd_growth'], measures['web_fd_growth']) <= limits['fd_growth_max'],
        'thread_growth': max(measures['collector_thread_growth'], measures['web_thread_growth']) <= limits['thread_growth_max'],
        'persistent_view_responsive': measures['persistent_fragment_gap_max'] is not None
        and measures['persistent_fragment_gap_max'] <= limits['fragment_gap_max_seconds'],
        'fresh_sessions': measures['fresh_sessions_rendered'] == fresh_started
        and (measures['fresh_session_max_seconds'] or 1e9) <= limits['fresh_session_max_seconds'],
        'no_exceptions_or_session_errors': not measures['exceptions'] and not measures['session_errors'],
        'cti_change_visible': measures['cti_change_visible_seconds'] is not None
        and measures['cti_change_visible_seconds'] <= limits['cti_change_visible_max_seconds'],
        'exact_conservation': imported == generated and rejected == 0,
        'retained_and_capacity_disclosed': final.get('retained_total') == min(generated, limits['record_limit'])
        and bool(final.get('capacity_loss')) == capacity_expected,
        'clean_exit': collector_exit == 0,
        'source_cache_unchanged': sha(SOURCE_CACHE) == plan['source_cache_sha256'],
    }
    return {'protocol': PROTOCOL, 'method_smoke': plan['method_smoke'], 'baseline_commit': plan['baseline_commit'],
            'measurements': measures, 'predeclared_checks': checks, 'all_passed': all(checks.values()),
            'wall_clock_seconds': work['duration_seconds'], 'new_detection_evidence': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--declare', action='store_true')
    action.add_argument('--run', action='store_true')
    parser.add_argument('--smoke', action='store_true', help='Declare a short method smoke, not soak evidence')
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.root)
    declare(root, args.smoke) if args.declare else evaluate(root)
