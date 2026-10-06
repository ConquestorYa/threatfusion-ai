"""Private operational fault matrix for the real foreground collector CLI.

Declare first (`--declare`), then run (`--run`) against the same root outside
Git. Every case owns synthetic input/state and a synthetic CTI cache with
reserved addresses and `.test` names. No user cache, telemetry, network access
or host-disk exhaustion is used. Outcomes are engineering contract evidence for
this machine, not detection efficacy or a comprehensive security audit.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.lab.evaluate_dns_collector import private_root, write_new
from scripts.lab.measure_multiday import log

REPO = Path(__file__).resolve().parents[2]
PROTOCOL = 'operational-faults-v1'
ROWS = 500
CTI_SIZE = 200_000
REFRESH_CYCLES = 6
LOCK_SECONDS = 12
SETTLE_SECONDS = 15
CASES = ('concurrent_refresh', 'exclusive_lock', 'state_readonly', 'unreadable_file', 'unreadable_subdir',
         'corrupt_state', 'truncated_gzip', 'expected_rules_missing', 'sigterm')
ACCEPTANCE = {
    'concurrent_refresh': 'Collector stays alive through six real 200k-record source replacements; no published status reports zero CTI indicators; final indicator count appears within 15 s; 500 rows import exactly once.',
    'exclusive_lock': 'A 12 s exclusive CTI lock (above the 5 s SQLite busy timeout) does not stop the collector; the snapshot stays valid; a later CTI change appears within 15 s.',
    'state_readonly': 'Read-only private state preserves the last snapshot bytes; any exit is nonzero, actionable and traceback-free; after restoring permissions (and a restart if exited) the new file imports exactly once and no temporary outputs remain.',
    'unreadable_file': 'An unreadable completed log is rejected as access with input coverage loss while another file imports; after restoring permission it imports exactly once; the collector stays alive.',
    'unreadable_subdir': 'An unreadable dated subdirectory fails before import: no sibling rows from that scan, preserved snapshot bytes; any exit is nonzero, actionable and traceback-free; restore and resume import all rows exactly once.',
    'corrupt_state': 'A corrupted private collector database is refused at start with a nonzero, traceback-free exit; it is not deleted or replaced; the published snapshot remains.',
    'truncated_gzip': 'A truncated gzip archive is rejected as archive with zero imported rows and input coverage loss; a complete replacement imports exactly once; the collector stays alive.',
    'expected_rules_missing': 'A removed declaration path stops processing with a nonzero, actionable, traceback-free exit and preserved snapshot; restoring and restarting imports zero duplicate rows.',
    'sigterm': 'SIGTERM exits 0 within 15 s with a valid snapshot; restart adds zero records.',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fingerprints():
    return {'runtime': {str(p.relative_to(REPO)): sha(p) for p in sorted((REPO / 'src/threatfusion').glob('*.py'))},
            'method': sha(Path(__file__))}


def declare(root, amends=None, reason=None):
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    plan = {'protocol': PROTOCOL, 'baseline_commit': head, 'candidate': fingerprints(),
            'permitted_runtime_changes': [], 'cases': list(CASES), 'acceptance': ACCEPTANCE,
            'rows_per_file': ROWS, 'cti_size': CTI_SIZE, 'refresh_cycles': REFRESH_CYCLES,
            'lock_seconds': LOCK_SECONDS, 'settle_seconds': SETTLE_SECONDS, 'poll_seconds': 1,
            'scope': 'Owned synthetic state/cache on one host; not physical disk exhaustion, power loss or a security audit.'}
    if amends:
        # Method-only amendment: the earlier root and its receipts stay intact.
        previous = Path(amends)
        earlier = json.loads((previous / 'plan.json').read_text())['candidate']['runtime']
        current = plan['candidate']['runtime']
        plan['permitted_runtime_changes'] = sorted(name for name in set(earlier) | set(current)
                                                   if earlier.get(name) != current.get(name))
        plan['amends'] = {'root': str(previous), 'plan_sha256': sha(previous / 'plan.json'),
                          'summary_sha256': sha(previous / 'summary.json'), 'reason': reason}
    raw = json.dumps(plan, indent=2) + '\n'
    for name, value in (('plan.json', raw), ('plan.sha256', hashlib.sha256(raw.encode()).hexdigest() + '\n')):
        with (root / name).open('x') as file:
            file.write(value)
        (root / name).chmod(0o600)
    print(json.dumps({'declared': PROTOCOL, 'plan_sha256': sha(root / 'plan.json')}))


def load_plan(root):
    if sha(root / 'plan.json') != (root / 'plan.sha256').read_text().strip():
        raise ValueError('Fault declaration changed')
    plan = json.loads((root / 'plan.json').read_text())
    if plan['protocol'] != PROTOCOL or plan['candidate'] != fingerprints() or plan['acceptance'] != ACCEPTANCE:
        raise ValueError('Candidate, method or acceptance differs from the declaration')
    return plan


def conn_rows(prefix, count=ROWS, now=None):
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(seconds=900)
    return [[(start + timedelta(seconds=index)).timestamp(), f'C{prefix}-{index}', f'192.0.2.{1 + index % 8}',
             41000 + index, '198.51.100.77' if index % 50 == 0 else f'203.0.113.{1 + index % 200}', 443,
             'tcp', 1.0, 100, 200, 'SF', 0] for index in range(count)]


def write_log(path, prefix, closed=True, count=ROWS):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(log('conn', conn_rows(prefix, count), closed=closed))
    path.chmod(0o600)
    return path


def indicators(count, variant):
    from threatfusion.models import IOCRecord, IOCType
    records = [IOCRecord(f'n{variant}-{index}.ioc.test', IOCType.DOMAIN, 'SyntheticA') for index in range(count)]
    return records + [IOCRecord('198.51.100.77', IOCType.IPV4, 'SyntheticA')]


def seed_cache(path, count=CTI_SIZE, variant='a'):
    from threatfusion.cti_cache import replace_source_records
    replace_source_records(path, 'SyntheticA', indicators(count, variant))
    path.chmod(0o600)


SPAWNED = []


class Collector:
    def __init__(self, case_root, name, *extra):
        SPAWNED.append(self)
        self.out = (case_root / f'{name}.stdout').open('xb')
        self.err_path = case_root / f'{name}.stderr'
        self.err = self.err_path.open('xb')
        args = [sys.executable, '-m', 'threatfusion.telemetry_collector', '--input-dir', str(case_root / 'input'),
                '--state-dir', str(case_root / 'state'), '--poll-seconds', '1', *extra]
        self.child = subprocess.Popen(args, cwd=REPO, stdout=self.out, stderr=self.err,
                                      env=os.environ | {'PYTHONPATH': str(REPO / 'src')})
        self.stdout_path = case_root / f'{name}.stdout'

    def ticks(self):
        return [json.loads(line) for line in self.stdout_path.read_text().splitlines() if line.startswith('{')]

    def alive(self):
        return self.child.poll() is None

    def stop(self, sig=signal.SIGTERM, timeout=15):
        if self.child.poll() is None:
            self.child.send_signal(sig)  # Only this explicitly spawned own child.
            try:
                self.child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=10)
        self.out.close()
        self.err.close()
        return self.child.returncode

    def stderr(self):
        return self.err_path.read_text(errors='replace')


def wait(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except (FileNotFoundError, json.JSONDecodeError, ValueError, sqlite3.OperationalError):
            pass  # State not yet created or atomically replaced between reads.
        time.sleep(0.2)
    return False


def status(case_root):
    return json.loads((case_root / 'state/status.json').read_text())


def imported(collector):
    return sum(tick['new_records'] for tick in collector.ticks())


def records(case_root):
    if not (case_root / 'state/collector.sqlite').exists():
        return 0
    with sqlite3.connect(f'file:{case_root / "state/collector.sqlite"}?mode=ro', uri=True) as db:
        return db.execute('SELECT count(*) FROM records').fetchone()[0]


def clean_exit(code, stderr):
    return {'exit_code': code, 'nonzero': code not in (0, None), 'traceback_free': 'Traceback' not in stderr,
            'actionable': 'Collector stopped:' in stderr}


def case_dir(root, name):
    path = root / 'cases' / name
    path.mkdir(mode=0o700, parents=True)
    (path / 'input').mkdir(mode=0o700)
    return path


def started(case_root, *extra, name='collector', expect=ROWS):
    collector = Collector(case_root, name, *extra)
    if not wait(lambda: records(case_root) >= expect and (case_root / 'state/connections.json').exists(), 60):
        collector.stop()
        raise ValueError(f'Collector did not import the initial source: {collector.stderr()[-400:]}')
    return collector


def concurrent_refresh(root):
    case = case_dir(root, 'concurrent_refresh')
    cache = case / 'cti.sqlite'
    seed_cache(cache)
    write_log(case / 'input/conn.a.log', 'refresh')
    collector = started(case, '--db', str(cache))
    observed = []
    refresher = subprocess.Popen([sys.executable, '-c', (
        'import sys; from pathlib import Path; from scripts.lab.operational_faults import seed_cache\n'
        f'for cycle in range({REFRESH_CYCLES}): seed_cache(Path(sys.argv[1]), variant="b" if cycle % 2 == 0 else "a")')
        , str(cache)], cwd=REPO, env=os.environ | {'PYTHONPATH': f'{REPO}:{REPO / "src"}'},
        stderr=(case / 'refresher.stderr').open('xb'))
    while refresher.poll() is None:
        try:
            observed.append(status(case)['cti_indicators'])
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.2)
    final = CTI_SIZE + 1
    settled = wait(lambda: status(case)['cti_indicators'] == final and collector.alive(), SETTLE_SECONDS)
    alive = collector.alive()
    rows = records(case)
    code = collector.stop()
    result = {'refresher_exit': refresher.returncode, 'collector_alive_after_refreshes': alive,
              'minimum_observed_indicators': min(observed, default=None), 'final_indicators_within_settle': settled,
              'records': rows, **clean_exit(code, collector.stderr())}
    result['passed'] = (refresher.returncode == 0 and alive and settled and rows == ROWS
                        and (result['minimum_observed_indicators'] or 0) > 0)
    return result


def exclusive_lock(root):
    from threatfusion.cti_cache import replace_source_records
    case = case_dir(root, 'exclusive_lock')
    cache = case / 'cti.sqlite'
    seed_cache(cache, count=1000)
    write_log(case / 'input/conn.a.log', 'lock')
    collector = started(case, '--db', str(cache))
    holder = sqlite3.connect(cache, timeout=0, isolation_level=None)
    holder.execute('BEGIN EXCLUSIVE')
    # Changing the cache file signature forces a reload attempt during the lock.
    os.utime(cache)
    alive_during = []
    for _ in range(LOCK_SECONDS * 5):
        alive_during.append(collector.alive())
        time.sleep(0.2)
    valid_during = json.loads((case / 'state/connections.json').read_text()) is not None
    holder.execute('ROLLBACK')
    holder.close()
    from threatfusion.models import IOCRecord, IOCType
    replace_source_records(cache, 'SyntheticB', [IOCRecord('changed.ioc.test', IOCType.DOMAIN, 'SyntheticB')])
    settled = wait(lambda: status(case)['cti_indicators'] == 1002 and collector.alive(), SETTLE_SECONDS)
    alive = collector.alive()
    code = collector.stop()
    result = {'alive_through_lock': all(alive_during), 'snapshot_valid_during_lock': valid_during,
              'change_visible_after_lock': settled,
              'collector_alive_at_end': alive, **clean_exit(code, collector.stderr())}
    result['passed'] = all(alive_during) and valid_during and settled and alive
    return result


def temporary_outputs(case):
    return sorted(path.name for path in (case / 'state').iterdir() if path.name.startswith('.collector-'))


def state_readonly(root):
    case = case_dir(root, 'state_readonly')
    write_log(case / 'input/conn.a.log', 'ro-a')
    collector = started(case)
    # Capture only after the fault exists: healthy ticks legitimately rewrite
    # generated timestamps, so earlier bytes cannot define preservation.
    (case / 'state').chmod(0o500)
    time.sleep(2)
    before = (case / 'state/connections.json').read_bytes()
    write_log(case / 'input/conn.b.log', 'ro-b')
    time.sleep(5)
    preserved = (case / 'state/connections.json').read_bytes() == before
    alive_during = collector.alive()
    (case / 'state').chmod(0o700)
    restarted = None
    if not collector.alive():
        code = collector.stop()
        first = clean_exit(code, collector.stderr())
        collector = Collector(case, 'restart')
        restarted = True
    else:
        first = None
    settled = wait(lambda: records(case) == 2 * ROWS and status(case)['counts']['retained_records'] == 2 * ROWS, 30)
    time.sleep(2)
    leftovers = temporary_outputs(case)
    rows = records(case)
    code = collector.stop()
    result = {'alive_during_fault': alive_during, 'snapshot_preserved_during_fault': preserved, 'first_exit': first,
              'restarted': bool(restarted), 'recovered': settled, 'records': rows, 'temporary_outputs': leftovers,
              'final': clean_exit(code, collector.stderr())}
    result['passed'] = (preserved and settled and rows == 2 * ROWS and not leftovers
                        and (first is None or (first['nonzero'] and first['traceback_free'] and first['actionable'])))
    return result


def unreadable_file(root):
    case = case_dir(root, 'unreadable_file')
    write_log(case / 'input/conn.a.log', 'uf-a')
    collector = started(case)
    blocked = write_log(case / 'input/conn.b.log', 'uf-b')
    blocked.chmod(0)
    write_log(case / 'input/conn.c.log', 'uf-c')
    rejected = wait(lambda: status(case)['scan']['rejections']['access'] >= 1 and records(case) == 2 * ROWS, 20)
    loss = status(case)['input_coverage_loss']
    blocked.chmod(0o600)
    recovered = wait(lambda: records(case) == 3 * ROWS, 20)
    alive = collector.alive()
    rows = records(case)
    code = collector.stop()
    result = {'rejected_as_access_while_other_imported': rejected, 'input_coverage_loss': loss,
              'recovered_exactly_once': recovered and rows == 3 * ROWS, 'records': rows,
              'collector_alive': alive, **clean_exit(code, collector.stderr())}
    result['passed'] = rejected and loss and recovered and rows == 3 * ROWS and alive
    return result


def unreadable_subdir(root):
    case = case_dir(root, 'unreadable_subdir')
    write_log(case / 'input/conn.a.log', 'us-a')
    collector = started(case)
    # Install the unreadable directory atomically, then wait for any healthy
    # tick in flight to finish before capturing bytes the fault must preserve.
    staging = case / 'staging/2026-10-06'
    write_log(staging / 'conn.b.log', 'us-b')
    staging.chmod(0o200)  # Unreadable/unsearchable, yet still movable on Linux.
    dated = case / 'input/2026-10-06'
    staging.rename(dated)
    dated.chmod(0)
    write_log(case / 'input/conn.c.log', 'us-c')
    time.sleep(2)
    before = (case / 'state/connections.json').read_bytes()
    time.sleep(5)
    sibling_rows = records(case) - ROWS
    preserved = (case / 'state/connections.json').read_bytes() == before
    alive_during = collector.alive()
    dated.chmod(0o700)
    first = None
    if not collector.alive():
        first = clean_exit(collector.stop(), collector.stderr())
        collector = Collector(case, 'restart')
    recovered = wait(lambda: records(case) == 3 * ROWS, 30)
    rows = records(case)
    code = collector.stop()
    result = {'alive_during_fault': alive_during, 'sibling_rows_during_fault': sibling_rows,
              'snapshot_preserved_during_fault': preserved, 'first_exit': first, 'recovered': recovered,
              'records': rows, 'final': clean_exit(code, collector.stderr())}
    result['passed'] = (sibling_rows == 0 and preserved and recovered and rows == 3 * ROWS
                        and (first is None or (first['nonzero'] and first['traceback_free'] and first['actionable'])))
    return result


def corrupt_state(root):
    case = case_dir(root, 'corrupt_state')
    write_log(case / 'input/conn.a.log', 'cs-a')
    collector = started(case)
    time.sleep(1)
    collector.stop()
    database = case / 'state/collector.sqlite'
    snapshot = sha(case / 'state/connections.json')
    with database.open('r+b') as file:
        file.write(b'\0' * 100)  # Owned synthetic state only.
    corrupted = sha(database)
    second = Collector(case, 'restart')
    wait(lambda: second.child.poll() is not None, 20)
    code = second.stop()
    result = {'refused': code not in (0, None), **clean_exit(code, second.stderr()),
              'corrupt_database_preserved': database.exists() and sha(database) == corrupted,
              'snapshot_preserved': sha(case / 'state/connections.json') == snapshot}
    result['passed'] = (result['refused'] and result['traceback_free'] and result['actionable']
                        and result['corrupt_database_preserved'] and result['snapshot_preserved'])
    return result


def truncated_gzip(root):
    case = case_dir(root, 'truncated_gzip')
    write_log(case / 'input/conn.a.log', 'tg-a')
    collector = started(case)
    complete = gzip.compress(log('conn', conn_rows('tg-b')).encode())
    partial = case / 'input/conn.b.log.gz'
    partial.write_bytes(complete[:len(complete) // 2])
    partial.chmod(0o600)
    rejected = wait(lambda: status(case)['scan']['rejections']['archive'] >= 1, 20)
    rows_during = records(case)
    loss = status(case)['input_coverage_loss']
    replacement = case / 'input/conn.c.log.gz'
    replacement.write_bytes(complete)
    replacement.chmod(0o600)
    recovered = wait(lambda: records(case) == 2 * ROWS, 20)
    alive = collector.alive()
    rows = records(case)
    code = collector.stop()
    result = {'rejected_as_archive': rejected, 'rows_during_rejection': rows_during, 'input_coverage_loss': loss,
              'replacement_imported_once': recovered and rows == 2 * ROWS, 'collector_alive': alive,
              **clean_exit(code, collector.stderr())}
    result['passed'] = rejected and rows_during == ROWS and loss and recovered and rows == 2 * ROWS and alive
    return result


def expected_rules_missing(root):
    case = case_dir(root, 'expected_rules_missing')
    rules = case / 'expected.json'
    rules.write_text(json.dumps({'schema_version': 1, 'rules': []}))
    rules.chmod(0o600)
    write_log(case / 'input/conn.a.log', 'er-a')
    collector = started(case, '--expected-connections', str(rules))
    time.sleep(2)
    snapshot = sha(case / 'state/connections.json')
    rules.unlink()
    exited = wait(lambda: not collector.alive(), 15)
    first = clean_exit(collector.stop(), collector.stderr())
    preserved = sha(case / 'state/connections.json') == snapshot
    rules.write_text(json.dumps({'schema_version': 1, 'rules': []}))
    rules.chmod(0o600)
    second = Collector(case, 'restart', '--expected-connections', str(rules))
    resumed = wait(lambda: len(second.ticks()) >= 2, 20)
    duplicates = imported(second)
    second.stop()
    result = {'stopped': exited, 'first_exit': first, 'snapshot_preserved': preserved,
              'resumed': resumed, 'restart_new_records': duplicates, 'records': records(case)}
    result['passed'] = (exited and first['nonzero'] and first['traceback_free'] and first['actionable']
                        and preserved and resumed and duplicates == 0 and result['records'] == ROWS)
    return result


def sigterm(root):
    case = case_dir(root, 'sigterm')
    write_log(case / 'input/conn.a.log', 'st-a')
    collector = started(case)
    time.sleep(1)
    started_at = time.monotonic()
    code = collector.stop(signal.SIGTERM)
    elapsed = time.monotonic() - started_at
    valid = isinstance(json.loads((case / 'state/connections.json').read_text()), dict)
    second = Collector(case, 'restart')
    resumed = wait(lambda: len(second.ticks()) >= 2, 20)
    duplicates = imported(second)
    second.stop()
    result = {'exit_code': code, 'stop_seconds': round(elapsed, 3), 'snapshot_valid': valid,
              'resumed': resumed, 'restart_new_records': duplicates, 'traceback_free': 'Traceback' not in collector.stderr()}
    result['passed'] = code == 0 and elapsed <= 15 and valid and resumed and duplicates == 0
    return result


def run(root):
    plan = load_plan(root)
    if (root / 'summary.json').exists():
        raise ValueError('Receipts exist; declare an amendment into a new root')
    results = {}
    for name in plan['cases']:
        started_at = time.monotonic()
        try:
            outcome = globals()[name](root)
        except Exception as error:  # Preserve the failure as an outcome.
            outcome = {'passed': False, 'method_error': f'{type(error).__name__}: {str(error)[:400]}'}
        finally:
            # A failed case must not leave its own collector running.
            outcome_orphans = [c for c in SPAWNED if c.alive()]
            for collector in SPAWNED:
                if not collector.out.closed:
                    collector.stop()
            SPAWNED.clear()
        outcome['orphaned_collectors_stopped'] = len(outcome_orphans)
        outcome['wall_seconds'] = round(time.monotonic() - started_at, 3)
        results[name] = outcome
        write_new(root / f'case-{name}.json', outcome)
        print(json.dumps({name: outcome['passed']}), flush=True)
    load_plan(root)
    summary = {'protocol': PROTOCOL, 'baseline_commit': plan['baseline_commit'],
               'passed': {name: value['passed'] for name, value in results.items()},
               'all_passed': all(value['passed'] for value in results.values()),
               'runtime_changed_from_baseline_commit': subprocess.run(
                   ['git', 'diff', '--quiet', plan['baseline_commit'], '--', 'src/threatfusion'], cwd=REPO).returncode != 0}
    write_new(root / 'summary.json', summary)
    print(json.dumps(summary))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--declare', action='store_true')
    action.add_argument('--run', action='store_true')
    parser.add_argument('--amends', type=Path, help='Earlier private root this amendment preserves')
    parser.add_argument('--reason', help='Declared amendment reason, recorded before outcomes')
    args = parser.parse_args()
    os.umask(0o077)
    root = private_root(args.root)
    declare(root, args.amends, args.reason) if args.declare else run(root)
