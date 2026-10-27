#!/usr/bin/env python3
"""Measure retained-history cost in real preserving batches, in disposable PKIs.

No production hooks or skipped barriers. JSON output contains aggregate timings
and counts only; fixture keys, journals and command output are never exported.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

from workspace import copy_sources

SOURCE = Path(__file__).resolve().parent.parent

# Injected only into the manifest-copied helper after fixture preparation. The
# sibling log is outside the measured workspace, so it cannot amplify the walk.
PROBE = '''
import atexit
import time
_metrics = dict(action=sys.argv[1], trees=0, tree_seconds=0.0,
                sync_calls=0, sync_seconds=0.0, full_calls=0, history_syncs=0)
_real_sync_path = sync_path
_real_sync_tree = sync_tree
def _measured_sync_path(path, full=False):
    started = time.perf_counter()
    try:
        return _real_sync_path(path, full=full)
    finally:
        _metrics['sync_seconds'] += time.perf_counter() - started
        _metrics['sync_calls'] += 1
        _metrics['full_calls'] += int(full)
        _metrics['history_syncs'] += int(path.name.startswith('history-record-'))
def _measured_sync_tree(root):
    started = time.perf_counter()
    try:
        return _real_sync_tree(root)
    finally:
        _metrics['tree_seconds'] += time.perf_counter() - started
        _metrics['trees'] += 1
def _save_metrics():
    with open(LOG_PATH, 'a') as stream:
        stream.write(json.dumps(_metrics) + '\\n')
sync_path = _measured_sync_path
sync_tree = _measured_sync_tree
atexit.register(_save_metrics)
'''


def run(work, env, command):
    result = subprocess.run(command, cwd=work, env=env, capture_output=True,
                            text=True, timeout=1800)
    if result.returncode:
        # Do not export arbitrary backend output or recovery diagnostics.
        raise RuntimeError('Fixture command failed (exit {}): {}'.format(
            result.returncode, ' '.join(command)))
    return result.stdout


def sample(env, rows, history, record_bytes):
    with tempfile.TemporaryDirectory(prefix='certnify-durability-bench-') as directory:
        base = Path(directory).resolve()
        work = base / 'work'
        copy_sources(SOURCE, work)
        run(work, env, ['make', 'root', 'CN=Benchmark Root'])
        run(work, env, ['make', 'int-web', 'CN=Benchmark Web'])
        for row in range(rows):
            run(work, env, ['make', 'server', 'CN=bench-{}.example.test'.format(row)])
        run(work, env, ['make', 'rollover-web', 'INT_CN=Benchmark Replacement'])
        run(work, env, ['make', 'list-leafs-web'])

        # Synthetic immutable history isolates entry count from batch size.
        # Real retained issuer state and issuance journals also remain in place.
        payload = b'x' * record_bytes
        for index in range(history):
            target = work / 'pki-data' / 'benchmark-history' / str(index // 100)
            target.mkdir(parents=True, exist_ok=True)
            (target / ('history-record-' + str(index))).write_bytes(payload)
        # Persist fixture setup before timing; this is a warm-cache measurement.
        run(work, env, [sys.executable, '-B', 'bin/pki-durable.py', 'flush', str(work)])

        log = base / 'metrics.jsonl'
        helper = work / 'bin/pki-durable.py'
        source = helper.read_text()
        marker = "if __name__ == '__main__':"
        if source.count(marker) != 1:
            raise RuntimeError('Durability helper entry point changed; review benchmark probe')
        helper.write_text(source.replace(marker,
                          PROBE.replace('LOG_PATH', repr(str(log))) + '\n' + marker))
        started = time.perf_counter()
        output = run(work, env, ['make', 'reissue-leafs-web'])
        elapsed = time.perf_counter() - started
        expected = 'total={} completed={} already_completed=0 planned=0 failed=0'.format(rows, rows)
        if expected not in output:
            raise RuntimeError('Batch did not complete every requested row')
        events = [json.loads(line) for line in log.read_text().splitlines()]
        totals = {key: sum(event[key] for event in events) for key in
                  ('trees', 'tree_seconds', 'sync_calls', 'sync_seconds',
                   'full_calls', 'history_syncs')}
        if not totals['trees'] or totals['history_syncs'] != history * totals['trees']:
            raise RuntimeError('History persistence coverage differs from full-tree protocol')
        actions = {}
        for event in events:
            actions[event['action']] = actions.get(event['action'], 0) + 1
        ca = work / 'intm-web-ca'
        receipts = list((ca / 'reissues').iterdir())
        if len(receipts) != rows or any(p.read_text() != 'completed\n' for p in receipts):
            raise RuntimeError('Incomplete batch receipts')
        if len((ca / 'index.txt').read_text().splitlines()) != rows:
            raise RuntimeError('Unexpected destination issuance count')
        for name in ('pending', 'power-loss', 'power-loss-error'):
            if (work / '.recovery' / name).exists():
                raise RuntimeError('Unexpected blocking recovery state')
        # Verify the resulting chain outside the measured interval/probe totals.
        for row in range(rows):
            run(work, env, ['make', 'verify', 'KIND=web',
                           'CN=bench-{}.example.test'.format(row)])
        return dict(rows=rows, history_files=history, history_bytes=history * record_bytes,
                    batch_seconds=elapsed, actions=actions, **totals)


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('must be nonnegative')
    return number


def positive(value):
    number = nonnegative(value)
    if not number:
        raise argparse.ArgumentTypeError('must be positive')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rows', type=positive, nargs='+', default=[1, 3])
    parser.add_argument('--history-files', type=nonnegative, nargs='+', default=[0, 100, 1000])
    parser.add_argument('--record-bytes', type=positive, default=4096)
    parser.add_argument('--repeat', type=positive, default=3)
    args = parser.parse_args()
    os.umask(0o077)
    backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
    if backend is None:
        parser.error('OpenSSL executable not found')
    env = {key: os.environ[key] for key in ('PATH', 'TMPDIR') if key in os.environ}
    env.update(OPENSSL=backend, LC_ALL='C', KEY_ALG='EC')
    # Runtime helpers call python3; ensure it is the interpreter reported here.
    runtime = subprocess.check_output(['python3', '-c', 'import sys; print(sys.executable)'],
                                      env=env, text=True).strip()
    if Path(runtime).resolve() != Path(sys.executable).resolve():
        parser.error('Run with the python3 selected by PATH')
    version = subprocess.check_output([backend, 'version'], env=env, text=True).strip()
    if not version.startswith('OpenSSL 3.'):
        parser.error('Preserving batch benchmark requires OpenSSL 3.x; found ' + version)
    metadata = dict(type='environment', platform=platform.platform(), python=sys.version.split()[0],
                    openssl=version, record_bytes=args.record_bytes,
                    instrumented=True, warm_cache=True,
                    source_sha256={name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest()
                                   for name in ('bin/pki-durable.py', 'bin/intm-reissue-leafs.sh')})
    print(json.dumps(metadata), flush=True)
    for repeat in range(args.repeat):
        for rows in args.rows:
            # Alternate history order to reduce systematic warmup/order bias.
            histories = args.history_files if repeat % 2 == 0 else list(reversed(args.history_files))
            for history in histories:
                print('Measuring repeat={} rows={} history={}'.format(repeat + 1, rows, history),
                      file=sys.stderr, flush=True)
                result = sample(env, rows, history, args.record_bytes)
                print(json.dumps(dict(type='sample', repeat=repeat + 1, **result)), flush=True)


if __name__ == '__main__':
    main()
