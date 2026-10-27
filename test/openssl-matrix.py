#!/usr/bin/env python3
"""Opt-in backend compatibility matrix; explicit executables, disposable PKIs.

JSONL contains identities and outcomes, never fixture keys, recovery journals or
captured test output. Rerun a failed test directly for its local diagnostics.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent
COMMON = (
    ('backend-contract.py', 'Backend.test_crl_signature_issuer_and_time_boundaries'),
    ('stage4.py', 'Revocation.test_strict_coverage'),
    ('stage4.py', 'Revocation.test_backend_status_overrides_misleading_output'),
    ('stage5.py', 'Policy.test_effective_key_metadata_matrix'),
    ('stage8.py', 'Operations.test_application_identity_purpose_and_strict_crls'),
    ('stage12.py', 'IssuanceCategories.test_compiled_custom_profiles_missing_multiple_and_oid_alias_ekus'),
)
OPENSSL3 = ('stage9.py', 'Migration.test_complete_subject_sans_curve_fresh_key_dry_run_and_retry')
OUTPUT_LOCK = threading.Lock()


def clean_env(backend):
    env = {key: os.environ[key] for key in ('PATH', 'TMPDIR') if key in os.environ}
    env.update(OPENSSL=backend, LC_ALL='C')
    return env


def emit(record):
    with OUTPUT_LOCK:
        print(json.dumps(record, sort_keys=True), flush=True)


def check_backend(candidate):
    backend, version, accepted = candidate
    env = clean_env(backend)
    failures = 0
    with tempfile.TemporaryDirectory(prefix='certnify-openssl-matrix-') as directory:
        work = Path(directory) / 'work'
        copy_sources(SOURCE, work)
        before = snapshot(work)
        if accepted:
            commands = [['/bin/bash', '-c', 'source bin/pki-env.sh']]
        else:
            commands = [['make', 'root', 'CN=Rejected Backend', 'KEY_ALG=EC'],
                        ['bin/gen-root.sh']]
        for command in commands:
            result = subprocess.run(command, cwd=work,
                                    env=dict(env, CN='Rejected Backend', KEY_ALG='EC'),
                                    capture_output=True, text=True, timeout=30)
            correct_status = (result.returncode == 0) == accepted
            rejected_by_gate = accepted or ('[ERR]' in result.stderr and
                                           ('OpenSSL' in result.stderr or 'LibreSSL' in result.stderr))
            passed = correct_status and rejected_by_gate and snapshot(work) == before
            emit(dict(type='admission', backend=backend, command=command,
                      expected='accept' if accepted else 'reject', passed=passed,
                      returncode=result.returncode))
            failures += int(not passed)
    if not accepted or failures:
        return failures
    selection = list(COMMON)
    if re.match(r'^OpenSSL 3\.', version):
        selection.append(OPENSSL3)
    else:
        emit(dict(type='not_applicable', backend=backend, test=list(OPENSSL3),
                  reason='Preserving migration requires OpenSSL 3.x; not qualification evidence'))
    for script, method in selection:
        started = time.monotonic()
        # Own the temporary tree and process group so a timeout cannot leave
        # fixture children writing after cleanup of their private test data.
        with tempfile.TemporaryDirectory(prefix='certnify-matrix-case-') as directory:
            with subprocess.Popen([sys.executable, '-B', str(SOURCE / 'test' / script), method],
                                  cwd=SOURCE, env=dict(env, TMPDIR=directory),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, start_new_session=True) as process:
                try:
                    process.communicate(timeout=600)
                    passed, status = process.returncode == 0, process.returncode
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    passed, status = False, 'timeout'
        emit(dict(type='test', backend=backend, test=[script, method], passed=passed,
                  returncode=status, seconds=round(time.monotonic() - started, 3)))
        failures += int(not passed)
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', action='append', default=[], help='Explicit accepted executable path; repeatable')
    parser.add_argument('--reject-backend', action='append', default=[], help='Executable expected to fail admission; repeatable')
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=1,
                        help='Concurrent backend workers (1–4); tests within a backend remain serial')
    args = parser.parse_args()
    if not args.backend and not args.reject_backend:
        parser.error('Specify at least one --backend or --reject-backend')
    os.umask(0o077)
    candidates, identities, aliases = [], [], []
    seen = {}
    for value, accepted in [(v, True) for v in args.backend] + [(v, False) for v in args.reject_backend]:
        path = Path(value).expanduser().resolve(strict=True)
        if not path.is_file() or not os.access(str(path), os.X_OK):
            parser.error('Not an executable file: ' + value)
        key = str(path)
        if key in seen:
            if seen[key] != accepted:
                parser.error('Conflicting expectations for aliases of ' + key)
            aliases.append(dict(type='alias', requested=value, backend=key,
                                reason='Same real executable; not another tested version'))
            continue
        seen[key] = accepted
        version = subprocess.check_output([key, 'version'], env=clean_env(key), text=True, timeout=10).strip()
        candidates.append((key, version, accepted))
        identities.append(dict(type='backend', backend=key, version=version,
                               expected='accept' if accepted else 'reject',
                               sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    emit(dict(type='environment', platform=platform.platform(), python=sys.version.split()[0],
              jobs=args.jobs, accepted_backends=sum(c[2] for c in candidates),
              rejected_backends=sum(not c[2] for c in candidates)))
    for record in identities + aliases:
        emit(record)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        failures = sum(pool.map(check_backend, candidates))
    emit(dict(type='summary', failures=failures, passed=failures == 0))
    return int(failures != 0)


if __name__ == '__main__':
    sys.exit(main())
