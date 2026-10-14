#!/usr/bin/env python3
"""RIS-02/03/04 regression tests; disposable workspaces and local remote adapter."""
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('durable13', SOURCE / 'bin/pki-durable.py')
durable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(durable)


class Scope(unittest.TestCase):
    def test_publication_deadline_is_shared_and_cancellation_reaps_children(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ('one', 'two'):
                (root / name).write_text('bytes')
            command = [sys.executable, '-B', str(SOURCE / 'bin/pki-publish.py'), 'one', 'two']
            env = dict(os.environ, ALLOW_ADMIN_HOOKS='1', PUBLISH_TIMEOUT='2',
                       PUBLISH_CMD='printf upload-log; sleep 0.6', PUBLISH_FETCH_CMD='sleep 0.6; cat %FILE%')
            start = time.monotonic()
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('artifact=one status=verified', result.stdout)
            self.assertNotIn('upload-log', result.stdout)
            self.assertIn('upload-log', result.stderr)
            self.assertIn('deadline exceeded', result.stderr)
            self.assertLess(time.monotonic() - start, 8)
            env.update(PUBLISH_CMD='echo ready > ready; sleep 2; touch leaked', PUBLISH_TIMEOUT='60')
            process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not (root / 'ready').exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue((root / 'ready').exists())
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=5)
                self.assertNotEqual(process.returncode, 0)
                time.sleep(2.1)
                self.assertFalse((root / 'leaked').exists())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_annexes_are_not_synced_but_all_operational_history_is(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            notes = root / 'notes'
            notes.mkdir()
            os.mkfifo(notes / 'pipe')
            for i in range(100):
                (notes / str(i)).write_text('ancillary')
            for name in ('custom/nested/ca/generations/old/private/key.pem',
                         '.recovery/pending/evidence', 'out/inventory.tsv'):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('operational')
            events = []
            with patch.object(durable, 'sync_path', side_effect=lambda p, **kw: events.append(p)):
                durable.sync_tree(root)
            self.assertFalse(any(notes == p or notes in p.parents for p in events))
            self.assertIn(root / 'custom/nested/ca/generations/old/private/key.pem', events)
            self.assertIn(root / '.recovery/pending/evidence', events)
            self.assertIn(root / 'out/inventory.tsv', events)
            (notes / 'old-ca').mkdir()
            (notes / 'old-ca/index.txt').write_text('')
            with self.assertRaisesRegex(ValueError, 'Authority state'):
                durable.Store(root).begin('123')
            self.assertFalse((root / '.recovery').joinpath('power-loss').exists())

    def test_preflight_io_failure_creates_no_fence(self):
        with tempfile.TemporaryDirectory() as folder:
            store = durable.Store(folder)
            with patch.object(durable, 'sync_path', side_effect=OSError('preflight EIO')):
                with self.assertRaisesRegex(OSError, 'preflight EIO'):
                    store.begin('123')
            self.assertFalse(store.journal.exists())


class Security(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage13-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.env = dict(PATH=os.environ['PATH'], LC_ALL='C', KEY_ALG='EC',
                        OPENSSL=shutil.which(os.environ.get('OPENSSL', 'openssl')))

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args], success, **env)

    def setup_ca(self):
        self.make('root', 'CN=Security Root')
        self.make('int-web', 'CN=Security Web')
        self.ca = self.work / 'intm-web-ca'

    def final(self, success=True, **env):
        return self.run_cmd(['bash', 'bin/intm-publish-final-crl.sh'], success,
                            KIND='web', **env)

    def test_hooks_disabled_before_any_mutation_and_make_values_literal(self):
        before = snapshot(self.work)
        for variable in ('ISSUE_CMD', 'PUBLISH_CMD', 'PUBLISH_FETCH_CMD'):
            result = self.make('root', 'CN=Blocked', success=False,
                               **{variable: 'touch executed'})
            self.assertIn('ALLOW_ADMIN_HOOKS=1', result.stderr)
            self.assertEqual(before, snapshot(self.work))
        self.make('root', 'CN=Blocked', 'PUBLISH_FETCH_CMD=$(shell touch injected)', success=False)
        self.assertEqual(before, snapshot(self.work))

    def test_annex_fifo_succeeds_operational_fifo_fails_before_mutation(self):
        notes = self.work / 'notes'
        notes.mkdir()
        os.mkfifo(notes / 'pipe')
        self.make('root', 'CN=FIFO Root')
        for path in ('notes/ca', 'draft/ca', 'image/ca', '.vscode/ca'):
            result = self.make('int-web', 'INT_DIR=' + path, 'CN=Reserved', success=False)
            self.assertIn('Reserved ancillary', result.stderr)
        (self.work / 'annex-alias').symlink_to('notes', target_is_directory=True)
        self.make('int-web', 'INT_DIR=annex-alias/ca', 'CN=Reserved', success=False)
        fifo = self.work / 'root/private/pipe'
        os.mkfifo(fifo)
        result = self.make('int-web', 'CN=Never Created', success=False)
        self.assertIn('Unsupported storage', result.stderr)
        self.assertFalse((self.work / 'intm-web-ca').exists())
        self.assertFalse((self.work / '.recovery/power-loss').exists())
        self.assertFalse((self.work / '.locks/root-ca.lock').exists())
        fifo.unlink()
        self.make('int-web', 'CN=Now Created')

    def test_publication_requires_fetch_before_generation(self):
        self.setup_ca()
        before = snapshot(self.ca)
        self.final(success=False, ALLOW_ADMIN_HOOKS='1', PUBLISH_CMD='true')
        for timeout in ('0', '-1', '3601', 'nan', '1.5'):
            self.final(success=False, ALLOW_ADMIN_HOOKS='1', PUBLISH_CMD='true',
                       PUBLISH_FETCH_CMD='true', PUBLISH_TIMEOUT=timeout)
        self.assertEqual(before, snapshot(self.ca))

    def test_false_success_timeout_and_verified_idempotent_retry(self):
        self.setup_ca()
        remote = Path(self.temp.name) / 'remote'
        remote.mkdir()
        fetch = 'cat ' + shlex.quote(str(remote)) + '/%FILE%'
        config = dict(ALLOW_ADMIN_HOOKS='1', PUBLISH_FETCH_CMD=fetch)
        result = self.final(success=False, PUBLISH_CMD='true', **config)
        self.assertNotIn('published and read-back verified', result.stdout)
        pem = next((self.ca / 'crl').glob('ca-*.crl.pem'))
        counter = (self.ca / 'crlnumber').read_bytes()
        config['FINAL_CRL'] = str(pem)
        start = time.monotonic()
        result = self.final(success=False, PUBLISH_CMD='sleep 30 & wait', PUBLISH_TIMEOUT='1', **config)
        self.assertLess(time.monotonic() - start, 15)
        self.assertIn('deadline exceeded', result.stderr)
        self.assertFalse((self.work / '.locks/root-ca.lock').exists())
        self.assertFalse((self.work / '.recovery/power-loss').exists())
        publish = 'cp -fL %FILE% ' + shlex.quote(str(remote)) + '/'
        for bad_fetch in ('printf wrong', 'sleep 30', 'yes x', 'cat %FILE%; exit 7'):
            bad = dict(config, PUBLISH_FETCH_CMD=bad_fetch)
            self.final(success=False, PUBLISH_CMD=publish, PUBLISH_TIMEOUT='1', **bad)
        result = self.final(PUBLISH_CMD=publish, **config)
        self.assertIn('All six CRL artifacts published and read-back verified', result.stdout)
        self.final(PUBLISH_CMD=publish, **config)
        self.assertEqual(counter, (self.ca / 'crlnumber').read_bytes())
        self.assertEqual((remote / 'ca.crl.pem').read_bytes(), pem.read_bytes())
        self.assertEqual(len(list(remote.iterdir())), 6)


if __name__ == '__main__':
    unittest.main(verbosity=2)
