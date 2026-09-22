#!/usr/bin/env python3
"""Persistence ordering, barrier failure and interrupted-backend admission (MIT).

Disposable workspaces only. Fault injection is in fixtures or unittest mocks,
never a production environment switch. These tests do not simulate a disk cache.
"""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('durable', SOURCE / 'bin/pki-durable.py')
durable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(durable)


class Barriers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-barriers-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.store = durable.Store(self.root)

    def test_intent_is_persisted_before_admission_and_completion_after_data(self):
        events = []
        with patch.object(durable, 'sync_path', side_effect=lambda path, **kwargs: events.append(path)):
            self.store.begin('123')
            self.assertEqual(events[:3], [self.store.fence, self.store.journal, self.root])
            data = self.root / 'index.txt'
            data.write_text('state')
            events.clear()
            replace = os.replace
            def record_replace(source, target):
                if Path(source) == self.store.fence:
                    self.assertIn(data, events)
                    self.assertIn(self.root, events)
                return replace(source, target)
            with patch.object(os, 'replace', side_effect=record_replace):
                self.store.finish()
        self.assertFalse(self.store.fence.exists())

    def test_failed_flush_preserves_fence_and_prevents_completion(self):
        self.store.begin('123')
        with patch.object(durable, 'sync_path', side_effect=OSError('injected EIO')):
            with self.assertRaises(OSError):
                self.store.finish()
        self.assertTrue(self.store.fence.exists())
        self.store.failure()
        with self.assertRaisesRegex(ValueError, 'manual review'):
            self.store.finish()
        self.assertTrue(self.store.fence.exists())

    def test_ready_alone_cannot_authorize_resume(self):
        self.store.begin('123')
        pending = self.store.journal / 'pending'
        pending.mkdir()
        (pending / 'ready').write_text('checked plan')
        with self.assertRaisesRegex(ValueError, 'checkpoint'):
            self.store.admit()
        self.store.seal()
        self.assertEqual(self.store.admit(), self.store.load()['id'])
        (pending / 'ready').write_text('changed plan')
        with self.assertRaisesRegex(ValueError, 'checkpoint'):
            self.store.admit()

    def test_symlinks_and_special_files_are_not_followed(self):
        (self.root / 'external').symlink_to('/dev/null')
        self.store.begin('123')
        self.store.flush()
        os.mkfifo(self.root / 'fifo')
        with self.assertRaisesRegex(ValueError, 'Unsupported storage'):
            self.store.finish()
        self.assertTrue(self.store.fence.exists())

    def test_platform_barriers_fail_closed(self):
        file = self.root / 'data'
        file.write_text('data')
        with patch.object(durable.sys, 'platform', 'darwin'), \
                patch.object(durable.os, 'fsync') as fsync, \
                patch.object(durable.fcntl, 'F_FULLFSYNC', 51, create=True), \
                patch.object(durable.fcntl, 'fcntl', side_effect=OSError('unsupported flush')) as full:
            with self.assertRaises(OSError):
                durable.sync_path(file, full=True)
            fsync.assert_called_once()
            full.assert_called_once()

    def test_review_can_be_retried_after_persistence_failure(self):
        identity = self.store.begin('123')
        self.store.failure()
        with patch.object(self.store, 'flush', side_effect=OSError('review EIO')):
            with self.assertRaises(OSError):
                self.store.acknowledge(identity, 'Reviewed fixture state')
        self.assertTrue(self.store.fence.exists())
        self.store.acknowledge(identity, 'Reviewed fixture state')
        self.assertFalse(self.store.fence.exists())
        self.assertFalse(self.store.error.exists())
        self.assertTrue((self.store.journal / ('power-loss-reviewed-' + identity)).exists())

    def test_retirement_failure_reestablishes_blocking_state(self):
        self.store.begin('123')
        real_sync = durable.sync_path
        def fail_receipt(path, **kwargs):
            if path.name.startswith('.durable-'):
                raise OSError('retirement EIO')
            real_sync(path, **kwargs)
        with patch.object(durable, 'sync_path', side_effect=fail_receipt):
            with self.assertRaises(OSError):
                self.store.finish()
        self.store.failure()
        self.assertTrue(self.store.fence.exists())
        self.assertTrue(self.store.error.exists())
        with self.assertRaisesRegex(ValueError, 'manual review'):
            self.store.finish()


class Integration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage11-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=180)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args], success, **env)

    def setup_ca(self):
        self.make('root', 'CN=Durable Root')
        self.make('int-web', 'CN=Durable Web')

    def wrapper(self, body):
        path = self.work / 'backend'
        path.write_text('#!/bin/bash\n' + body + '\nexec ' + shlex.quote(self.backend) + ' "$@"\n')
        path.chmod(0o700)
        return str(path)

    def test_intent_precedes_backend_and_normal_exit_clears_it(self):
        wrapper = self.wrapper('''if [[ "$1" == req && " $* " == *" -x509 "* ]]; then
  [[ -s "$ROOT_DIR/.recovery/power-loss" ]] || exit 77
  touch "$ROOT_DIR/observed-fence"
fi''')
        self.make('root', 'CN=Durable Root', OPENSSL=wrapper)
        self.assertTrue((self.work / 'observed-fence').exists())
        self.assertFalse((self.work / '.recovery/power-loss').exists())

    def test_operational_paths_cannot_use_persistence_exclusions(self):
        for path in ('.git/ca.cnf', '.locks/ca.cnf', 'profiles/root/base.cnf'):
            with self.subTest(path=path):
                result = self.make('root', 'CN=Excluded State', 'ROOT_CNF=' + path, success=False)
                self.assertTrue('Reserved non-PKI' in result.stderr or 'Distribution source' in result.stderr,
                                result.stdout + result.stderr)
                self.assertFalse((self.work / 'root/private/ca.key.pem').exists())
        self.assertFalse((self.work / '.git/ca.cnf').exists())
        self.assertFalse((self.work / '.locks/ca.cnf').exists())
        self.assertEqual((self.work / 'profiles/root/base.cnf').read_bytes(),
                         (SOURCE / 'profiles/root/base.cnf').read_bytes())

    def test_power_interruption_without_issuance_journal_blocks_retry(self):
        self.setup_ca()
        self.make('server', 'CN=power.example')
        original_index = (self.work / 'intm-web-ca/index.txt').read_bytes()
        wrapper = self.wrapper('''if [[ "$1" == ca && " $* " == *" -revoke "* ]]; then
  printf 'partial-database-write' > "$ROOT_DIR/intm-web-ca/index.txt"
  kill -KILL "$PPID"
  exit 99
fi''')
        self.make('revoke', 'KIND=web', 'CN=power.example', success=False, OPENSSL=wrapper)
        fence = self.work / '.recovery/power-loss'
        self.assertTrue(fence.exists())
        self.assertFalse((self.work / '.recovery/pending').exists())
        # The killed process is reaped; only its disposable fixture lock is removed.
        shutil.rmtree(self.work / '.locks/root-ca.lock')
        ca = self.work / 'intm-web-ca'
        before = snapshot(ca)
        result = self.make('server', 'CN=retry.example', success=False, PKI_DURABLE_OWNED='spoof')
        self.assertIn('power-loss', result.stderr)
        self.assertEqual(before, snapshot(ca))
        self.run_cmd(['bash', 'bin/recovery.sh'], success=False, RECOVERY_ACTION='resume')
        # Offline fixture reconciliation: no real revocation ran in the wrapper.
        (ca / 'index.txt').write_bytes(original_index)
        identity = json.loads(fence.read_text())['id']
        self.run_cmd(['bash', 'bin/recovery.sh'], RECOVERY_ACTION='acknowledge',
                     RECOVERY_ID=identity, RECOVERY_NOTE='Synthetic truncated index restored from fixture evidence; no backend revocation ran; counters checked.')
        self.assertFalse(fence.exists())
        self.make('server', 'CN=retry.example')

    def test_failed_final_barrier_is_not_success_and_cannot_be_retried(self):
        helper = self.work / 'bin/pki-durable.py'
        helper.write_text(helper.read_text().replace("elif action == 'finish':\n            store.finish()",
                         "elif action == 'finish':\n            raise OSError('injected EIO at commit')"))
        result = self.make('root', 'CN=Durable Root', success=False)
        self.assertIn('injected EIO', result.stderr)
        self.assertNotIn('Local state durably synchronized', result.stderr)
        self.assertTrue((self.work / '.recovery/power-loss').exists())
        self.assertTrue((self.work / '.recovery/power-loss-error').exists())
        helper.write_text((SOURCE / 'bin/pki-durable.py').read_text())
        shutil.rmtree(self.work / '.locks/root-ca.lock')
        result = self.make('int-web', 'CN=blocked', success=False)
        self.assertIn('power-loss', result.stderr)
        self.assertFalse((self.work / 'intm-web-ca').exists())

    def test_failed_intent_barrier_prevents_initialization(self):
        helper = self.work / 'bin/pki-durable.py'
        helper.write_text(helper.read_text().replace('sync_path(self.root)\n        self.device_barrier()',
                         "raise OSError('injected intent EIO')\n        self.device_barrier()"))
        result = self.make('root', 'CN=Never Created', success=False)
        self.assertIn('injected intent EIO', result.stderr)
        self.assertFalse((self.work / 'root').exists())
        self.assertTrue((self.work / '.recovery/power-loss').exists())

    def test_killed_sealed_installation_resumes_without_signing(self):
        self.setup_ca()
        directory = self.work / 'shims'
        directory.mkdir()
        script = directory / 'mv'
        script.write_text('#!/bin/bash\n' + shlex.quote(shutil.which('mv')) + ''' "$@" || exit
if [[ "$*" == *"/certs/sealed.example.cert.pem" ]]; then
  kill -KILL "$PPID"
  exit 99
fi
''')
        script.chmod(0o700)
        self.make('server', 'CN=sealed.example', success=False,
                  PATH=str(directory) + os.pathsep + self.env['PATH'])
        fence = self.work / '.recovery/power-loss'
        self.assertTrue(json.loads(fence.read_text())['ready'])
        shutil.rmtree(self.work / '.locks/root-ca.lock')
        serial = (self.work / 'intm-web-ca/serial').read_bytes()
        self.run_cmd(['bash', 'bin/recovery.sh'], RECOVERY_ACTION='resume')
        self.assertFalse(fence.exists())
        self.assertEqual(serial, (self.work / 'intm-web-ca/serial').read_bytes())
        self.make('verify', 'KIND=web', 'CN=sealed.example')
        # Automatic recovery must finish the old fence before admitting a new
        # signing operation, with exactly one additional serial for that request.
        script.write_text(script.read_text().replace('sealed.example', 'automatic.example'))
        self.make('server', 'CN=automatic.example', success=False,
                  PATH=str(directory) + os.pathsep + self.env['PATH'])
        shutil.rmtree(self.work / '.locks/root-ca.lock')
        next_serial = int((self.work / 'intm-web-ca/serial').read_text(), 16)
        self.make('server', 'CN=after-auto.example', AUTO_RECOVER='1')
        self.assertEqual(next_serial + 1, int((self.work / 'intm-web-ca/serial').read_text(), 16))
        self.assertFalse(fence.exists())
        self.make('verify', 'KIND=web', 'CN=automatic.example')
        # An orderly installation error retires its fence. A subsequent resume
        # must seal a fresh fence before installing, so a second interruption is
        # recoverable too, without treating readiness alone as crash evidence.
        script.write_text('#!/bin/bash\n' + shlex.quote(shutil.which('mv')) + ''' "$@" || exit
if [[ "$*" == *"/certs/repeated.example.cert.pem" ]]; then exit 71; fi
''')
        self.make('server', 'CN=repeated.example', success=False,
                  PATH=str(directory) + os.pathsep + self.env['PATH'])
        self.assertFalse(fence.exists())
        script.write_text('#!/bin/bash\n' + shlex.quote(shutil.which('mv')) + ''' "$@" || exit
if [[ "$*" == *"/certs/repeated.example.fullchain.cert.pem" ]]; then
  kill -KILL "$PPID"
  exit 99
fi
''')
        self.run_cmd(['bash', 'bin/recovery.sh'], success=False, RECOVERY_ACTION='resume',
                     PATH=str(directory) + os.pathsep + self.env['PATH'])
        self.assertTrue(json.loads(fence.read_text())['ready'])
        shutil.rmtree(self.work / '.locks/root-ca.lock')
        serial = (self.work / 'intm-web-ca/serial').read_bytes()
        self.run_cmd(['bash', 'bin/recovery.sh'], RECOVERY_ACTION='resume')
        self.assertFalse(fence.exists())
        self.assertEqual(serial, (self.work / 'intm-web-ca/serial').read_bytes())
        self.make('verify', 'KIND=web', 'CN=repeated.example')


if __name__ == '__main__':
    unittest.main()
