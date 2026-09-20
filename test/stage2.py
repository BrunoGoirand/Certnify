#!/usr/bin/env python3
"""Authority isolation, generations, and transaction regressions."""
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class State(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage2-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.work = self.base / 'work'
        copy_sources(SOURCE, self.work)
        self.env = {'PATH': os.environ['PATH'], 'OPENSSL': os.environ.get('OPENSSL', 'openssl'), 'LC_ALL': 'C'}
        self.make('root', 'CN=State Root')
        self.make('int-web', 'CN=State Web')
        self.make('crl-root')

    def run_command(self, command, success=True, **env):
        r = subprocess.run(command, cwd=self.work, env=dict(self.env, **env), capture_output=True, text=True, timeout=45)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def make(self, *args, success=True, **env):
        return self.run_command(['make', *args, 'KEY_ALG=EC'], success, **env)

    def test_rollover_legacy_crl_revoke_and_rollback(self):
        self.make('server', 'CN=old.example')
        self.make('rollover-web', 'INT_CN=State Web v2')
        legacy = next(self.work.glob('intm-web-ca-legacy-*'))
        active = self.work / 'intm-web-ca'
        self.assertIn(str(legacy), (legacy / 'openssl.cnf').read_text())
        self.make('server', 'CN=new.example')
        before = snapshot(active)
        self.make('crl', 'INT_DIR=' + str(legacy))
        self.make('revoke', 'INT_DIR=' + str(legacy), 'CN=old.example')
        self.assertEqual(before, snapshot(active))
        self.make('verify', 'INT_DIR=' + str(legacy), 'CN=old.example', 'VERIFY_CRL=1', 'VERIFY_MODE=info')
        self.make('rollback-web')
        backup = next(self.work.glob('intm-web-ca-pre-rollback-*'))
        self.assertIn(str(backup), (backup / 'openssl.cnf').read_text())
        self.assertIn(str(active), (active / 'openssl.cnf').read_text())
        self.assertTrue((active / 'ca.meta').exists())
        self.assertEqual(os.readlink(active / 'certs/chain.cert.pem'), 'ca.chain.cert.pem')
        self.make('verify', 'INT_DIR=' + str(backup), 'CN=new.example')

    def test_in_place_rekey_keeps_historical_signer(self):
        self.make('server', 'CN=historical.example')
        ca = self.work / 'intm-web-ca'
        binding = (ca / 'issuers/1000').read_text().splitlines()[0]
        old_key = (ca / 'generations' / binding / 'ca.key.pem').read_bytes()
        self.make('int-web', 'CN=State Web', 'ROTATE_KEY=1')
        self.assertEqual(old_key, (ca / 'generations' / binding / 'ca.key.pem').read_bytes())
        self.make('verify', 'KIND=web', 'CN=historical.example')
        self.make('revoke', 'KIND=web', 'CN=historical.example')
        self.assertTrue((ca / 'generations' / binding / 'ca.crl.pem').is_file())
        self.make('server', 'CN=current.example')
        self.make('verify', 'KIND=web', 'CN=current.example')
        (ca / 'generations' / binding / 'ca.cert.pem').unlink()
        self.make('verify', 'KIND=web', 'CN=historical.example', success=False)

    def test_absolute_nested_alias_paths_and_external_rejection(self):
        nested = self.work / 'pki-data/team'
        self.make('intermediate', 'INT_DIR=' + str(nested), 'CN=Nested CA')
        (self.work / 'team-alias').symlink_to(nested, target_is_directory=True)
        self.make('server', 'INT_DIR=team-alias', 'CN=nested.example')
        self.make('verify', 'INT_DIR=' + str(nested), 'CN=nested.example')
        self.make('crl', 'INT_DIR=team-alias')
        outside = self.base / 'outside'
        outside.mkdir()
        (self.work / 'outside-alias').symlink_to(outside, target_is_directory=True)
        self.make('intermediate', 'INT_DIR=outside-alias', 'CN=Escape', success=False)
        self.assertEqual(list(outside.iterdir()), [])
        # Wrong config binding must fail before any CA state mutation.
        cnf = nested / 'openssl.cnf'
        cnf.write_text(cnf.read_text().replace(str(nested), str(self.work / 'intm-web-ca')))
        before = snapshot(nested)
        self.make('crl', 'INT_DIR=' + str(nested), success=False)
        self.assertEqual(before, snapshot(nested))

    def test_legacy_layout_and_rollback_backup_collision(self):
        import shutil
        self.make('server', 'CN=import.example')
        self.make('rollover-web', 'INT_CN=Replacement')
        legacy = next(self.work.glob('intm-web-ca-legacy-*'))
        # Simulate old rollover artifacts, retaining only key/certificate/index.
        shutil.rmtree(legacy / 'generations')
        shutil.rmtree(legacy / 'issuers')
        (legacy / 'ca.meta').rename(legacy / 'meta')
        (legacy / 'serial.last').unlink()
        (legacy / 'certs/chain.cert.pem').unlink()
        (legacy / 'certs/ca.chain.cert.pem').rename(legacy / 'certs/chain.cert.pem')
        fakebin = self.base / 'fakebin'
        fakebin.mkdir()
        date = fakebin / 'date'
        date.write_text('#!/bin/bash\nif [[ "$1" == +%Y%m%d%H%M%S ]]; then echo 20000101000000; else exec /bin/date "$@"; fi\n')
        date.chmod(0o700)
        collision = self.work / 'intm-web-ca-pre-rollback-20000101000000'
        collision.mkdir(); (collision / 'sentinel').write_text('keep')
        self.make('rollback-web', 'LEGACY_DIR=' + str(legacy), PATH=str(fakebin) + ':' + self.env['PATH'])
        self.assertEqual((collision / 'sentinel').read_text(), 'keep')
        self.assertTrue((self.work / (collision.name + '-1')).is_dir())
        self.make('verify', 'KIND=web', 'CN=import.example')
        self.assertTrue((self.work / 'intm-web-ca/ca.meta').is_file())
        self.assertTrue((self.work / 'intm-web-ca/issuers/1000').is_file())

    def test_concurrent_issue_revoke_and_crl(self):
        self.make('server', 'CN=revoke.example')
        commands = [['make', 'server', 'CN=survivor.example', 'KEY_ALG=EC'],
                    ['make', 'revoke', 'KIND=web', 'CN=revoke.example'],
                    ['make', 'crl', 'KIND=web']]
        processes = [subprocess.Popen(c, cwd=self.work, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) for c in commands]
        for proc in processes:
            out, _ = proc.communicate(timeout=45)
            self.assertEqual(proc.returncode, 0, out)
        self.make('verify', 'KIND=web', 'CN=survivor.example')
        r = self.make('verify', 'KIND=web', 'CN=revoke.example', 'VERIFY_CRL=1', 'VERIFY_MODE=info')
        self.assertIn('VERIFY STATUS: REVOKED', r.stdout)
        self.make('revoke-intermediate', 'KIND=web')
        self.make('server', 'CN=blocked.example', success=False)

    def test_concurrent_writers_and_lock_timeout(self):
        (self.work / 'web-alias').symlink_to('intm-web-ca', target_is_directory=True)
        commands = [ ['make', 'server', 'CN=parallel%d.example' % i, 'KEY_ALG=EC',
                      'INT_DIR=' + ('web-alias' if i % 2 else 'intm-web-ca')] for i in range(3) ]
        processes = [subprocess.Popen(c, cwd=self.work, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) for c in commands]
        for proc in processes:
            out, _ = proc.communicate(timeout=45)
            self.assertEqual(proc.returncode, 0, out)
        rows = (self.work / 'intm-web-ca/index.txt').read_text().splitlines()
        self.assertEqual(len({r.split('\t')[3] for r in rows}), 3)
        holder = subprocess.Popen(['bash', '-c', 'source bin/pki-env.sh; pki_begin; echo READY; sleep 3'],
                                  cwd=self.work, env=self.env, stdout=subprocess.PIPE, text=True)
        self.assertEqual(holder.stdout.readline().strip(), 'READY')
        before = snapshot(self.work / 'intm-web-ca')
        self.make('crl', 'KIND=web', 'LOCK_TIMEOUT=0', success=False)
        self.assertEqual(before, snapshot(self.work / 'intm-web-ca'))
        holder.wait(timeout=10)
        holder.stdout.close()
        self.assertFalse((self.work / '.locks/root-ca.lock').exists())
        lock = self.work / '.locks/root-ca.lock'
        lock.mkdir(); (lock / 'pid').write_text('999999999\n')
        self.make('crl', 'KIND=web', 'LOCK_TIMEOUT=0', success=False)
        self.assertTrue(lock.exists())  # Never steal allegedly abandoned locks.


if __name__ == '__main__':
    unittest.main(verbosity=2)
