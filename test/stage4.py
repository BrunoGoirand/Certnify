#!/usr/bin/env python3
"""Strict verification, read-only plans and safe CRL replacement."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Revocation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage4-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = {'PATH': os.environ['PATH'], 'OPENSSL': self.backend, 'LC_ALL': 'C'}
        self.make('root', 'CN=CRL Root')
        self.make('int-web', 'CN=CRL Issuer')
        self.make('server', 'CN=leaf.example')
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, cmd, success=True, **env):
        r = subprocess.run(cmd, cwd=self.work, env=dict(self.env, **env), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args, 'KEY_ALG=EC'], success, **env)

    def wrapper(self, body):
        p = self.work / 'probe-openssl'
        p.write_text('#!/bin/bash\n' + body + '\nexec ' + shlex.quote(self.backend) + ' "$@"\n')
        p.chmod(0o700)
        return str(p)

    def verify(self, success=True, mode='normal', **env):
        return self.make('verify', 'KIND=web', 'CN=leaf.example', 'VERIFY_CRL=1', 'VERIFY_MODE=' + mode, success=success, **env)

    def crls(self):
        self.make('crl-root')
        self.make('crl', 'KIND=web')

    def test_strict_coverage(self):
        self.verify(False)
        self.make('crl-root')
        self.verify(False, mode='info')  # Missing required coverage is an input error.
        root = self.work / 'root/crl/ca.crl.pem'
        saved = root.read_bytes(); root.unlink()
        self.make('crl', 'KIND=web')
        self.verify(False, mode='tolerate_revoked')
        root.write_bytes(saved)
        self.assertIn('VERIFY STATUS: OK', self.verify().stdout)
        self.make('revoke', 'KIND=web', 'CN=leaf.example')
        self.assertIn('VERIFY STATUS: REVOKED', self.verify(False).stdout)
        self.verify(mode='tolerate_revoked')
        self.verify(mode='info')
        self.make('revoke-intermediate', 'KIND=web')
        self.assertIn('VERIFY STATUS: REVOKED', self.verify(mode='info').stdout)

    def test_invalid_crls_never_tolerated(self):
        self.crls()
        crl = self.ca / 'crl/ca.crl.pem'
        valid = crl.read_bytes()
        crl.chmod(0o600)  # Corrupt only this disposable read-only fixture.
        crl.write_bytes((self.work / 'root/crl/ca.crl.pem').read_bytes())
        self.verify(False, mode='info')
        crl.write_bytes(valid)
        self.run_cmd([self.backend, 'crl', '-in', str(crl), '-badsig', '-out', 'bad.crl'])
        crl.write_bytes((self.work / 'bad.crl').read_bytes())
        self.verify(False, mode='tolerate_revoked')
        for start, end in [('20000101000000Z', '20000102000000Z'), ('20990101000000Z', '20990102000000Z')]:
            self.run_cmd([self.backend, 'ca', '-batch', '-config', str(self.ca / 'openssl.cnf'), '-gencrl', '-crl_lastupdate', start, '-crl_nextupdate', end, '-out', str(crl)])
            self.verify(False, mode='info')
        crl.write_text('malformed\n')
        self.verify(False)

    def test_backend_status_overrides_misleading_output(self):
        self.crls()
        wrapper = self.wrapper('if [[ "$1" == verify && " $* " == *" -verbose "* ]]; then printf "%s: OK\\n" "${!#}"; exit 9; fi')
        r = self.make('verify', 'KIND=web', 'CN=leaf.example', success=False, OPENSSL=wrapper)
        self.assertIn('VERIFY STATUS: ERROR', r.stdout)
        self.make('verify', 'KIND=web', 'CN=leaf.example', 'VERIFY_MODE=tolerate_revoked', success=False, OPENSSL=wrapper)
        self.make('verify', 'KIND=web', 'CN=leaf.example', 'VERIFY_MODE=info', OPENSSL=wrapper)
        path = self.ca / 'certs/certificate revoked [.*].pem'
        shutil.copyfile(self.ca / 'certs/leaf.example.cert.pem', path)
        self.make('verify', 'KIND=web', 'FILE=' + str(path), success=False, OPENSSL=wrapper)
        path.write_text('not a certificate')
        self.make('verify', 'KIND=web', 'FILE=' + str(path), success=False)

    def test_expired_chain_failure_is_not_tolerated(self):
        self.crls()
        self.run_cmd([self.backend, 'ca', '-batch', '-config', str(self.ca / 'openssl.cnf'),
                      '-in', str(self.ca / 'csr/leaf.example.csr.pem'), '-subj', '/CN=expired.example',
                      '-extensions', 'server_ec', '-startdate', '20000101000000Z', '-enddate', '20010101000000Z',
                      '-out', str(self.ca / 'certs/expired.example.cert.pem')])
        for mode, success in [('normal', False), ('tolerate_revoked', False), ('info', True)]:
            r = self.make('verify', 'KIND=web', 'CN=expired.example', 'VERIFY_MODE=' + mode, 'VERIFY_CRL=1', success=success)
            self.assertIn('VERIFY STATUS: ERROR', r.stdout)

    def test_dry_runs_leave_no_lock_or_state(self):
        self.crls()
        shutil.rmtree(self.work / '.locks')
        (self.work / 'batch.tsv').write_text('1000\t2030-01-01T00:00:00Z\tplan.example\t\n')
        before = snapshot(self.work)
        self.make('revoke', 'KIND=web', 'CN=leaf.example', 'DRY_RUN=1')
        self.make('revoke-intermediate', 'KIND=web', 'DRY_RUN=1')
        self.make('revoke-intm-and-leafs', 'KIND=web', 'DRY_RUN=1')
        self.make('reissue-leafs-web', 'INPUT=batch.tsv', 'DRY_RUN=1')
        self.assertEqual(before, snapshot(self.work))
        self.assertFalse((self.work / '.locks').exists())

    def test_idempotence_refresh_and_unsupported_release(self):
        self.crls()
        for target in [('revoke', 'KIND=web', 'CN=leaf.example'), ('revoke-intermediate', 'KIND=web'), ('revoke-intm-and-leafs', 'KIND=web')]:
            before = snapshot(self.work)
            self.make(*target, 'REASON=removeFromCRL', success=False)
            self.make(*target, 'REASON=privilegeWithdrawn', 'MAP_PRIV_WITHDRAWN_TO=removeFromCRL', success=False)
            self.assertEqual(before, snapshot(self.work))
        self.make('revoke', 'KIND=web', 'CN=leaf.example', 'CRL_UPDATE=0')
        before = snapshot(self.ca)
        self.make('revoke', 'KIND=web', 'CN=leaf.example', 'CRL_UPDATE=0')
        self.assertEqual(before, snapshot(self.ca))
        counter = (self.ca / 'crlnumber').read_text()
        self.make('revoke', 'KIND=web', 'CN=leaf.example', 'CRL_UPDATE=1')
        self.assertNotEqual(counter, (self.ca / 'crlnumber').read_text())
        self.make('revoke-intermediate', 'KIND=web', 'CRL_UPDATE=0')
        before = snapshot(self.work)
        self.make('revoke-intermediate', 'KIND=web', 'CRL_UPDATE=0')
        self.assertEqual(before, snapshot(self.work))
        self.make('revoke-intm-and-leafs', 'KIND=web', 'LEAF_STATUSES=R', 'CRL_UPDATE=1')

    def test_failed_generation_preserves_installed_crls(self):
        self.crls()
        self.run_cmd(['bash', 'bin/intm-publish-final-crl.sh'], KIND='web', ALLOW_REMAINING_LEAFS='1')
        self.assertTrue((self.ca / 'crl/ca.crl.pem').is_symlink())
        self.verify()  # The normal final-CRL path also installs a valid list.
        old = (self.ca / 'crl/ca.crl.pem').read_bytes()
        for mode in ['exit 17', 'for ((i=1;i<=$#;i++)); do if [[ "${!i}" == -out ]]; then j=$((i+1)); echo junk > "${!j}"; fi; done; exit 0']:
            wrapper = self.wrapper('if [[ " $* " == *" -gencrl "* ]]; then ' + mode + '; fi')
            self.make('crl', 'KIND=web', success=False, OPENSSL=wrapper)
            self.assertEqual(old, (self.ca / 'crl/ca.crl.pem').read_bytes())
            self.assertEqual(list((self.ca / 'crl').glob('.crl.*')), [])
            self.make('server', 'CN=blocked.example', 'REFRESH_CRL_BEFORE_ISSUE=1', success=False, OPENSSL=wrapper)
            self.assertFalse((self.ca / 'certs/blocked.example.cert.pem').exists())
            self.assertEqual(old, (self.ca / 'crl/ca.crl.pem').read_bytes())
            self.run_cmd(['bash', 'bin/intm-publish-final-crl.sh'], False, KIND='web', ALLOW_REMAINING_LEAFS='1', OPENSSL=wrapper)
            self.assertEqual(old, (self.ca / 'crl/ca.crl.pem').read_bytes())
            self.assertEqual(list((self.ca / 'crl').glob('.crl.*')), [])

    def test_committed_revocation_then_crl_failure(self):
        self.crls()
        old = (self.ca / 'crl/ca.crl.pem').read_bytes()
        wrapper = self.wrapper('if [[ " $* " == *" -gencrl "* ]]; then exit 17; fi')
        r = self.make('revoke', 'KIND=web', 'CN=leaf.example', success=False, OPENSSL=wrapper)
        self.assertIn('Revocation is committed', r.stderr)
        self.assertTrue((self.ca / 'index.txt').read_text().startswith('R\t'))
        self.assertEqual(old, (self.ca / 'crl/ca.crl.pem').read_bytes())
        self.make('revoke', 'KIND=web', 'CN=leaf.example')
        self.assertIn('VERIFY STATUS: REVOKED', self.verify(mode='info').stdout)

    def test_updatedb_failure_aborts_issuance(self):
        wrapper = self.wrapper('if [[ " $* " == *" -updatedb "* ]]; then exit 18; fi')
        before = (self.ca / 'index.txt').read_bytes(), (self.ca / 'serial').read_bytes()
        self.make('server', 'CN=not-issued.example', success=False, OPENSSL=wrapper)
        self.assertEqual(before, ((self.ca / 'index.txt').read_bytes(), (self.ca / 'serial').read_bytes()))
        self.assertFalse((self.ca / 'certs/not-issued.example.cert.pem').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
