#!/usr/bin/env python3
"""Routine-operation hardening: disposable PKI fixtures only."""
import datetime
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Operations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage8-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')
        self.make('root', 'CN=Operations Root')
        self.make('int-web', 'CN=Operations Web')
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        if success:
            self.assertNotIn('unbound variable', result.stdout + result.stderr)
        return result

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args], success, **env)

    def state(self):
        return {name: snapshot(self.work / name) for name in ['root', 'intm-web-ca']}

    def test_clean_preview_apply_and_unrelated_paths(self):
        unrelated = self.work / 'intm-notes'
        unrelated.mkdir(); (unrelated / 'keep').write_text('unrelated')
        output = self.work / 'out'
        output.mkdir(); (output / 'inventory.tsv').write_text('generated')
        before = snapshot(self.work)
        result = self.make('clean')
        self.assertIn('Preview only', result.stdout)
        self.assertEqual(before, snapshot(self.work))
        self.make('clean', 'CLEAN_APPLY=1', 'DRY_RUN=1', success=False)
        self.assertEqual(before, snapshot(self.work))
        self.make('clean', 'CLEAN_APPLY=1')
        self.assertFalse((self.work / 'root').exists())
        self.assertFalse(self.ca.exists())
        self.assertFalse(output.exists())
        self.assertEqual((unrelated / 'keep').read_text(), 'unrelated')
        self.assertTrue((self.work / 'Makefile').exists())

    def test_clean_after_workspace_move(self):
        original = self.work
        self.work = original.with_name('relocated')
        original.rename(self.work)
        # An unrelated directory at the old location must never be deleted.
        original.mkdir()
        sentinel = original / 'keep'
        sentinel.write_text('external')
        before = snapshot(self.work)
        result = self.make('clean')
        self.assertIn('Preview only', result.stdout)
        self.assertEqual(before, snapshot(self.work))
        result = self.make('crl-root', success=False)
        self.assertIn('Stale authority binding', result.stderr)
        self.make('clean', 'CLEAN_APPLY=1')
        self.assertFalse((self.work / 'root').exists())
        self.assertFalse((self.work / 'intm-web-ca').exists())
        self.assertEqual(sentinel.read_text(), 'external')

    def test_clean_refuses_symlinks_and_incomplete_authorities(self):
        outside = self.work.parent / 'outside'
        outside.mkdir(); (outside / 'keep').write_text('external')
        alias = self.work / 'intm-alias'
        alias.symlink_to(outside, target_is_directory=True)
        before = self.state()
        self.make('clean', 'CLEAN_APPLY=1', success=False)
        self.assertEqual(before, self.state())
        self.assertEqual((outside / 'keep').read_text(), 'external')
        alias.unlink()
        (self.ca / 'serial').unlink()
        before = self.state()
        self.make('clean', 'CLEAN_APPLY=1', success=False)
        self.assertEqual(before, self.state())

    def test_chain_duration_limit_before_mutation(self):
        self.make('int-web', 'CN=Operations Web', 'DAYS=2', 'FORCE_REISSUE=1')
        before = self.state()
        result = self.make('server', 'CN=too-long.example', 'DAYS=3', success=False)
        self.assertIn('maximum DAYS=1', result.stderr)
        self.assertIn('limiting notAfter=', result.stderr)
        self.assertEqual(before, self.state())
        self.make('server', 'CN=within.example', 'DAYS=1')
        def expiry(path):
            result = self.run_cmd([self.backend, 'x509', '-in', str(path), '-noout', '-enddate'])
            return datetime.datetime.strptime(result.stdout.strip().split('=', 1)[1], '%b %d %H:%M:%S %Y GMT')
        self.assertLessEqual(expiry(self.ca / 'certs/within.example.cert.pem'), expiry(self.ca / 'certs/ca.cert.pem'))
        before = self.state()
        self.make('intermediate', 'KIND=too-long', 'DAYS=9000', success=False)
        self.assertFalse((self.work / 'intm-too-long-ca').exists())
        self.make('rollover-web', 'DAYS=9000', success=False)
        self.assertEqual(before, self.state())

    def test_root_is_also_a_validity_limit(self):
        # Shorten the test root with the same subject/key; existing signatures remain valid.
        root = self.work / 'root'
        (root / 'certs/ca.cert.pem').chmod(0o600)
        self.run_cmd([self.backend, 'req', '-new', '-x509', '-key', str(root / 'private/ca.key.pem'),
                      '-subj', '/CN=Operations Root', '-days', '1', '-config', str(root / 'openssl.cnf'),
                      '-extensions', 'v3_ca', '-out', str(root / 'certs/ca.cert.pem')])
        before = self.state()
        result = self.make('server', 'CN=root-limited.example', 'DAYS=2', success=False)
        self.assertIn('root/certs/ca.cert.pem', result.stderr)
        self.assertIn('maximum DAYS=', result.stderr)
        self.assertEqual(before, self.state())

    def test_expired_issuer_refused_before_signing(self):
        cert = self.ca / 'certs/ca.cert.pem'
        cert.chmod(0o600)
        self.run_cmd([self.backend, 'ca', '-batch', '-config', 'root/openssl.cnf',
                      '-in', str(self.ca / 'csr/ca.csr.pem'), '-subj', '/CN=Expired Operations CA',
                      '-extensions', 'v3_intermediate_ca', '-startdate', '20000101000000Z',
                      '-enddate', '20010101000000Z', '-out', str(cert)])
        before = self.state()
        result = self.make('server', 'CN=expired-issuer.example', success=False)
        self.assertIn('Issuer chain is not currently valid', result.stderr)
        self.assertEqual(before, self.state())
        self.assertFalse((self.work / '.recovery/pending').exists())

    def test_application_identity_purpose_and_strict_crls(self):
        self.make('server', 'CN=app.example', 'SAN_DNS=app.example', 'SAN_IP=127.0.0.1')
        common = ('verify', 'KIND=web', 'CN=app.example')
        self.make(*common, 'VERIFY_DNS=app.example', 'VERIFY_PURPOSE=sslserver')
        self.make(*common, 'VERIFY_IP=127.0.0.1', 'VERIFY_PURPOSE=sslserver')
        self.make(*common, 'VERIFY_DNS=wrong.example', success=False)
        self.make(*common, 'VERIFY_IP=127.0.0.2', success=False)
        self.make(*common, 'VERIFY_PURPOSE=smimesign', success=False)
        self.make(*common, 'VERIFY_DNS=app.example', 'VERIFY_IP=127.0.0.1', success=False)
        self.make(*common, 'VERIFY_MODE=strict', success=False)
        strict = common + ('VERIFY_MODE=strict', 'VERIFY_DNS=app.example', 'VERIFY_PURPOSE=sslserver')
        self.make(*strict, success=False)  # Missing root CRL, even with default VERIFY_CRL=0.
        self.make('crl-all', 'CRL_HISTORY=1')
        self.assertIn('VERIFY STATUS: OK', self.make(*strict, 'VERIFY_CRL=0').stdout)
        self.make('revoke', 'KIND=web', 'CN=app.example')
        self.make(*strict, success=False)

    def test_email_identity_and_strict_rejects_cn_fallback(self):
        self.make('int-smime', 'CN=Mail CA')
        self.make('email', 'CN=user@example.test', 'SMIME_MODE=sign')
        common = ('verify', 'KIND=smime', 'CN=user@example.test', 'VERIFY_PURPOSE=smimesign')
        self.make(*common, 'VERIFY_EMAIL=user@example.test')
        self.make(*common, 'VERIFY_EMAIL=other@example.test', success=False)
        # Custom policy without a SAN is still checked by purpose and strict SAN admission.
        self.run_cmd(['bin/gen-leaf.sh'], KIND='web', CN='cn-only.example', ACTION='dev')
        result = self.make('verify', 'KIND=web', 'CN=cn-only.example', 'VERIFY_MODE=strict',
                           'VERIFY_DNS=cn-only.example', 'VERIFY_PURPOSE=sslserver', success=False)
        self.assertIn('requires a DNS SAN', result.stderr)

    def test_batch_user_without_email_and_cn_only_warning(self):
        self.make('int-auth', 'CN=Users CA')
        inventory = self.work / 'users.tsv'
        inventory.write_text('1000\t2030-01-01T00:00:00Z\tAlice Example\tunknown\n'
                             '1001\t2030-01-01T00:00:00Z\talice@example.test\tunknown\n')
        result = self.make('reissue-leafs-auth', 'INPUT=users.tsv')
        self.assertIn('CN-only', result.stderr)
        self.assertIn('completed=2', result.stdout)
        cert = self.work / 'intm-auth-ca/certs/Alice Example.cert.pem'
        text = self.run_cmd([self.backend, 'x509', '-in', str(cert), '-noout', '-text']).stdout
        self.assertNotIn('email:Alice Example', text)
        cert = self.work / 'intm-auth-ca/certs/alice@example.test.cert.pem'
        text = self.run_cmd([self.backend, 'x509', '-in', str(cert), '-noout', '-ext', 'subjectAltName']).stdout
        self.assertIn('email:alice@example.test', text)

    def test_historical_crls_cover_old_and_active_leafs(self):
        self.make('server', 'CN=old.example')
        old_id = self.run_cmd([self.backend, 'x509', '-in', str(self.ca / 'certs/ca.cert.pem'), '-outform', 'PEM']).stdout
        self.make('int-web', 'CN=Operations Web', 'ROTATE_KEY=1')
        self.make('server', 'CN=new.example')
        self.make('revoke', 'KIND=web', 'CN=old.example', 'CRL_UPDATE=0')
        # Missing historical key is detected before even the root CRL advances.
        generations = list((self.ca / 'generations').iterdir())
        old_dir = next(p for p in generations if (p / 'ca.cert.pem').read_text() == old_id)
        key = old_dir / 'ca.key.pem'; key.rename(old_dir / 'saved.key')
        before = self.state()
        self.make('crl-all', 'CRL_HISTORY=1', success=False)
        self.assertEqual(before, self.state())
        (old_dir / 'saved.key').rename(key)
        self.make('crl-all', 'CRL_HISTORY=1')
        self.assertTrue((old_dir / 'ca.crl.pem').is_file())
        self.make('verify', 'KIND=web', 'CN=new.example', 'VERIFY_CRL=1')
        result = self.make('verify', 'KIND=web', 'CN=old.example', 'VERIFY_CRL=1', success=False)
        self.assertIn('VERIFY STATUS: REVOKED', result.stdout)
        self.make('rollover-web', 'INT_CN=Replacement Web')
        self.make('crl-all', 'CRL_HISTORY=1')
        legacy = next(self.work.glob('intm-web-ca-legacy-*'))
        self.make('verify', 'INT_DIR=' + legacy.name, 'CN=new.example', 'VERIFY_CRL=1')

    def test_calendar_conversion_boundaries(self):
        for value in ['1970-01-01T00:00:00', '2000-02-29T23:59:59', '2038-01-19T03:14:08',
                      '2100-03-01T00:00:00', '2400-02-29T12:30:45', '9999-12-31T23:59:59']:
            stamp = datetime.datetime.fromisoformat(value).replace(tzinfo=datetime.timezone.utc)
            epoch = str(int(stamp.timestamp()))
            result = self.run_cmd(['awk', '-f', 'bin/pki-time.awk'], PKI_TIME_MODE='encode', PKI_TIME_VALUE=epoch)
            self.assertEqual(result.stdout.strip(), stamp.strftime('%Y%m%d%H%M%SZ'))
            date = 'notAfter=' + stamp.strftime('%b %d %H:%M:%S %Y GMT') + '\n'
            decoded = subprocess.run(['awk', '-f', 'bin/pki-time.awk'], cwd=self.work,
                                     env=self.env, input=date, text=True, capture_output=True, check=True)
            self.assertEqual(decoded.stdout.split('\t')[0], epoch)

    def test_selected_custom_crl_coverage_and_default_scope(self):
        self.make('intermediate', 'INT_DIR=pki-data/custom', 'CN=Custom Operations CA')
        self.make('server', 'INT_DIR=pki-data/custom', 'CN=custom.example')
        custom = self.work / 'pki-data/custom'
        web_counter = (self.ca / 'crlnumber').read_bytes()
        self.make('crl', 'INT_DIR=pki-data/custom', 'CRL_HISTORY=1')
        self.assertEqual(web_counter, (self.ca / 'crlnumber').read_bytes())
        self.make('verify', 'INT_DIR=pki-data/custom', 'CN=custom.example',
                  'VERIFY_MODE=strict', 'VERIFY_DNS=custom.example', 'VERIFY_PURPOSE=sslserver')
        root_counter = (self.work / 'root/crlnumber').read_bytes()
        custom_counter = (custom / 'crlnumber').read_bytes()
        self.make('crl-all')
        self.assertEqual(root_counter, (self.work / 'root/crlnumber').read_bytes())
        self.assertEqual(custom_counter, (custom / 'crlnumber').read_bytes())
        before = snapshot(self.work)
        self.make('crl', 'INT_DIR=pki-data/custom', 'CRL_HISTORY=1', 'ISSUER_ID=' + 'a'*64, success=False)
        self.assertEqual(before, snapshot(self.work))


if __name__ == '__main__':
    unittest.main(verbosity=2)
