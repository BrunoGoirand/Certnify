#!/usr/bin/env python3
"""Preserving migration regressions, exclusively in disposable workspaces."""
import os
import shutil
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Migration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage9-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')
        self.run_cmd(['make', 'root', 'CN=Migration Root'])
        self.run_cmd(['make', 'int-web', 'CN=Migration Web'])
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, command, success=True, **env):
        r = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                           capture_output=True, text=True, timeout=90)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def rollover(self, kind='web'):
        self.run_cmd(['make', 'rollover-' + kind, 'INT_CN=Replacement CA'])
        self.legacy = next(self.work.glob('intm-' + kind + '-ca-legacy-*'))
        self.run_cmd(['make', 'list-leafs-' + kind])
        return self.legacy

    def cert(self, path, *args):
        return self.run_cmd([self.backend, 'x509', '-in', str(path), '-noout', *args]).stdout

    def test_complete_subject_sans_curve_fresh_key_dry_run_and_retry(self):
        self.run_cmd(['make', 'server', 'CN=app.example', 'C=FR', 'O=Équipe / R&D',
                      'OU=Ops + QA', 'KEY_CURVE=secp384r1',
                      'SAN=DNS:app.example,DNS:www.example,IP:2001:db8::1,email:ops@example.test,URI:urn:example:service'])
        old = self.ca / 'newcerts/1000.pem'
        subject = self.cert(old, '-subject', '-nameopt', 'RFC2253')
        sans = self.cert(old, '-ext', 'subjectAltName')
        public = self.cert(old, '-pubkey')
        self.rollover()
        # Source private leaf keys are not necessary for migration.
        (self.legacy / 'private/app.example.key.pem').rename(self.work / 'saved-old-key.pem')
        before = snapshot(self.work)
        r = self.run_cmd(['make', 'reissue-leafs-web', 'DRY_RUN=1'])
        self.assertIn('status=planned', r.stdout)
        self.assertEqual(before, snapshot(self.work))
        self.run_cmd(['make', 'reissue-leafs-web'], SAN_DNS='wrong.example', KEY_ALG='RSA', O='Wrong org')
        new = self.ca / 'newcerts/1000.pem'
        self.assertEqual(subject, self.cert(new, '-subject', '-nameopt', 'RFC2253'))
        self.assertEqual(sans, self.cert(new, '-ext', 'subjectAltName'))
        self.assertNotEqual(public, self.cert(new, '-pubkey'))
        self.assertIn('secp384r1', self.cert(new, '-text'))
        before = snapshot(self.work)
        r = self.run_cmd(['make', 'reissue-leafs-web'])
        self.assertIn('already_completed=1', r.stdout)
        self.assertEqual(before, snapshot(self.work))

    def test_rsa_and_eddsa_profile_variants(self):
        self.run_cmd(['make', 'int-smime', 'CN=Mail CA'])
        self.run_cmd(['make', 'email', 'CN=encrypt@example.test', 'SMIME_MODE=encrypt', 'KEY_ALG=RSA', 'KEY_SIZE=2048'])
        self.run_cmd(['make', 'email', 'CN=sign@example.test', 'SMIME_MODE=sign', 'KEY_ALG=Ed25519'])
        old = self.work / 'intm-smime-ca'
        expected = {s: self.cert(old / ('newcerts/' + s + '.pem'), '-ext', 'keyUsage,extendedKeyUsage,subjectAltName') for s in ['1000', '1001']}
        self.rollover('smime')
        self.run_cmd(['make', 'reissue-leafs-smime'])
        for serial, profile in [('1000', 'smime_encrypt'), ('1001', 'smime_sign')]:
            cert = old / ('newcerts/' + serial + '.pem')
            self.assertEqual(expected[serial], self.cert(cert, '-ext', 'keyUsage,extendedKeyUsage,subjectAltName'))
            self.assertIn('EXT_SECTION=' + profile, (old / ('issuers/' + serial + '.policy')).read_text())
        self.assertIn('Public-Key: (2048 bit)', self.cert(old / 'newcerts/1000.pem', '-text'))
        self.assertIn('ED25519', self.cert(old / 'newcerts/1001.pem', '-text'))

    def test_missing_metadata_stale_inventory_and_policy_drift_fail_without_mutation(self):
        self.run_cmd(['make', 'server', 'CN=first.example'])
        self.run_cmd(['make', 'server', 'CN=second.example'])
        self.rollover()
        policy = self.legacy / 'issuers/1001.policy'
        policy.rename(policy.with_suffix('.saved'))
        before = snapshot(self.work)
        r = self.run_cmd(['make', 'reissue-leafs-web'], False)
        self.assertIn('Missing original profile record', r.stderr)
        self.assertEqual(before, snapshot(self.work))
        policy.with_suffix('.saved').rename(policy)
        config = self.ca / 'openssl.cnf'
        original = config.read_text()
        config.chmod(0o600)
        # Fragment spacing is intentionally handled independently of production parser.
        import re
        config.write_text(re.sub(r'extendedKeyUsage\s*=\s*serverAuth', 'extendedKeyUsage = clientAuth', original))
        before = snapshot(self.work)
        r = self.run_cmd(['make', 'reissue-leafs-web'], False)
        self.assertIn('would change SANs/profile', r.stderr)
        self.assertEqual(before, snapshot(self.work))
        config.write_text(original)
        backend = self.work / 'failing-asn1.sh'
        backend.write_text('#!/bin/bash\nfor arg; do [[ "$arg" != -strparse ]] || exit 55; done\nexec ' +
                           shlex.quote(self.backend) + ' "$@"\n')
        backend.chmod(0o700)
        before = snapshot(self.work)
        r = self.run_cmd(['make', 'reissue-leafs-web', 'DRY_RUN=1'], False, OPENSSL=str(backend))
        self.assertIn('Cannot decode original subject', r.stderr)
        self.assertEqual(before, snapshot(self.work))
        inventory = next((self.work / 'out').glob('web-leafs-*.tsv'))
        inventory.write_text(inventory.read_text().replace('first.example', 'wrong.example'))
        before = snapshot(self.work)
        self.run_cmd(['make', 'reissue-leafs-web', 'DRY_RUN=1'], False)
        self.assertEqual(before, snapshot(self.work))

    def test_custom_profile_critical_san_and_extended_subject(self):
        profile = """
[ migration_profile ]
basicConstraints = critical, CA:false
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = critical,DNS:custom.example
"""
        config = self.ca / 'openssl.cnf'
        config.chmod(0o600)
        config.write_text(config.read_text().replace('[ req_distinguished_name ]',
            '[ req_distinguished_name ]\nST = Île-de-France\nL = Paris\n0.OU = First\n1.OU = Second') + profile)
        self.run_cmd(['make', 'server', 'CN=Équipe / app', 'SAN_DNS=custom.example',
                      'PROFILE=migration_profile', 'KEY_CURVE=secp521r1'])
        old = self.ca / 'newcerts/1000.pem'
        subject = self.cert(old, '-subject', '-nameopt', 'RFC2253')
        self.assertIn('ST=', subject)
        self.assertEqual(subject.count('OU='), 2)
        self.assertIn('critical', self.cert(old, '-ext', 'subjectAltName'))
        self.rollover()
        before = snapshot(self.work)
        self.run_cmd(['make', 'reissue-leafs-web'], False)
        self.assertEqual(before, snapshot(self.work))
        config.chmod(0o600)
        config.write_text(config.read_text() + profile)
        self.run_cmd(['make', 'reissue-leafs-web'])
        new = self.ca / 'newcerts/1000.pem'
        self.assertEqual(subject, self.cert(new, '-subject', '-nameopt', 'RFC2253'))
        self.assertIn('critical', self.cert(new, '-ext', 'subjectAltName'))
        self.assertIn('secp521r1', self.cert(new, '-text'))

    def test_absent_san_stays_absent_and_legacy_mode_is_explicit(self):
        self.run_cmd(['make', 'int-code', 'CN=Code CA'])
        self.run_cmd(['make', 'code', 'CN=Release Team', 'KEY_ALG=Ed448'])
        self.rollover('code')
        self.run_cmd(['make', 'reissue-leafs-code'])
        self.assertNotIn('Subject Alternative Name', self.cert(self.work / 'intm-code-ca/newcerts/1000.pem', '-text'))
        (self.work / 'manual.tsv').write_text('1000\t2030-01-01T00:00:00Z\tmanual.example\tunknown\n')
        self.run_cmd(['make', 'reissue-leafs-web', 'INPUT=manual.tsv'], False)
        r = self.run_cmd(['make', 'reissue-leafs-web', 'INPUT=manual.tsv', 'REISSUE_MODE=cn-only'])
        self.assertIn('CN-only', r.stderr)


if __name__ == '__main__':
    unittest.main()
