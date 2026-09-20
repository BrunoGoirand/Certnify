#!/usr/bin/env python3
"""Audit A01-A06 regressions. Generated, disposable authorities only."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class AuditFixes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage7-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')
        self.run_cmd(['bin/gen-root.sh'], CN='Audit Root')
        self.run_cmd(['bin/gen-intm.sh'], CN='Audit Web', KIND='web')
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        if success:
            self.assertNotIn('unbound variable', result.stdout + result.stderr)
        return result

    def state(self):
        return {p.name: snapshot(p) for p in (self.work / 'root', self.ca)}

    def test_missing_state_is_never_initialized_again(self):
        self.run_cmd(['bin/gen-server.sh'], CN='before.example')
        for directory in (self.ca, self.work / 'root'):
            for names in [('index.txt',), ('serial',), ('crlnumber',), ('openssl.cnf',), ('index.txt', 'serial')]:
                with self.subTest(authority=directory.name, missing=names):
                    for name in names: (directory / name).rename(directory / (name + '.saved'))
                    before = self.state()
                    self.run_cmd(['bin/gen-server.sh'], False, CN='after.example')
                    self.assertEqual(before, self.state())
                    command = ['bin/gen-root.sh'] if directory.name == 'root' else ['bin/gen-intm.sh']
                    self.run_cmd(command, False, CN='Audit Root' if directory.name == 'root' else 'Audit Web', KIND='web')
                    self.assertEqual(before, self.state())
                    for name in names: (directory / (name + '.saved')).rename(directory / name)

    def test_orphan_serial_history_blocks_before_mutation(self):
        # Numeric identity includes different case/padding, not just exact spelling.
        for relative in ['newcerts/00001000.pem', 'issuers/001000',
                         'issuers/1000.policy', 'certs/srl-1000-old.cert.pem']:
            with self.subTest(relative=relative):
                orphan = self.ca / relative
                orphan.parent.mkdir(exist_ok=True)
                orphan.write_text('retained history; must never be replaced\n')
                before = self.state()
                self.run_cmd(['bin/gen-server.sh'], False, CN='collision.example')
                self.assertEqual(before, self.state())
                self.run_cmd(['bin/gen-intm.sh'], False, CN='Replacement', KIND='web', FORCE_REISSUE='1')
                self.assertEqual(before, self.state())
                orphan.unlink()
        root = self.work / 'root'
        serial = (root / 'serial').read_text().strip()
        (root / 'newcerts' / ('00' + serial.lower() + '.pem')).write_text('retained root history\n')
        before = self.state()
        self.run_cmd(['bin/gen-intm.sh'], False, CN='Another CA', KIND='other')
        self.assertFalse((self.work / 'intm-other-ca').exists())
        self.assertEqual(before, self.state())

    def test_make_arguments_are_literal_data(self):
        # Adapter probe: no actual CA operation, and no shell interpolation of inputs.
        for name in ['gen-root.sh', 'gen-intm.sh', 'verify.sh', 'revoke-leaf.sh',
                     'intm-rollover.sh', 'intm-reissue-leafs.sh', 'intm-rollback-to-legacy.sh',
                     'list-leafs-by-issuer.sh']:
            (self.work / 'bin' / name).write_text('#!/bin/bash\nenv > observed.env\n')
        cases = [('root', 'DAYS'), ('root', 'KEY_ALG'), ('root', 'KEY_SIZE'),
                 ('root', 'ROOT_PATHLEN'), ('root', 'ROOT_CNF'), ('root', 'OPENSSL'),
                 ('intermediate', 'INT_DIR'), ('intermediate', 'KIND'),
                 ('verify', 'VERIFY_MODE'), ('verify', 'VERIFY_CRL'), ('revoke', 'REASON'),
                 ('revoke', 'CRL_DAYS'), ('revoke', 'DRY_RUN'), ('rollback-web', 'LEGACY_DIR'),
                 ('reissue-leafs-web', 'INPUT'), ('root', 'CN'),
                 ('verify', 'VERIFY_DNS'), ('verify', 'VERIFY_IP'),
                 ('verify', 'VERIFY_EMAIL'), ('verify', 'VERIFY_PURPOSE'),
                 ('root', 'CLEAN_APPLY'), ('root', 'CRL_HISTORY')]
        for target, variable in cases:
            for value in ['x`touch injected`', '$(shell touch injected)', 'x"; touch injected; #', 'a b']:
                with self.subTest(target=target, variable=variable, value=value):
                    marker = self.work / 'injected'
                    if marker.exists(): marker.unlink()
                    self.run_cmd(['make', target, variable + '=' + value])
                    self.assertFalse((self.work / 'injected').exists())
                    values = dict(line.split('=', 1) for line in (self.work / 'observed.env').read_text().splitlines() if '=' in line)
                    self.assertEqual(values[variable], value)
        for prefix in ['rollover-', 'rollback-', 'reissue-leafs-', 'list-leafs-']:
            self.run_cmd(['make', prefix + 'web`touch injected`'])
            self.assertFalse((self.work / 'injected').exists())

    def test_invalid_scalar_options_fail_before_mutation(self):
        for options in [dict(DAYS='0'), dict(DAYS='bad'), dict(FORCE_NEW_KEY='yes'),
                        dict(ALLOW_DUPLICATE_CN='yes'), dict(DN_MAXLEN='x'), dict(AUTO_UPDATEDB='maybe')]:
            before = self.state()
            self.run_cmd(['bin/gen-server.sh'], False, CN='invalid.example', **options)
            self.assertEqual(before, self.state())
        self.run_cmd(['bin/gen-server.sh'], CN='decimal.example', DAYS='008', LOCK_TIMEOUT='00')

    def test_weak_new_and_reused_keys_are_rejected(self):
        before = self.state()
        self.run_cmd(['bin/gen-server.sh'], False, CN='weak.example', KEY_ALG='RSA', KEY_SIZE='512')
        self.assertEqual(before, self.state())
        self.run_cmd(['bin/gen-intm.sh'], False, CN='Weak CA', KIND='weak', KEY_ALG='RSA', KEY_SIZE='1024')
        self.assertFalse((self.work / 'intm-weak-ca').exists())
        self.run_cmd(['bin/intm-rollover.sh'], False, KIND='web', INT_CN='Weak replacement', KEY_ALG='RSA', KEY_SIZE='512')
        self.assertEqual(before, self.state())
        key = self.ca / 'private/reused.example.key.pem'
        self.run_cmd([self.backend, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024', '-out', str(key)])
        before = self.state()
        self.run_cmd(['bin/gen-server.sh'], False, CN='reused.example')
        self.assertEqual(before, self.state())
        self.run_cmd(['bin/gen-server.sh'], CN='strong.example', KEY_ALG='RSA', KEY_SIZE='2048')
        self.run_cmd(['bin/verify.sh'], KIND='web', CN='strong.example')
        # A fresh root also rejects weak requests before creating its directory.
        self.work = self.work.parent / 'weak-root'
        copy_sources(SOURCE, self.work)
        self.run_cmd(['bin/gen-root.sh'], False, CN='Weak Root', KEY_ALG='RSA', KEY_SIZE='512')
        self.assertFalse((self.work / 'root').exists())
        self.run_cmd(['bin/gen-root.sh'], CN='Reusable Root')
        root_key = self.work / 'root/private/ca.key.pem'
        root_key.chmod(0o600)
        self.run_cmd([self.backend, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:1024', '-out', str(root_key)])
        before = snapshot(self.work / 'root')
        self.run_cmd(['bin/gen-root.sh'], False, CN='Reusable Root')
        self.assertEqual(before, snapshot(self.work / 'root'))

    def test_verify_rejects_weak_import_even_when_revocation_tolerated(self):
        key = self.ca / 'private/import.key.pem'
        csr = self.ca / 'csr/import.csr.pem'
        cert = self.ca / 'certs/import.cert.pem'
        self.run_cmd([self.backend, 'req', '-new', '-newkey', 'rsa:1024', '-nodes',
                      '-subj', '/CN=import.example', '-keyout', str(key), '-out', str(csr)])
        self.run_cmd([self.backend, 'ca', '-batch', '-config', str(self.ca / 'openssl.cnf'),
                      '-extensions', 'server_cert', '-in', str(csr), '-out', str(cert)])
        for mode in ['normal', 'tolerate_revoked']:
            self.run_cmd(['bin/verify.sh'], False, KIND='web', FILE='certs/import.cert.pem', VERIFY_MODE=mode)
        result = self.run_cmd(['bin/verify.sh'], KIND='web', FILE='certs/import.cert.pem', VERIFY_MODE='info')
        self.assertIn('VERIFY STATUS: ERROR', result.stdout)

    def test_profile_san_conflicts_fail_before_signing(self):
        cnf = self.ca / 'openssl.cnf'
        original = cnf.read_text()
        for definition in ['DNS:wrong.example', '@policy_names']:
            cnf.write_text(original.replace('[ server_ec ]', '[ server_ec ]\nsubjectAltName = ' + definition)
                           + '\n[ policy_names ]\nDNS.1 = wrong.example\n')
            before = self.state()
            self.run_cmd(['bin/gen-server.sh'], False, CN='requested.example', SAN_DNS='requested.example')
            self.assertEqual(before, self.state())
        cnf.write_text(original.replace('[ server_ec ]', '[ server_ec ]\nsubjectAltName = DNS:requested.example'))
        self.run_cmd(['bin/gen-server.sh'], CN='requested.example', SAN_DNS='requested.example')
        cnf.write_text(original + '\n[ alt_names ]\nDNS.99 = must-not-leak.example\n')
        self.run_cmd(['bin/gen-server.sh'], CN='mixed.example', SAN_DNS='a.example,b.example',
                     SAN_IP='2001:db8::1,127.0.0.1', SAN_EMAIL='a@example.test', SAN_URI='urn:example:one')
        sans = self.run_cmd([self.backend, 'x509', '-in', str(self.ca / 'certs/mixed.example.cert.pem'), '-noout', '-ext', 'subjectAltName']).stdout
        self.assertNotIn('must-not-leak', sans)

    def test_empty_request_and_profile_only_sans(self):
        result = self.run_cmd(['bin/gen-leaf.sh'], CN='No SAN Signing', KIND='web', ACTION='dev')
        self.assertNotIn('unbound variable', result.stdout + result.stderr)
        cert = self.ca / 'certs/No SAN Signing.cert.pem'
        decoded = self.run_cmd([self.backend, 'x509', '-in', str(cert), '-noout', '-text']).stdout
        self.assertNotIn('X509v3 Subject Alternative Name:', decoded)
        cnf = self.ca / 'openssl.cnf'
        cnf.write_text(cnf.read_text().replace('[ code_sign ]', '[ code_sign ]\nsubjectAltName = URI:urn:example:signing'))
        result = self.run_cmd(['bin/gen-leaf.sh'], CN='Profile SAN Signing', KIND='web', ACTION='dev')
        self.assertNotIn('unbound variable', result.stdout + result.stderr)
        cert = self.ca / 'certs/Profile SAN Signing.cert.pem'
        decoded = self.run_cmd([self.backend, 'x509', '-in', str(cert), '-noout', '-ext', 'subjectAltName']).stdout
        self.assertIn('URI:urn:example:signing', decoded)

    def test_utf8_identity_and_idempotence(self):
        # Independent UTF-8 root, so requested root DN is not a replacement.
        self.work = self.work.parent / 'unicode'
        copy_sources(SOURCE, self.work)
        for command, options in [(['bin/gen-root.sh'], dict(CN='Autorité été', O='組織')),
                                 (['bin/gen-intm.sh'], dict(CN='Émetteur 東京', KIND='web'))]:
            self.run_cmd(command, **options)
            directory = self.work / ('root' if 'gen-root' in command[0] else 'intm-web-ca')
            cert = directory / 'certs/ca.cert.pem'
            old = cert.read_bytes()
            self.run_cmd(command, **options)
            self.assertEqual(old, cert.read_bytes())
            subject = self.run_cmd([self.backend, 'x509', '-in', str(cert), '-noout', '-subject', '-nameopt', 'RFC2253,utf8,-esc_msb']).stdout
            self.assertIn(options['CN'], subject)
        cn = 'Élodie 東京 / A+B'
        self.run_cmd(['bin/gen-code.sh'], CN=cn, INT_DIR='intm-web-ca')
        self.run_cmd(['bin/gen-code.sh'], False, CN=cn, INT_DIR='intm-web-ca')
        self.run_cmd(['bin/verify.sh'], CN=cn, KIND='web')
        self.run_cmd(['bin/revoke-leaf.sh'], CN=cn, KIND='web', CRL_UPDATE='0')

    def test_utf8_validation_and_special_dn_comparison(self):
        before = self.state()
        self.run_cmd(['bin/gen-code.sh'], False, CN=os.fsdecode(b'bad\xff'), INT_DIR='intm-web-ca')
        self.assertEqual(before, self.state())
        self.work = self.work.parent / 'special'
        copy_sources(SOURCE, self.work)
        cn = 'Autorité=CA; A+B,C<D>'
        self.run_cmd(['bin/gen-root.sh'], CN=cn)
        cert = self.work / 'root/certs/ca.cert.pem'
        old = cert.read_bytes()
        self.run_cmd(['bin/gen-root.sh'], CN=cn)
        self.assertEqual(old, cert.read_bytes())

    def test_bad_profile_san_compilation_has_no_ca_side_effects(self):
        cnf = self.ca / 'openssl.cnf'
        cnf.write_text(cnf.read_text().replace('[ server_ec ]', '[ server_ec ]\nsubjectAltName = IP:999.1.1.1'))
        before = self.state()
        self.run_cmd(['bin/gen-server.sh'], False, CN='invalid.example')
        self.assertEqual(before, self.state())
        self.assertFalse((self.work / '.recovery/pending').exists())

    def test_post_sign_san_mismatch_is_not_installed(self):
        # Simulate a backend/configuration change after the preflight snapshot.
        wrapper = self.work / 'backend'
        wrapper.write_text('#!/bin/bash\n'
                           'if [[ "$1" == ca && " $* " == *" -in "* ]]; then\n'
                           "printf '\\n[ server_ec ]\\nsubjectAltName = DNS:wrong.example\\n' >> intm-web-ca/openssl.cnf\n"
                           'fi\nexec ' + shlex.quote(self.backend) + ' "$@"\n')
        wrapper.chmod(0o700)
        result = self.run_cmd(['bin/gen-server.sh'], False, CN='requested.example', OPENSSL=str(wrapper))
        self.assertIn('Issued SANs differ', result.stderr)
        self.assertFalse((self.ca / 'certs/requested.example.cert.pem').exists())
        self.assertTrue((self.ca / 'newcerts/1000.pem').exists())
        self.assertTrue((self.work / '.recovery/pending').exists())

    def test_default_direct_intermediate(self):
        self.run_cmd(['bin/gen-intm.sh'], CN='Default Intermediate')
        cert = self.work / 'intermediate/certs/ca.cert.pem'
        original = cert.read_bytes()
        self.run_cmd(['bin/gen-intm.sh'], CN='Default Intermediate')
        self.assertEqual(original, cert.read_bytes())
        self.assertFalse((self.work / '.recovery/pending').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
