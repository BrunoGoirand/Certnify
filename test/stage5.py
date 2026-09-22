#!/usr/bin/env python3
"""Effective keys, explicit policy, SAN validation and artifact identities."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Policy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage5-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.env = {'PATH': os.environ['PATH'], 'OPENSSL': os.environ.get('OPENSSL', 'openssl'), 'LC_ALL': 'C'}
        self.make('root', 'CN=Policy Root')
        self.make('int-web', 'CN=Policy Web')
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, cmd, success=True, **env):
        r = subprocess.run(cmd, cwd=self.work, env=dict(self.env, **env), capture_output=True, text=True, timeout=90)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def make(self, *args, success=True, **env):
        args = list(args)
        if not any(a.startswith('KEY_ALG=') for a in args): args.append('KEY_ALG=EC')
        return self.run_cmd(['make', *args], success, **env)

    def cert(self, relative):
        return self.run_cmd([self.env['OPENSSL'], 'x509', '-in', relative, '-noout', '-text']).stdout

    def test_zero_root_pathlen_blocks_existing_hierarchy_without_mutation(self):
        # Re-sign only the disposable root, preserving its subject/key so the
        # existing intermediate still chains to it (legacy incompatible PKI).
        config = self.work / 'zero-root.cnf'
        config.write_text((self.work / 'root/openssl.cnf').read_text().replace('pathlen:1', 'pathlen:0'))
        cert = self.work / 'root/certs/ca.cert.pem'
        cert.chmod(0o600)
        self.run_cmd([self.env['OPENSSL'], 'x509', '-in', str(cert),
                      '-signkey', 'root/private/ca.key.pem', '-days', '7300',
                      '-extfile', str(config), '-extensions', 'v3_ca',
                      '-out', 'zero-root.pem'])
        cert.write_bytes((self.work / 'zero-root.pem').read_bytes())
        self.assertIn('pathlen:0', self.cert('root/certs/ca.cert.pem'))
        for args in [('int-web', 'CN=Policy Web', 'FORCE_REISSUE=1'),
                     ('int-auth', 'CN=Blocked CA'),
                     ('rollover-web', 'INT_CN=Replacement'),
                     ('server', 'CN=blocked.example')]:
            with self.subTest(args=args):
                before = snapshot(self.work)
                result = self.make(*args, 'ROOT_PATHLEN=9', success=False)
                self.assertIn('requires CA:TRUE and pathlen >= 1', result.stderr)
                self.assertEqual(before, snapshot(self.work))

    def test_fresh_root_pathlen_zero_and_unconstrained(self):
        for limit in ['0', '']:
            with self.subTest(pathlen=limit):
                self.work = Path(self.temp.name) / ('fresh-' + (limit or 'unlimited'))
                copy_sources(SOURCE, self.work)
                result = self.make('root', 'CN=Standalone Root', 'ROOT_PATHLEN=' + limit)
                if limit == '0':
                    self.assertIn('cannot support Certnify intermediates', result.stderr)
                    before = snapshot(self.work)
                    result = self.make('int-web', 'CN=Blocked CA', success=False)
                    self.assertIn('requires CA:TRUE and pathlen >= 1', result.stderr)
                    self.assertEqual(before, snapshot(self.work))
                else:
                    self.make('int-web', 'CN=Unlimited Web')
                    self.make('server', 'CN=unlimited.example')

    def test_effective_key_metadata_matrix(self):
        for alg, option, expected in [('RSA', 'KEY_SIZE=2048', 'RSA'), ('EC', 'KEY_CURVE=prime256v1', 'EC'),
                                      ('EC', 'KEY_CURVE=secp384r1', 'EC'), ('EC', 'KEY_CURVE=secp521r1', 'EC'),
                                      ('Ed25519', 'KEY_SIZE=2048', 'ED25519'), ('Ed448', 'KEY_SIZE=2048', 'ED448')]:
            script = 'source bin/pki-env.sh; gen_private_key "$KEY_ALG" "${KEY_SIZE:-2048}" "${KEY_CURVE:-prime256v1}" probe.key.pem >/dev/null; inspect_private_key_metadata probe.key.pem; printf "%s|%s|%s|%s" "$DETECTED_KEY_ALG" "$DETECTED_KEY_SIZE" "$DETECTED_KEY_CURVE" "$DETECTED_KEY_EDDSA"'
            key, value = option.split('=', 1)
            r = self.run_cmd(['bash', '-c', script], KEY_ALG=alg, **{key: value})
            self.assertTrue(r.stdout.startswith(expected + '|'), r.stdout)
            if alg == 'EC': self.assertIn(value, r.stdout)
            if alg == 'RSA': self.assertIn('2048', r.stdout)
            (self.work / 'probe.key.pem').unlink()
        self.make('int-web', 'CN=Policy Web', 'KEY_ALG=RSA', 'FORCE_REUSE_KEY=1', 'FORCE_REISSUE=1')
        meta = (self.ca / 'ca.meta').read_text()
        self.assertIn('ALG=EC\n', meta)
        self.assertIn('PATHLEN=0\n', meta)
        self.assertIn('POLICY_SHA256=', meta)
        self.make('root', 'CN=Policy Root', 'KEY_ALG=RSA', 'ROOT_PATHLEN=9')
        self.assertIn('PATHLEN=1\n', (self.work / 'root/ca.meta').read_text())
        self.assertIn('ALG=EC\n', (self.work / 'root/ca.meta').read_text())

    def test_eddsa_noop_and_real_variant_change(self):
        self.make('intermediate', 'INT_DIR=pki-data/ed', 'CN=Ed CA', 'KEY_ALG=Ed448')
        ca = self.work / 'pki-data/ed'
        key = (ca / 'private/ca.key.pem').read_bytes()
        serial = (self.work / 'root/serial').read_bytes()
        for args in [('KEY_ALG=Ed448',), ('KEY_ALG=EdDSA', 'KEY_EDDSA=ed448')]:
            self.make('intermediate', 'INT_DIR=pki-data/ed', 'CN=Ed CA', *args)
            self.assertEqual(serial, (self.work / 'root/serial').read_bytes())
            self.assertEqual(key, (ca / 'private/ca.key.pem').read_bytes())
        self.make('server', 'INT_DIR=pki-data/ed', 'CN=ed-issuer.example')
        self.make('intermediate', 'INT_DIR=pki-data/ed', 'CN=Ed CA', 'KEY_ALG=Ed25519')
        self.assertNotEqual(key, (ca / 'private/ca.key.pem').read_bytes())
        self.assertIn('ALG=ED25519\n', (ca / 'ca.meta').read_text())

    def test_skip_repairs_companions_and_refuses_mismatch(self):
        (self.ca / 'ca.meta').unlink()
        (self.ca / 'certs/chain.cert.pem').unlink()
        (self.ca / 'certs/ca.chain.cert.pem').unlink()
        self.make('int-web', 'CN=Policy Web')
        self.assertTrue((self.ca / 'ca.meta').exists())
        self.assertEqual(os.readlink(self.ca / 'certs/chain.cert.pem'), 'ca.chain.cert.pem')
        key = self.ca / 'private/ca.key.pem'
        key.chmod(0o600)
        key.write_bytes((self.work / 'root/private/ca.key.pem').read_bytes())
        before = snapshot(self.ca)
        self.make('int-web', 'CN=Policy Web', success=False)
        self.assertEqual(before, snapshot(self.ca))

    def test_config_staging_and_preserved_custom_policy(self):
        fragment = self.work / 'profiles/leaf/server-ec.cnf'
        original = fragment.read_text()
        fragment.unlink()
        self.make('intermediate', 'INT_DIR=pki-data/missing', 'CN=Missing', success=False)
        dest = self.work / 'pki-data/missing'
        self.assertFalse((dest / 'openssl.cnf').exists())
        self.assertEqual(list(dest.glob('.policy.*')), [])
        fragment.write_text(original)
        self.make('intermediate', 'INT_DIR=pki-data/missing', 'CN=Missing')
        cnf = self.ca / 'openssl.cnf'
        cnf.write_text(cnf.read_text() + '\n# Operator customization retained\n')
        before = cnf.read_bytes()
        fragment.write_text(original.replace('digitalSignature', 'INVALID_USAGE'))
        self.make('int-web', 'CN=Policy Web')
        self.assertEqual(before, cnf.read_bytes())
        self.make('intermediate', 'INT_DIR=pki-data/invalid', 'CN=Invalid', success=False)
        self.assertFalse((self.work / 'pki-data/invalid/openssl.cnf').exists())
        cnf.write_text(cnf.read_text().replace('[ server_ec ]', '[ removed_server_ec ]'))
        self.make('server', 'CN=blocked.example', success=False)
        self.assertFalse((self.ca / 'certs/blocked.example.cert.pem').exists())

    def test_profiles_follow_reused_keys(self):
        self.make('server', 'CN=reused.example')
        key = (self.ca / 'private/reused.example.key.pem').read_bytes()
        self.make('revoke', 'KIND=web', 'CN=reused.example', 'CRL_UPDATE=0')
        self.make('server', 'CN=reused.example', 'KEY_ALG=RSA')
        self.assertEqual(key, (self.ca / 'private/reused.example.key.pem').read_bytes())
        text = self.cert('intm-web-ca/newcerts/1001.pem')
        self.assertIn('Digital Signature', text)
        self.assertNotIn('Key Encipherment', text)
        policy = (self.ca / 'issuers/1001.policy').read_text()
        self.assertIn('EXT_SECTION=server_ec', policy)
        self.assertTrue(list((self.ca / 'policies').glob('*.cnf')))
        self.make('revoke', 'KIND=web', 'SERIAL=1001', 'CRL_UPDATE=0')
        self.make('server', 'CN=reused.example', 'KEY_ALG=RSA', 'PROFILE=server_cert', success=False)
        self.make('int-smime', 'CN=Policy Mail')
        self.make('email', 'INT_DIR=intm-smime-ca', 'CN=sign@example.test', 'SMIME_MODE=sign')
        self.make('email', 'INT_DIR=intm-smime-ca', 'CN=encrypt@example.test', 'SMIME_MODE=encrypt', success=False)
        for alg in ['Ed25519', 'Ed448']:
            self.make('server', 'CN=' + alg.lower() + '.example', 'KEY_ALG=' + alg)
            self.assertNotIn('Key Encipherment', self.cert('intm-web-ca/certs/' + alg.lower() + '.example.cert.pem'))

    def test_explicit_sans_and_invalid_inputs(self):
        self.make('server', 'CN=cn.example', 'SAN_DNS=other.example', 'SAN_IP=2001:db8::1,127.0.0.1', 'SAN_URI=spiffe://service/path,urn:example:value')
        text = self.cert('intm-web-ca/certs/cn.example.cert.pem')
        self.assertIn('DNS:other.example', text)
        self.assertNotIn('DNS:cn.example', text)
        self.assertIn('URI:urn:example:value', text)
        for value in ['DNS:', 'BOGUS:thing', 'DNS:good.example,,DNS:two.example', 'IP:999.1.1.1', 'IP:1::2::3', 'DNS:bad_name', 'DNS:good.example\n[req]']:
            before = snapshot(self.ca)
            self.run_cmd(['bash', 'bin/gen-server.sh'], False, CN='invalid.example', SAN=value)
            self.assertEqual(before, snapshot(self.ca))

    def test_direct_core_and_name_collision_guard(self):
        r = self.run_cmd(['bash', 'bin/gen-leaf.sh'], INT_DIR='intm-web-ca', CN='direct.example', KEY_ALG='Ed448', SAN='DNS:direct.example')
        self.assertTrue((self.ca / 'certs/direct.example.cert.pem').exists(), r.stdout + r.stderr)
        self.assertNotIn('Key Encipherment', self.cert('intm-web-ca/certs/direct.example.cert.pem'))
        self.make('int-code', 'CN=Policy Code')
        self.ca = self.work / 'intm-code-ca'
        self.make('code', 'CN=collision')
        mapping = self.ca / 'names/collision.cn'
        mapping.chmod(0o600)
        mapping.write_text('different identity\n')
        before = snapshot(self.ca)
        self.make('code', 'CN=collision', success=False)
        self.assertEqual(before, snapshot(self.ca))

    def test_unsafe_cn_is_data_and_reserved_names_do_not_collide(self):
        self.make('int-code', 'CN=Policy Code')
        self.ca = self.work / 'intm-code-ca'
        for cn in ['A/B', 'A_B', 'ca', 'chain', "O\"Brien $ENV::HOME # tag", "$(touch injected)"]:
            self.make('code', 'CN=' + cn, 'INT_DIR=intm-code-ca')
            self.make('verify', 'KIND=code', 'CN=' + cn)
        self.assertFalse((self.work / 'injected').exists())
        digest = hashlib.sha256(b'A/B').hexdigest()
        self.assertTrue((self.ca / ('certs/cn-' + digest + '.cert.pem')).exists())
        self.assertTrue((self.ca / 'certs/A_B.cert.pem').exists())
        self.assertTrue((self.ca / 'certs/ca.cert.pem').exists())
        # Import lookup uses durable history even when no current named artifact exists.
        (self.ca / ('certs/cn-' + digest + '.cert.pem')).unlink()
        self.run_cmd(['bash', 'bin/verify.sh'], KIND='code', CN='A/B')
        self.run_cmd(['bash', 'bin/revoke-leaf.sh'], KIND='code', CN='A/B', CRL_UPDATE='0')


if __name__ == '__main__':
    unittest.main(verbosity=2)
