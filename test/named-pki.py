#!/usr/bin/env python3
"""Named workspace regression tests; generated keys stay in disposable fixtures."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parents[1]


class NamedPKI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-named-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve() / 'source with spaces'
        copy_sources(SOURCE, self.base)
        self.env = {'PATH': os.environ['PATH'], 'LC_ALL': 'C',
                    'OPENSSL': os.environ.get('OPENSSL', 'openssl')}

    def run_make(self, target, pki=None, ok=True, **params):
        args = ['make', '--no-print-directory', target]
        if pki is not None:
            args.append('PKI=' + pki)
        args.extend(k + '=' + v for k, v in params.items())
        result = subprocess.run(args, cwd=self.base, env=self.env,
                                capture_output=True, text=True, timeout=90)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout[-1500:] + result.stderr[-1500:])
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def hierarchy(self, pki):
        policy = dict(KEY_ALG='EC', KEY_CURVE='prime256v1')
        self.run_make('root', pki, CN=pki, DAYS='3650', ROOT_PATHLEN='1', **policy)
        self.run_make('int-web', pki, CN=pki+' Web', DAYS='365', **policy)
        self.run_make('server', pki, CN='app.test', SAN_DNS='app.test', DAYS='30', **policy)

    def test_two_hierarchies_revocation_guards_and_paths(self):
        a, b = 'certnify-alpha', 'certnify-beta'
        self.hierarchy(a)
        before_a = snapshot(self.base / a)
        self.hierarchy(b)
        self.assertEqual(snapshot(self.base / a), before_a)
        before_b = snapshot(self.base / b)
        self.run_make('verify', a, KIND='web', CN='app.test', VERIFY_DNS='app.test', VERIFY_PURPOSE='sslserver')
        self.run_make('revoke', a, KIND='web', FILE='certs/app.test.cert.pem', REASON='superseded', CRL_UPDATE='1')
        self.run_make('crl-root', a)
        self.run_make('verify', a, ok=False, KIND='web', CN='app.test', VERIFY_MODE='strict', VERIFY_CRL='1')
        self.assertEqual(snapshot(self.base / b), before_b)
        self.run_make('verify', b, KIND='web', CN='app.test')
        # Direct script invocation must use the same selected workspace.
        direct = subprocess.run(['bash', str(self.base / 'bin/list-leafs-by-issuer.sh')],
            cwd=self.base.parent, env=dict(self.env, PKI=b, KIND='web', OUT='out/leaves.tsv'),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(direct.returncode, 0, direct.stderr)
        self.assertTrue((self.base / b / 'out/leaves.tsv').is_file())
        self.assertFalse((self.base / 'out').exists())
        cross = subprocess.run([self.env['OPENSSL'], 'verify',
            '-CAfile', str(self.base / a / 'root/certs/ca.cert.pem'),
            '-untrusted', str(self.base / b / 'intm-web-ca/certs/ca.cert.pem'),
            str(self.base / b / 'intm-web-ca/certs/app.test.cert.pem')],
            env=self.env, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(cross.returncode, 0)
        # Synthetic recovery guard is local to A; preserve it on refusal.
        recovery = self.base / a / '.recovery/pending'
        recovery.mkdir()
        self.run_make('verify', a, ok=False, KIND='web', CN='app.test')
        self.run_make('verify', b, KIND='web', CN='app.test')
        self.assertTrue(recovery.exists())
        recovery.rmdir()  # Synthetic marker in this disposable test only.
        # A blocked peer must not block the selected PKI.
        guard = self.base / a / '.locks/root-ca.lock'
        guard.mkdir()
        self.run_make('verify', b, KIND='web', CN='app.test')
        self.run_make('verify', a, ok=False, KIND='web', CN='app.test', LOCK_TIMEOUT='0')
        self.assertTrue(guard.is_dir())
        before_b = snapshot(self.base / b)
        self.run_make('verify', b, ok=False, INT_DIR=str(self.base / a / 'intm-web-ca'), CN='app.test')
        self.assertEqual(snapshot(self.base / b), before_b)
        before_a = snapshot(self.base / a)
        self.run_make('clean', b)  # Preview leaves B's public state unchanged.
        self.run_make('clean', b, CLEAN_APPLY='1')
        self.assertFalse((self.base / b / 'root').exists())
        self.assertEqual(snapshot(self.base / a), before_a)
        self.assertFalse((self.base / 'root').exists())
        self.assertFalse((self.base / '.locks').exists())
        self.assertFalse((self.base / '.recovery').exists())
        self.run_make('root', ok=False, CN='No implicit selection')
        self.assertFalse((self.base / 'root').exists())

    def test_named_rollover_and_preserving_reissue(self):
        pki = 'certnify-lifecycle'
        self.hierarchy(pki)
        self.run_make('rollover-web', pki, INT_CN='Replacement Web', DAYS='365', KEY_ALG='EC', KEY_CURVE='prime256v1')
        self.run_make('list-leafs-web', pki)
        self.run_make('reissue-leafs-web', pki, REISSUE_MODE='preserve', DAYS='30')
        self.run_make('verify', pki, KIND='web', CN='app.test', VERIFY_DNS='app.test', VERIFY_PURPOSE='sslserver')
        self.assertTrue(list((self.base / pki).glob('intm-web-ca-legacy-*')))
        self.assertFalse((self.base / 'root').exists())

    def test_readonly_resolver_and_legacy_guard(self):
        before = snapshot(self.base)
        result = json.loads(self.run_make('pki-info', 'certnify-new').stdout)
        self.assertFalse(result['exists'])
        self.assertEqual(result['workspace'], str(self.base / 'certnify-new'))
        self.assertEqual(snapshot(self.base), before)
        (self.base / '.recovery').mkdir()
        self.run_make('root', 'certnify-new', ok=False)
        self.assertFalse((self.base / 'certnify-new').exists())
        self.run_make('pki-info', 'certnify-new', ok=False)
        self.assertEqual(json.loads(self.run_make('pki-info').stdout)['layout'], 'legacy')

    def test_selectors_naming_and_symlinks(self):
        before = snapshot(self.base)
        for selector in ('', '../outside', 'certnify-A', 'certnify-a/child', 'certnify-a--b', 'certnify-'+'a'*73, 'certnify-$(touch injected)'):
            self.run_make('root', selector, ok=False)
            self.assertEqual(snapshot(self.base), before)
        self.assertEqual(self.run_make('pki-name', CN='  Racine École  ').stdout.strip(), 'certnify-racine-ecole')
        self.run_make('pki-name', CN='日本', ok=False)
        self.run_make('pki-name', CN='a'*73, ok=False)
        other = self.base.parent / 'other'
        other.mkdir()
        (self.base / 'certnify-link').symlink_to(other, target_is_directory=True)
        self.run_make('root', 'certnify-link', ok=False)
        self.assertEqual(list(other.iterdir()), [])
        self.run_make('int-web', 'certnify-missing', ok=False)
        self.assertFalse((self.base / 'certnify-missing').exists())


class SiblingPKI(NamedPKI):
    def setUp(self):
        super().setUp()
        destination = self.base.parent / '.certnify'
        self.base.rename(destination)
        self.base = destination

    # Run the full lifecycle suite with the original physical PKI directories:
    # nested state remains supported when the engine is renamed to .certnify.
    def hierarchy(self, pki):
        (self.base / pki).mkdir()
        super().hierarchy(pki)

    def test_readonly_resolver_and_legacy_guard(self):
        before = snapshot(self.base)
        result = json.loads(self.run_make('pki-info', 'certnify-new').stdout)
        self.assertEqual(result['workspace'], str(self.base.parent / 'certnify-new'))
        self.assertFalse(result['exists'])
        self.assertEqual(snapshot(self.base), before)
        (self.base / '.recovery').mkdir()
        self.run_make('pki-info', 'certnify-new', ok=False)

    def test_sibling_lifecycle_and_conflicts(self):
        pki = 'certnify-sibling'
        NamedPKI.hierarchy(self, pki)
        workspace = self.base.parent / pki
        self.assertTrue((workspace / 'root/certs/ca.cert.pem').is_file())
        self.assertFalse((self.base / pki).exists())
        self.run_make('verify', pki, KIND='web', CN='app.test')
        self.run_make('pki-info', ok=False)
        before = snapshot(workspace)
        (self.base / pki).mkdir()
        self.run_make('pki-info', pki, ok=False)
        self.run_make('verify', pki, ok=False, KIND='web', CN='app.test')
        self.assertEqual(snapshot(workspace), before)
        for name, symlink in [('certnify-link-sibling', True), ('certnify-file', False)]:
            path = self.base.parent / name
            if symlink:
                path.symlink_to(workspace, target_is_directory=True)
            else:
                path.touch()
            self.run_make('pki-info', name, ok=False)
        self.assertEqual(snapshot(workspace), before)


if __name__ == '__main__':
    unittest.main()
