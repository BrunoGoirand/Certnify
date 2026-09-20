#!/usr/bin/env python3
"""Regression gate for source packaging and disposable test workspaces."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot, source_paths

SOURCE = Path(__file__).resolve().parent.parent


class StageZero(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage0-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.seed = self.base / 'seed'
        copy_sources(SOURCE, self.seed)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.seed), *args], capture_output=True, text=True)

    def test_source_only_and_root_generation(self):
        # Unlisted data must never be copied, even if placed inside source folders.
        for name in ['root/private/ca.key.pem', 'intm-custom-ca/private/ca.key.pem',
                     'pki-data/customer/private/ca.key.pem', 'bin/unlisted.key.pem',
                     'profiles/unlisted.cnf', '.locks/root-ca.lock/pid', '.recovery/pending/operation']:
            path = self.seed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('DO NOT COPY')
        packaged = self.base / 'package'
        copy_sources(self.seed, packaged)
        actual = {p.relative_to(packaged).as_posix() for p in packaged.rglob('*') if p.is_file()}
        self.assertEqual(actual, set(source_paths(self.seed)))
        self.assertNotIn('root/private/ca.key.pem', actual)
        before = snapshot(packaged)
        env = {'PATH': os.environ['PATH'], 'OPENSSL': os.environ.get('OPENSSL', 'openssl'), 'LC_ALL': 'C'}
        result = subprocess.run(['make', 'root', 'CN=Stage Zero Fixture', 'KEY_ALG=EC'],
                                cwd=packaged, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = snapshot(packaged)
        self.assertNotIn('root/index.txt', before)
        self.assertEqual(after['root/index.txt']['content'], '')
        self.assertEqual(after['root/serial']['content'], '1000\n')
        self.assertEqual(after['root/private/ca.key.pem']['mode'], '0600')
        self.assertEqual(len(after['root/certs/ca.cert.pem']['certificate_der_sha256']), 1)
        self.assertNotIn('content', after['root/private/ca.key.pem'])
        for name in actual:
            self.assertEqual(before[name], after[name], name)

    def test_git_rules(self):
        self.assertEqual(self.git('init', '-q').returncode, 0)
        excluded = ['root/serial', 'intm-web-ca/index.txt', 'intm-custom-ca/index.txt',
                    'intm-web-ca-legacy-20260101/openssl.cnf',
                    'intm-web-ca-pre-rollback-20260101/serial', 'intermediate/index.txt',
                    'pki-data/custom/index.txt', 'out/list.tsv', '.locks/root-ca.lock/pid',
                    'test-results/report.json', '.recovery/pending/operation', 'custom/private/key', 'custom/example.key.pem',
                    'custom/example.key.20260101.bak.pem', 'custom/ca.key.20260101.bak']
        for name in excluded:
            self.assertEqual(self.git('check-ignore', '--no-index', '-q', name).returncode, 0, name)
        for name in source_paths(self.seed):
            self.assertEqual(self.git('check-ignore', '--no-index', '-q', name).returncode, 1, name)
        # Simulate a fresh source distribution using only paths eligible for Git.
        self.assertEqual(self.git('add', '--', *source_paths(self.seed)).returncode, 0)
        self.assertIn('profiles/root/base.cnf', self.git('ls-files').stdout.splitlines())

    def test_fail_closed_manifest_and_symlinks(self):
        fragment = self.seed / 'profiles/root/base.cnf'
        fragment.unlink()
        destination = self.base / 'missing'
        with self.assertRaises(ValueError):
            copy_sources(self.seed, destination)
        self.assertFalse(destination.exists())
        fragment.symlink_to(SOURCE / 'profiles/root/base.cnf')
        with self.assertRaises(ValueError):
            copy_sources(self.seed, destination)
        self.assertFalse(destination.exists())
        fragment.unlink()
        fragment.write_text('test')
        with (self.seed / 'test/source-manifest.txt').open('a') as stream:
            stream.write('../outside\n')
        with self.assertRaises(ValueError):
            copy_sources(self.seed, destination)
        self.assertFalse(destination.exists())

    def test_snapshot_detects_state_changes_and_links(self):
        fixture = self.base / 'state'
        fixture.mkdir()
        (fixture / 'index.txt').write_text('V\t270101000000Z\t\t1000\tunknown\t/CN=test\n')
        (fixture / 'serial').write_text('1001\n')
        (fixture / 'chain').symlink_to('certificate')
        before = snapshot(fixture)
        (fixture / 'serial').write_text('1002\n')
        (fixture / 'serial').chmod(0o400)
        after = snapshot(fixture)
        self.assertEqual(before['chain']['target'], 'certificate')
        self.assertEqual(before['index.txt'], after['index.txt'])
        self.assertNotEqual(before['serial']['sha256'], after['serial']['sha256'])
        self.assertEqual(after['serial']['content'], '1002\n')
        self.assertEqual(after['serial']['mode'], '0400')


if __name__ == '__main__':
    unittest.main(verbosity=2)
