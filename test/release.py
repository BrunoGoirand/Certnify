#!/usr/bin/env python3
"""Release integration tests use manifest-only sources and local bare remotes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from workspace import copy_sources

SOURCE = Path(__file__).resolve().parents[1]


class Release(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='certnify-release-')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name).resolve()
        self.root = base / 'engine'
        self.remote = base / 'remote.git'
        copy_sources(SOURCE, self.root)
        self.env = {'PATH': os.environ['PATH'], 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0'}
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.test')
        self.git('config', 'commit.gpgsign', 'false')
        self.git('config', 'tag.gpgsign', 'false')
        (self.root / 'VERSION').write_text('2.7.9\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'Fixture')
        self.git('init', '--bare', '--quiet', str(self.remote))
        self.git('remote', 'add', 'origin', str(self.remote))
        self.head = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args],
                                       env=self.env, text=True).strip()

    def run_release(self, *args):
        return subprocess.run([sys.executable, '-B', 'tools/release.py', *args],
                              cwd=self.root, env=self.env, capture_output=True, text=True)

    def test_preview_and_all_levels(self):
        for level, expected in [('patch', '2.7.10'), ('minor', '2.8.0'), ('major', '3.0.0')]:
            preview = self.run_release(level, '--dry-run')
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertEqual(self.git('rev-parse', 'HEAD'), self.head)
            self.assertEqual((self.root / 'VERSION').read_text(), '2.7.9\n')
            self.assertEqual(self.git('tag', '--list', 'v' + expected), '')
            self.assertEqual(self.git('ls-remote', 'origin', 'refs/tags/v' + expected), '')
            result = self.run_release(level)
            self.assertEqual(result.returncode, 0, result.stderr)
            tag = 'v' + expected
            self.assertEqual(self.git('show', tag + ':VERSION'), expected)
            self.assertEqual(self.git('cat-file', '-t', tag), 'tag')
            self.assertIn(self.git('rev-parse', tag), self.git('ls-remote', 'origin', 'refs/tags/' + tag))
            self.assertEqual(self.git('ls-remote', '--heads', 'origin'), '')
            self.assertEqual(self.git('status', '--porcelain'), '')
            self.git('reset', '--hard', self.head)  # Disposable fixture only.

    def test_dirty_invalid_level_and_existing_tag_do_not_bump(self):
        (self.root / 'unreviewed').write_text('keep')
        self.assertNotEqual(self.run_release('patch').returncode, 0)
        (self.root / 'unreviewed').unlink()
        self.assertNotEqual(self.run_release('invalid').returncode, 0)
        self.git('tag', 'v2.7.10')
        self.assertNotEqual(self.run_release('patch').returncode, 0)
        self.git('push', 'origin', 'refs/tags/v2.7.10')
        self.git('tag', '-d', 'v2.7.10')
        self.assertNotEqual(self.run_release('patch').returncode, 0)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.head)
        self.assertEqual((self.root / 'VERSION').read_text(), '2.7.9\n')

    def test_rejected_push_preserves_local_release(self):
        hook = self.remote / 'hooks/pre-receive'
        hook.write_text('#!/bin/sh\nexit 1\n')
        hook.chmod(0o700)
        result = self.run_release('patch')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No automatic rollback', result.stderr)
        self.assertEqual(self.git('show', 'v2.7.10:VERSION'), '2.7.10')
        self.assertEqual(self.git('ls-remote', '--tags', 'origin'), '')
        self.assertFalse((self.root / '.release.lock').exists())


if __name__ == '__main__':
    unittest.main()
