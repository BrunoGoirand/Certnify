#!/usr/bin/env python3
"""Version maintenance and source archive regressions in manifest-only fixtures."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from workspace import archive_sources, copy_sources, snapshot, source_paths

SOURCE = Path(__file__).resolve().parent.parent


class Versioning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-versioning-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.seed = self.base / 'source'
        copy_sources(SOURCE, self.seed)
        self.version = self.seed / 'VERSION'
        self.env = {key: os.environ[key] for key in ('PATH', 'TMPDIR', 'LC_ALL') if key in os.environ}
        self.env['OPENSSL'] = '/nonexistent/backend'

    def command(self, *args, level=None):
        env = dict(self.env)
        if level is not None:
            env['LEVEL'] = level
        return subprocess.run(args, cwd=self.seed, env=env, capture_output=True, text=True)

    def test_show_and_bumps_make_direct_parity_and_only_version_changes(self):
        for direct in (False, True):
            for level, expected in [('patch', '2.7.10'), ('minor', '2.8.0'), ('major', '3.0.0')]:
                with self.subTest(direct=direct, level=level):
                    self.version.write_text('2.7.9\n')
                    self.version.chmod(0o640)
                    before = snapshot(self.seed)
                    args = [sys.executable, '-B', 'tools/version.py', 'show'] if direct else ['make', '-s', 'version']
                    result = self.command(*args)
                    self.assertEqual((result.returncode, result.stdout), (0, '2.7.9\n'))
                    self.assertEqual(before, snapshot(self.seed))
                    args = [sys.executable, '-B', 'tools/version.py', 'bump'] if direct else ['make', '-s', 'version-bump']
                    result = self.command(*args, level=level)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.version.read_text(), expected + '\n')
                    after = snapshot(self.seed)
                    self.assertEqual(after['VERSION']['mode'], '0640')
                    del before['VERSION'], after['VERSION']
                    self.assertEqual(before, after)
        self.assertEqual(self.command('make', '-s', 'version-bump', 'LEVEL=patch').returncode, 0)
        self.assertEqual(self.version.read_text(), '3.0.1\n')

    def test_invalid_levels_are_literal_and_nonmutating(self):
        for level in (None, '', 'PATCH', 'foo', 'patch; touch INJECTED', '$(shell touch INJECTED)', '`touch INJECTED`'):
            for direct in (False, True):
                before = snapshot(self.seed)
                args = [sys.executable, '-B', 'tools/version.py', 'bump'] if direct else ['make', '-s', 'version-bump']
                if not direct and level is not None:
                    args.append('LEVEL=' + level)
                result = self.command(*args, level=level if direct else None)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, snapshot(self.seed))

    def test_invalid_versions_and_owned_lock_cleanup(self):
        for data in (b'01.2.3\n', b'1.2\n', b'1.2.3', b'1.2.3\r\n', b'1.2.3\n\n', b'1.2.3-rc1\n', b'\xff'):
            self.version.write_bytes(data)
            before = snapshot(self.seed)
            for operation in ('version', 'version-bump'):
                self.assertNotEqual(self.command('make', '-s', operation, 'LEVEL=patch').returncode, 0)
                self.assertEqual(before, snapshot(self.seed))
        self.version.unlink()
        for kind in ('missing', 'symlink', 'directory', 'fifo'):
            if kind == 'symlink':
                self.version.symlink_to(self.seed / 'CHANGELOG.md')
            elif kind == 'directory':
                self.version.mkdir()
            elif kind == 'fifo':
                os.mkfifo(self.version)
            result = self.command('make', '-s', 'version-bump', 'LEVEL=patch')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.seed / '.version-bump.lock').exists())
            if kind == 'directory':
                self.version.rmdir()
            elif kind != 'missing':
                self.version.unlink()

    def test_existing_lock_is_preserved_and_replace_failure_cleans_up(self):
        lock = self.seed / '.version-bump.lock'
        lock.mkdir()
        (lock / 'owner').write_text('another source operation')
        before = snapshot(self.seed)
        self.assertNotEqual(self.command('make', '-s', 'version-bump', 'LEVEL=patch').returncode, 0)
        self.assertEqual(before, snapshot(self.seed))
        (lock / 'owner').unlink()
        lock.rmdir()
        spec = importlib.util.spec_from_file_location('version_fixture', self.seed / 'tools/version.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        before = snapshot(self.seed)
        with mock.patch.object(module.os, 'replace', side_effect=OSError('injected replacement failure')):
            with self.assertRaises(OSError):
                module.bump(self.seed, 'patch')
        self.assertEqual(before, snapshot(self.seed))

    def test_archive_exact_members_and_usable_without_git(self):
        for name in ('root/private/ca.key.pem', '.recovery/pending/journal', 'bin/unlisted.key.pem', 'draft/plan.md'):
            target = self.seed / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('synthetic excluded sentinel')
        before = snapshot(self.seed)
        output = self.base / 'source.tar.gz'
        result = self.command(sys.executable, '-B', 'test/workspace.py', 'archive', '.', str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        extracted = self.base / 'extracted'
        with tarfile.open(output) as archive:
            self.assertEqual(archive.getnames(), ['certnify/' + name for name in source_paths(self.seed)])
            for member in archive.getmembers():
                self.assertTrue(member.isfile())
                relative = member.name[len('certnify/') :]
                self.assertEqual(archive.extractfile(member).read(), (self.seed / relative).read_bytes())
                target = extracted / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(member.mode)
        result = subprocess.run(['make', '-s', 'version'], cwd=extracted / 'certnify', env=self.env, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (0, self.version.read_text()))
        self.assertEqual(before, snapshot(self.seed))

    def test_archive_rejects_invalid_manifest_before_creation(self):
        manifest = self.seed / 'test/source-manifest.txt'
        original = manifest.read_text()
        for addition in ('../escape', '/absolute', 'VERSION', 'missing', './VERSION'):
            manifest.write_text(original + '\n' + addition + '\n')
            output = self.base / 'bad.tar.gz'
            with self.assertRaises(ValueError):
                archive_sources(self.seed, output)
            self.assertFalse(output.exists())
        manifest.write_text(original)
        self.version.unlink()
        self.version.symlink_to(self.seed / 'CHANGELOG.md')
        with self.assertRaises(ValueError):
            archive_sources(self.seed, output)
        self.assertFalse(output.exists())
        self.version.unlink()
        self.version.write_text('1.0.0\n')
        manifest.unlink()
        manifest.symlink_to(SOURCE / 'test/source-manifest.txt')
        with self.assertRaises(ValueError):
            archive_sources(self.seed, output)
        self.assertFalse(output.exists())

    def test_archive_exclusive_output_and_failed_write_cleanup(self):
        output = self.base / 'source.tar.gz'
        output.write_bytes(b'existing')
        with self.assertRaises(FileExistsError):
            archive_sources(self.seed, output)
        self.assertEqual(output.read_bytes(), b'existing')
        output.unlink()
        output.symlink_to(self.base / 'absent')
        with self.assertRaises(FileExistsError):
            archive_sources(self.seed, output)
        self.assertTrue(output.is_symlink())
        self.assertFalse((self.base / 'absent').exists())
        output.unlink()
        with mock.patch.object(tarfile.TarFile, 'add', side_effect=OSError('injected archive failure')):
            with self.assertRaises(OSError):
                archive_sources(self.seed, output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
