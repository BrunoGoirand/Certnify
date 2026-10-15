#!/usr/bin/env python3
"""Isolated regression tests for list-leafs-by-issuer.sh; disposable PKIs only."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources

SOURCE = Path(__file__).resolve().parent.parent


class ListLeafs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage14-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')
        self.make('root', 'CN=List Leafs Root')
        self.make('int-web', 'CN=List Leafs Web')
        self.ca = self.work / 'intm-web-ca'

    def make(self, *args, success=True, **env):
        r = subprocess.run(['make', *args], cwd=self.work,
                           env=dict(self.env, **env),
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def run_script(self, *args, success=True, **env):
        r = subprocess.run(list(args), cwd=self.work,
                           env=dict(self.env, **env),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def list_leafs(self, success=True, **env):
        return self.run_script('bin/list-leafs-by-issuer.sh', success=success, **env)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def tsv_rows(self, path):
        """Return non-empty lines from a TSV file as lists of fields."""
        return [line.split('\t') for line in path.read_text().splitlines() if line.strip()]

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_empty_intermediate_produces_empty_tsv(self):
        r = self.list_leafs(KIND='web')
        self.assertIn('Inventory written', r.stderr)
        out_files = list((self.work / 'out').glob('web-leafs*.tsv'))
        self.assertEqual(len(out_files), 1)
        rows = self.tsv_rows(out_files[0])
        self.assertEqual(rows, [])

    def test_active_leaf_appears_in_tsv(self):
        self.make('server', 'CN=app.example.com', 'SAN_DNS=app.example.com')
        r = self.list_leafs(KIND='web')
        self.assertIn('Inventory written', r.stderr)
        out_files = list((self.work / 'out').glob('web-leafs*.tsv'))
        self.assertEqual(len(out_files), 1)
        rows = self.tsv_rows(out_files[0])
        self.assertEqual(len(rows), 1)
        # TSV columns: SERIAL, NOTAFTER(UTC), CN, CERT_PATH
        serial, notafter, cn, _ = rows[0]
        self.assertRegex(serial, r'^[0-9A-F]+$')
        self.assertRegex(notafter, r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
        self.assertEqual(cn, 'app.example.com')

    def test_revoked_leaf_excluded_by_default(self):
        self.make('server', 'CN=gone.example')
        self.make('server', 'CN=alive.example', 'SAN_DNS=alive.example')
        self.make('revoke', 'KIND=web', 'CN=gone.example')
        r = self.list_leafs(KIND='web')
        out_files = list((self.work / 'out').glob('web-leafs*.tsv'))
        rows = self.tsv_rows(out_files[0])
        cns = [row[2] for row in rows]
        self.assertIn('alive.example', cns)
        self.assertNotIn('gone.example', cns)

    def test_include_revoked_flag(self):
        self.make('server', 'CN=gone.example')
        self.make('server', 'CN=alive.example', 'SAN_DNS=alive.example')
        self.make('revoke', 'KIND=web', 'CN=gone.example')
        r = self.list_leafs(KIND='web', INCLUDE_REVOKED='1')
        out_files = sorted((self.work / 'out').glob('web-leafs*.tsv'),
                           key=lambda p: p.stat().st_mtime, reverse=True)
        rows = self.tsv_rows(out_files[0])
        cns = [row[2] for row in rows]
        self.assertIn('alive.example', cns)
        self.assertIn('gone.example', cns)

    def test_stdout_mode_does_not_create_file(self):
        self.make('server', 'CN=stdout.example', 'SAN_DNS=stdout.example')
        before_out = set((self.work / 'out').glob('*')) if (self.work / 'out').exists() else set()
        r = self.list_leafs(KIND='web', OUT='-')
        after_out = set((self.work / 'out').glob('*')) if (self.work / 'out').exists() else set()
        # No new file created in out/
        self.assertEqual(before_out, after_out)
        # TSV row written to stdout
        rows = [line.split('\t') for line in r.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], 'stdout.example')

    def test_explicit_int_dir_takes_precedence_over_kind(self):
        self.make('int-auth', 'CN=List Leafs Auth')
        self.make('user', 'CN=alice@example.test',
                  'SAN_EMAIL=alice@example.test', 'KIND=auth')
        # Provide INT_DIR explicitly pointing to web; auth leaf must not appear.
        r = self.list_leafs(INT_DIR='intm-web-ca')
        out_files = list((self.work / 'out').glob('*leafs*.tsv'))
        rows = self.tsv_rows(out_files[0])
        cns = [row[2] for row in rows]
        self.assertNotIn('alice@example.test', cns)

    def test_missing_kind_and_int_dir_fails(self):
        r = self.list_leafs(success=False)
        self.assertIn('INT_DIR', r.stderr + r.stdout)

    def test_legacy_resolution_after_rollover(self):
        """After rollover, list-leafs targets the newest legacy by default."""
        self.make('server', 'CN=before.example', 'SAN_DNS=before.example')
        self.make('rollover-web', 'INT_CN=Replacement Web CA')
        self.make('server', 'CN=after.example', 'SAN_DNS=after.example')

        # Without INT_DIR, the script should target the legacy (pre-rollover) CA.
        r = self.list_leafs(KIND='web')
        self.assertIn('Inventory written', r.stderr)
        out_files = list((self.work / 'out').glob('web-leafs-*.tsv'))
        self.assertGreater(len(out_files), 0)
        # The timestamped TSV should correspond to the legacy CA's leaf.
        # Sort by name descending (newest timestamp first).
        latest = sorted(out_files, reverse=True)[0]
        rows = self.tsv_rows(latest)
        cns = [row[2] for row in rows]
        self.assertIn('before.example', cns)
        # after.example was issued under the new CA, not the legacy.
        self.assertNotIn('after.example', cns)

    def test_output_is_overwritten_on_second_call(self):
        self.make('server', 'CN=first.example', 'SAN_DNS=first.example')
        self.list_leafs(KIND='web')
        out_files = list((self.work / 'out').glob('web-leafs*.tsv'))
        self.assertEqual(len(out_files), 1)
        first_rows = self.tsv_rows(out_files[0])
        self.assertEqual(len(first_rows), 1)
        self.make('server', 'CN=second.example', 'SAN_DNS=second.example')
        self.list_leafs(KIND='web')
        out_files = list((self.work / 'out').glob('web-leafs*.tsv'))
        self.assertEqual(len(out_files), 1)
        second_rows = self.tsv_rows(out_files[0])
        self.assertEqual(len(second_rows), 2)


if __name__ == '__main__':
    unittest.main()
