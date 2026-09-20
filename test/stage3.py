#!/usr/bin/env python3
"""Executed command adapters, batch outcomes, and retry safety."""
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Commands(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage3-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.env = {'PATH': os.environ['PATH'], 'OPENSSL': os.environ.get('OPENSSL', 'openssl'), 'LC_ALL': 'C'}
        self.make('root', 'CN=Batch Root')
        self.make('int-web', 'CN=Batch Web')

    def run_cmd(self, command, success=True, **env):
        r = subprocess.run(command, cwd=self.work, env=dict(self.env, **env), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args, 'KEY_ALG=EC'], success, **env)

    def inventory(self, *names):
        (self.work / 'unusual.tsv').write_text(''.join('%X\t2030-01-01T00:00:00Z\t%s\t\n' % (4096+i, name) for i, name in enumerate(names)))

    def test_make_empty_dry_run_and_active_override(self):
        self.inventory()
        self.make('reissue-leafs-web', 'INPUT=unusual.tsv')
        target = self.work / 'pki-data/alternate'
        self.make('intermediate', 'INT_DIR=' + str(target), 'CN=Alternate Web')
        self.inventory('batch.example')
        before = snapshot(self.work)
        r = self.make('reissue-leafs-web', 'INPUT=unusual.tsv', 'ACTIVE_DIR=' + str(target), 'DRY_RUN=1')
        self.assertIn('status=planned', r.stdout)
        self.assertEqual(before, snapshot(self.work))
        untouched = snapshot(self.work / 'intm-web-ca')
        self.make('reissue-leafs-web', 'INPUT=unusual.tsv', 'ACTIVE_DIR=' + str(target))
        self.assertTrue((target / 'certs/batch.example.cert.pem').exists())
        self.assertEqual(untouched, snapshot(self.work / 'intm-web-ca'))
        before = snapshot(target)
        r = self.make('reissue-leafs-web', 'INPUT=unusual.tsv', 'ACTIVE_DIR=' + str(target))
        self.assertIn('status=already_completed', r.stdout)
        self.assertEqual(before, snapshot(target))

    def test_partial_reissue_and_committed_failure_not_retried(self):
        self.inventory('fail.example', 'success.example')
        command = 'bin/gen-server.sh && { if [[ "$CN" == fail.example ]]; then exit 23; fi; }'
        r = self.make('reissue-leafs-web', 'INPUT=unusual.tsv', success=False, ISSUE_CMD=command)
        self.assertIn('serial=1000 status=failed', r.stderr)
        self.assertIn('serial=1001 status=completed', r.stdout)
        self.assertIn('failed=1', r.stdout)
        ca = self.work / 'intm-web-ca'
        self.assertEqual(len((ca / 'index.txt').read_text().splitlines()), 2)
        before = snapshot(ca)
        r = self.make('reissue-leafs-web', 'INPUT=unusual.tsv', success=False, ISSUE_CMD=command)
        self.assertIn('status=needs_review', r.stderr)
        self.assertIn('status=already_completed', r.stdout)
        self.assertEqual(before, snapshot(ca))

    def test_custom_command_values_are_data_and_placeholders_rejected(self):
        name = "O'Brien $(touch injected)"
        self.inventory(name)
        self.make('reissue-leafs-web', 'INPUT=unusual.tsv', ISSUE_CMD='printf "%s" "$CN" > received')
        self.assertEqual((self.work / 'received').read_text(), name)
        self.assertFalse((self.work / 'injected').exists())
        self.make('reissue-leafs-web', 'INPUT=unusual.tsv', success=False, ISSUE_CMD="echo '%CN%'")

    def test_concurrent_reissue_claim_is_not_repeated(self):
        self.inventory('once.example')
        env = dict(self.env, ISSUE_CMD='echo invoked >> invocations; sleep 3')
        command = ['make', 'reissue-leafs-web', 'INPUT=unusual.tsv', 'KEY_ALG=EC']
        first = subprocess.Popen(command, cwd=self.work, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 15
            while not (self.work / 'invocations').exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue((self.work / 'invocations').exists())
            r = self.run_cmd(command, success=False, ISSUE_CMD=env['ISSUE_CMD'])
            self.assertIn('status=needs_review', r.stderr)
            output, _ = first.communicate(timeout=30)
            self.assertEqual(first.returncode, 0, output)
            self.assertEqual((self.work / 'invocations').read_text(), 'invoked\n')
        finally:
            if first.poll() is None:
                first.terminate()
            first.communicate(timeout=10)

    def test_file_forms_and_rejected_chain(self):
        self.make('server', 'CN=forms.example')
        ca = self.work / 'intm-web-ca'
        (self.work / 'alias').symlink_to('intm-web-ca', target_is_directory=True)
        for file in ['certs/forms.example.cert.pem', 'intm-web-ca/certs/forms.example.cert.pem',
                     'alias/certs/forms.example.cert.pem', str(ca / 'certs/forms.example.cert.pem')]:
            self.make('verify', 'KIND=web', 'FILE=' + file)
        before = snapshot(ca)
        self.make('verify', 'KIND=web', 'FILE=certs/forms.example.cert.pem', 'CHAIN=anything.pem', success=False)
        self.make('verify', 'FILE=intm-web-ca/certs/forms.example.cert.pem', success=False)
        self.assertEqual(before, snapshot(ca))
        for i, form in enumerate(['relative', 'workspace', 'absolute']):
            name = 'revoke%d.example' % i
            self.make('server', 'CN=' + name)
            file = 'certs/' + name + '.cert.pem'
            if form == 'workspace': file = 'intm-web-ca/' + file
            if form == 'absolute': file = str(ca / file)
            self.make('revoke', 'KIND=web', 'FILE=' + file)
        self.make('intermediate', 'INT_DIR=pki-data/other', 'CN=Other')
        self.make('verify', 'INT_DIR=pki-data/other', 'FILE=intm-web-ca/certs/forms.example.cert.pem', success=False)

    def test_bulk_partial_outcomes_and_retry(self):
        self.make('server', 'CN=first.example')
        self.make('server', 'CN=second.example')
        backend = shutil.which(self.env['OPENSSL'])
        wrapper = self.work / 'fail-openssl'
        wrapper.write_text('#!/bin/bash\nif [[ " $* " == *" -revoke "* && " $* " == *"/newcerts/1000.pem "* ]]; then exit 19; fi\nexec ' + shlex.quote(backend) + ' "$@"\n')
        wrapper.chmod(0o700)
        r = self.make('revoke-intm-and-leafs', 'KIND=web', 'CRL_UPDATE=0', 'OPENSSL=' + str(wrapper), success=False)
        self.assertIn('serial=1000 status=failed', r.stderr)
        self.assertIn('serial=1001 status=completed', r.stdout)
        self.assertIn('failed=1', r.stdout)
        rows = (self.work / 'intm-web-ca/index.txt').read_text().splitlines()
        self.assertEqual([r.split('\t')[0] for r in rows], ['V', 'R'])
        r = self.make('revoke-intm-and-leafs', 'KIND=web', 'LEAF_STATUSES=V,R', 'CRL_UPDATE=0')
        self.assertIn('[PARENT] status=already_completed', r.stdout)
        self.assertIn('serial=1001 status=already_completed', r.stdout)
        self.assertIn('failed=0', r.stdout)

    def test_bulk_missing_history_reports_all_without_mutation(self):
        self.make('server', 'CN=missing.example')
        self.make('server', 'CN=remaining.example')
        (self.work / 'intm-web-ca/newcerts/1000.pem').unlink()
        before = snapshot(self.work)
        r = self.make('revoke-intm-and-leafs', 'KIND=web', success=False)
        self.assertIn('serial=1000 status=skipped_required', r.stderr)
        self.assertIn('serial=1001 status=skipped_required', r.stderr)
        self.assertEqual(before, snapshot(self.work))

    def test_bulk_dry_run_and_empty_batch(self):
        self.make('server', 'CN=dry.example')
        before = snapshot(self.work)
        r = self.make('revoke-intm-and-leafs', 'KIND=web', 'DRY_RUN=1')
        self.assertIn('serial=1000 status=planned', r.stdout)
        self.assertEqual(before, snapshot(self.work))
        self.make('revoke-intm-and-leafs', 'KIND=web', 'CRL_UPDATE=0')
        r = self.make('revoke-intm-and-leafs', 'KIND=web', 'CRL_UPDATE=0')
        self.assertIn('total=0', r.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
