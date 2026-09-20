#!/usr/bin/env python3
"""Stage-1 parsing and selection regressions; disposable data only."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


def row(serial='100A', cn='sample', status='V', expiry='270101000000Z', filename='unknown'):
    rev = '260101000000Z,keyCompromise' if status == 'R' else ''
    return '\t'.join([status, expiry, rev, serial, filename, '/CN=' + cn]) + '\n'


class Records(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage1-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = {'PATH': os.environ['PATH'], 'LC_ALL': 'C',
                    'OPENSSL': os.environ.get('OPENSSL', 'openssl')}
        self.index = self.base / 'index.txt'

    def parse(self, mode, content, **options):
        self.index.write_text(content)
        env = dict(self.env, PKI_RECORD_MODE=mode, PKI_RECORD_NOW='20260919000000Z', **options)
        return subprocess.run(['awk', '-f', str(SOURCE / 'bin/pki-records.awk'), str(self.index)],
                              env=env, capture_output=True, text=True)

    def test_serials_are_exact_and_monotonic(self):
        cases = [('', '1000', '1000'), (row(), '1000', '100B'),
                 (row(), '2000', '2000'), (row('0000100a'), '00001000', '100B'),
                 (row('7FFFFFFFFFFFFFFF'), '1000', '8000000000000000'),
                 (row('FFFFFFFFFFFFFFFE'), '1000', 'FFFFFFFFFFFFFFFF'),
                 (row('00FF', status='R') + row('0100', status='E'), '0001', '0101')]
        for content, current, expected in cases:
            with self.subTest(current=current, expected=expected):
                r = self.parse('serial', content, PKI_RECORD_COUNTER=current)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), expected)

    def test_invalid_or_exhausted_serials_fail(self):
        for content, counter in [(row('FFFFFFFFFFFFFFFF'), '1000'),
                                 (row('10000000000000000'), '1000'),
                                 (row('not-hex'), '1000'), (row(), ' 1000'),
                                 (row(), '1000\n1001'), (row(), ''),
                                 (row() + row('0000100A'), '1000'),
                                 (row().replace('\t\t', '\t'), '1000')]:
            r = self.parse('serial', content, PKI_RECORD_COUNTER=counter)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, '')

    def test_literal_cn_and_decoded_subjects(self):
        for encoded, cn in [('a.b[1]', 'a.b[1]'), (r'a\/b\+c\=d,e', 'a/b+c=d,e'),
                            (r'path\\name', 'path\\name'), ('Élodie', 'Élodie'),
                            (r'\xC3\x89lodie', 'Élodie')]:
            with self.subTest(cn=cn):
                r = self.parse('duplicates', row(cn=encoded), PKI_RECORD_CN=cn)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue(r.stdout.startswith('100A\x1f'))
        r = self.parse('duplicates', row(cn='axb') + row('100B', cn='a.b.extra'), PKI_RECORD_CN='a.b')
        self.assertEqual(r.stdout, '')
        r = self.parse('duplicates', row(cn='a.b', status='R') + row('100B', cn='a.b', expiry='250101000000Z'), PKI_RECORD_CN='a.b')
        self.assertEqual(r.stdout, '')

    def test_dates_and_inventory(self):
        content = row(expiry='491231235959Z') + row('100B', expiry='500101000000Z', status='E') + row('100C', expiry='20500228000000Z', status='R')
        r = self.parse('list', content, INCLUDE_REVOKED='1', INCLUDE_EXPIRED='1')
        self.assertEqual(r.returncode, 0, r.stderr)
        for value in ['2049-12-31T23:59:59Z', '1950-01-01T00:00:00Z', '2050-02-28T00:00:00Z']:
            self.assertIn(value, r.stdout)
        for date in ['270229000000Z', '20261301000000Z', '270101240000Z', 'bad']:
            r = self.parse('list', row(expiry=date))
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, '')
        # Empty fourth column and CRLF must not shift CN or selected fields.
        r = self.parse('inventory', '100A\t2050-01-01T00:00:00Z\tÉlodie / A,B\t\r\n', COL_SERIAL='1', COL_EXPIRES='2', COL_CN='3')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, '100A\x1f2050-01-01T00:00:00Z\x1fÉlodie / A,B\n')
        r = self.parse('inventory', 'Name\t\t100A\t2050-01-01T00:00:00Z\n', COL_SERIAL='3', COL_EXPIRES='4', COL_CN='1')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split('\x1f')[0], '100A')

    def test_malformed_inventory_is_all_or_nothing(self):
        good = '1000\t2027-01-01T00:00:00Z\tName\tunknown\n'
        for cs, ce, cc, text in [('1', '2', '3', good + 'bad\n'),
                                  ('0', '2', '3', good), ('1', '1', '3', good),
                                  ('1', '2', '5', good),
                                  ('1', '2', '3', good.replace('Name', ''))]:
            r = self.parse('inventory', text, COL_SERIAL=cs, COL_EXPIRES=ce, COL_CN=cc)
            self.assertNotEqual(r.returncode, 0)
            self.assertEqual(r.stdout, '')

    def test_revoke_selection(self):
        r = self.parse('serial-target', row('00aB'), PKI_RECORD_SERIAL='AB')
        self.assertEqual(r.stdout, '00aB\x1funknown\n')
        r = self.parse('revoke', row(cn='app') + row('100B', cn='app.extra'), PKI_RECORD_CN='app')
        self.assertEqual(r.stdout, '100A\n')
        r = self.parse('revoke', row(cn='app') + row('100B', cn='app'), PKI_RECORD_CN='app')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('100A 100B', r.stderr)
        r = self.parse('revoke', row(cn='app', status='R') + row('100B', cn='app'), PKI_RECORD_CN='app')
        self.assertEqual(r.stdout, '100B\n')
        r = self.parse('revoke', row(cn='app', status='R'), PKI_RECORD_CN='app')
        self.assertEqual(r.stdout, '100A\n')
        r = self.parse('revoke', row(cn='app.extra'), PKI_RECORD_CN='app')
        self.assertNotEqual(r.returncode, 0)
        for dn in ['sample\\', 'sample/CN=second', r'sample\xZZ']:
            r = self.parse('list', row(cn=dn))
            self.assertNotEqual(r.returncode, 0)

    def test_failed_repair_does_not_mutate_files(self):
        workspace = self.base / 'workspace'
        copy_sources(SOURCE, workspace)
        fixture = workspace / 'fixture'
        fixture.mkdir()
        (fixture / 'index.txt').write_text(row('FFFFFFFFFFFFFFFF'))
        (fixture / 'serial').write_text('1000\n')
        before = snapshot(fixture)
        r = subprocess.run(['bash', '-c', 'source bin/pki-env.sh; ensure_serial_monotonic fixture'],
                           cwd=workspace, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(before, snapshot(fixture))
        (fixture / 'index.txt').write_text(row())
        r = subprocess.run(['bash', '-c', 'source bin/pki-env.sh; ensure_serial_monotonic fixture'],
                           cwd=workspace, env=self.env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((fixture / 'serial').read_text(), '100B\n')

    def test_inventory_script_roundtrip_and_failed_output_preservation(self):
        workspace = self.base / 'workspace'
        copy_sources(SOURCE, workspace)
        ca = workspace / 'intm-web-ca'
        for args in [('root', 'CN=Inventory Root'), ('int-web', 'CN=Inventory Web')]:
            generated = subprocess.run(['make', *args, 'KEY_ALG=EC'], cwd=workspace,
                                       env=self.env, capture_output=True, text=True)
            self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
        (ca / 'index.txt').write_text(row(cn=r'Élodie \/ A,B', expiry='20500101000000Z'))
        r = subprocess.run(['bash', 'bin/list-leafs-by-issuer.sh'], cwd=workspace,
                           env=dict(self.env, INT_DIR='intm-web-ca', OUT='batch.tsv'),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        exported = (workspace / 'batch.tsv').read_text()
        self.assertIn('Élodie / A,B', exported)
        r = subprocess.run(['bash', 'bin/intm-reissue-leafs.sh'], cwd=workspace,
                           env=dict(self.env, KIND='web', INPUT='batch.tsv', DRY_RUN='1'),
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Élodie / A,B', r.stdout)
        (ca / 'index.txt').write_text(row() + 'invalid later row\n')
        r = subprocess.run(['bash', 'bin/list-leafs-by-issuer.sh'], cwd=workspace,
                           env=dict(self.env, INT_DIR='intm-web-ca', OUT='batch.tsv'),
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual((workspace / 'batch.tsv').read_text(), exported)

    def test_real_duplicate_and_revoke_workflow(self):
        workspace = self.base / 'workspace'
        copy_sources(SOURCE, workspace)
        def make(*args, success=True):
            r = subprocess.run(['make', *args, 'KEY_ALG=EC'], cwd=workspace, env=self.env,
                               capture_output=True, text=True)
            self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
            return r
        make('root', 'CN=Stage One Root')
        make('int-web', 'CN=Stage One Web')
        make('server', 'CN=axb')
        make('server', 'CN=a.b')  # Regex matching used to confuse this with axb.
        make('server', 'CN=a.b', success=False)
        make('server', 'CN=a.b', 'ALLOW_DUPLICATE_CN=1')
        ca = workspace / 'intm-web-ca'
        before = snapshot(ca)
        r = make('revoke', 'KIND=web', 'CN=a.b', success=False)
        self.assertIn('Ambiguous CN', r.stderr)
        self.assertEqual(before, snapshot(ca))
        make('revoke', 'KIND=web', 'SERIAL=FFFF', 'CN=axb', success=False)
        self.assertEqual(before, snapshot(ca))
        make('revoke', 'KIND=web', 'SERIAL=00001001', 'CRL_UPDATE=0')
        make('revoke', 'KIND=web', 'CN=a.b', 'CRL_UPDATE=0')
        statuses = {line.split('\t')[3]: line.split('\t')[0] for line in (ca / 'index.txt').read_text().splitlines()}
        self.assertEqual(statuses, {'1000': 'V', '1001': 'R', '1002': 'R'})
        # stdout is pure TSV; a valid active listing exits successfully.
        r = subprocess.run(['bash', 'bin/list-leafs-by-issuer.sh'], cwd=workspace,
                           env=dict(self.env, INT_DIR='intm-web-ca', OUT='-'), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split('\t')[2], 'axb')
        # A malformed later row cannot run an earlier batch command.
        (workspace / 'batch.tsv').write_text('1000\t2027-01-01T00:00:00Z\taxb\tunknown\nbad\n')
        r = subprocess.run(['bash', 'bin/intm-reissue-leafs.sh'], cwd=workspace,
                           env=dict(self.env, KIND='web', INPUT='batch.tsv', ISSUE_CMD='touch executed'),
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((workspace / 'executed').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
