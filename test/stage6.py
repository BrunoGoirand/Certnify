#!/usr/bin/env python3
"""Commit-boundary failures, explicit recovery review, and local publication."""
import base64
import hashlib
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage6-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = {'PATH': os.environ['PATH'], 'OPENSSL': self.backend, 'LC_ALL': 'C'}
        self.make('root', 'CN=Recovery Root')
        self.make('int-web', 'CN=Recovery Web')
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args, 'KEY_ALG=EC'], success, **env)

    def wrapper(self, body):
        path = self.work / 'backend'
        path.write_text('#!/bin/bash\n' + body + '\nexec ' + shlex.quote(self.backend) + ' "$@"\n')
        path.chmod(0o700)
        return str(path)

    def acknowledge(self):
        pending = self.work / '.recovery/pending'
        identity = (pending / 'operation').read_text().splitlines()[0].split('=', 1)[1]
        self.run_cmd(['bash', 'bin/recovery.sh'], RECOVERY_ACTION='acknowledge',
                     RECOVERY_ID=identity, RECOVERY_NOTE='Fixture artifacts and committed state inspected; retain all serials.')
        self.assertFalse(pending.exists())
        self.assertTrue((self.work / ('.recovery/reviewed-' + identity) / 'review').exists())

    def final(self, success=True, **env):
        return self.run_cmd(['bash', 'bin/intm-publish-final-crl.sh'], success, KIND='web', **env)

    def shim(self, executable, condition, after=False):
        directory = self.work / 'shims'
        directory.mkdir(exist_ok=True)
        real = shutil.which(executable)
        path = directory / executable
        call = shlex.quote(real) + ' "$@"'
        path.write_text('#!/bin/bash\nif ' + condition + '; then\n' +
                        (call + '\n' if after else '') + 'exit 71\nfi\nexec ' + call + '\n')
        path.chmod(0o700)
        return str(directory) + os.pathsep + self.env['PATH']

    def test_backend_before_and_after_commit_blocks_retry(self):
        for after in (False, True):
            with self.subTest(after=after):
                before = (self.ca / 'serial').read_text()
                body = 'if [[ "$1" == ca && " $* " == *" -in "* ]]; then\n'
                if after: body += shlex.quote(self.backend) + ' "$@" || exit\n'
                body += 'exit 72\nfi'
                result = self.make('server', 'CN=uncertain.example', success=False, OPENSSL=self.wrapper(body))
                self.assertIn('Recovery required', result.stderr)
                self.assertEqual((self.ca / 'serial').read_text() == before, not after)
                if after: self.assertTrue((self.ca / 'newcerts' / (before.strip() + '.pem')).exists())
                state = snapshot(self.ca)
                result = self.make('server', 'CN=retry.example', success=False, PKI_RECOVERY_OWNED='1')
                self.assertIn('Unresolved operation', result.stderr)
                self.assertEqual(state, snapshot(self.ca))
                before_report = snapshot(self.work)
                self.run_cmd(['bash', 'bin/recovery.sh'])
                self.assertEqual(before_report, snapshot(self.work))
                self.acknowledge()
        self.make('server', 'CN=next.example')
        serials = [row.split('\t')[3] for row in (self.ca / 'index.txt').read_text().splitlines()]
        self.assertEqual(serials, ['1000', '1001'])

    def test_leaf_rekey_failure_preserves_old_pair(self):
        self.make('server', 'CN=rekey.example')
        old_key = (self.ca / 'private/rekey.example.key.pem').read_bytes()
        old_cert = (self.ca / 'certs/rekey.example.cert.pem').read_bytes()
        wrapper = self.wrapper('if [[ "$1" == ca && " $* " == *" -in "* ]]; then exit 79; fi')
        self.make('server', 'CN=rekey.example', 'ALLOW_DUPLICATE_CN=1', 'FORCE_NEW_KEY=1',
                  success=False, OPENSSL=wrapper)
        self.assertEqual(old_key, (self.ca / 'private/rekey.example.key.pem').read_bytes())
        self.assertEqual(old_cert, (self.ca / 'certs/rekey.example.cert.pem').read_bytes())
        self.assertTrue(list((self.ca / 'private').glob('rekey.example.key.*.bak.pem')))
        self.acknowledge()
        self.make('server', 'CN=rekey.example', 'ALLOW_DUPLICATE_CN=1', 'FORCE_NEW_KEY=1')
        self.assertNotEqual(old_key, (self.ca / 'private/rekey.example.key.pem').read_bytes())
        self.assertNotEqual(old_cert, (self.ca / 'certs/rekey.example.cert.pem').read_bytes())
        for directory, suffix in [('private', 'key.pem'), ('csr', 'csr.pem'),
                                  ('certs', 'cert.pem'), ('certs', 'fullchain.cert.pem')]:
            self.assertEqual((self.ca / directory / ('rekey.example.' + suffix)).read_bytes(),
                             (self.ca / directory / ('srl-1001-rekey.example.' + suffix)).read_bytes())
        key = self.run_cmd([self.backend, 'pkey', '-in', str(self.ca / 'private/rekey.example.key.pem'), '-pubout']).stdout
        cert = self.run_cmd([self.backend, 'x509', '-in', str(self.ca / 'certs/rekey.example.cert.pem'), '-noout', '-pubkey']).stdout
        self.assertEqual(key, cert)
        self.assertEqual(old_cert, (self.ca / 'newcerts/1000.pem').read_bytes())

    def test_rekey_failure_preserves_old_pair_and_metadata(self):
        old = {name: (self.ca / name).read_bytes() for name in
               ['private/ca.key.pem', 'certs/ca.cert.pem', 'certs/ca.chain.cert.pem', 'ca.meta']}
        wrapper = self.wrapper('if [[ "$1" == ca && " $* " == *" -in "* ]]; then exit 73; fi')
        self.make('int-web', 'CN=Recovery Web', 'ROTATE_KEY=1', success=False, OPENSSL=wrapper)
        for name, data in old.items(): self.assertEqual(data, (self.ca / name).read_bytes(), name)
        self.assertTrue(list((self.ca / 'private').glob('.replacement.*')))
        self.assertTrue(list((self.ca / 'generations').glob('*/ca.key.pem')))
        self.acknowledge()
        self.make('int-web', 'CN=Recovery Web', 'ROTATE_KEY=1')

    def test_certificate_install_failure_and_post_verify_failure(self):
        path = self.shim('mv', '[[ "$1" == -f && "$2" == */.install.* && "$3" == */certs/install.example.cert.pem ]]')
        self.make('server', 'CN=install.example', success=False, PATH=path)
        self.assertFalse((self.ca / 'certs/install.example.cert.pem').exists())
        self.assertTrue((self.ca / 'newcerts/1000.pem').exists())
        self.assertIn('issuance-committed', (self.work / '.recovery/pending/phase').read_text())
        self.acknowledge()
        wrapper = self.wrapper('if [[ "$1" == verify && " $* " == *"/post.example.cert.pem "* ]]; then exit 74; fi')
        self.make('server', 'CN=post.example', success=False, OPENSSL=wrapper)
        self.assertTrue((self.ca / 'certs/post.example.cert.pem').exists())
        self.assertIn('post-verification', (self.work / '.recovery/pending/phase').read_text())
        self.assertEqual((self.ca / 'serial').read_text().strip(), '1002')

    def test_lifecycle_move_failures_preserve_history_and_block_restart(self):
        self.make('server', 'CN=history.example')
        old_key = (self.ca / 'private/ca.key.pem').read_bytes()
        old_index = (self.ca / 'index.txt').read_bytes()
        for after in (False, True):
            with self.subTest(after=after):
                path = self.shim('mv', '[[ "$1" == intm-web-ca && "$2" == intm-web-ca-legacy-* ]]', after)
                self.make('rollover-web', 'INT_CN=New Web', success=False, PATH=path)
                preserved = next(self.work.glob('intm-web-ca-legacy-*')) if after else self.ca
                self.assertEqual(old_key, (preserved / 'private/ca.key.pem').read_bytes())
                self.assertEqual(old_index, (preserved / 'index.txt').read_bytes())
                self.make('rollover-web', 'INT_CN=New Web', success=False)
                if after:
                    # Manual reconciliation example: restore directory to the still-bound old path.
                    preserved.rename(self.ca)
                self.acknowledge()
        self.make('rollover-web', 'INT_CN=New Web')
        path = self.shim('mv', '[[ "$1" == intm-web-ca-legacy-* && "$2" == intm-web-ca ]]', True)
        self.make('rollback-web', success=False, PATH=path)
        self.assertEqual(old_index, (self.ca / 'index.txt').read_bytes())
        self.assertTrue(list(self.work.glob('intm-web-ca-pre-rollback-*')))
        self.make('server', 'CN=blocked.example', success=False)

    def test_killed_issuer_keeps_pending_journal_and_stale_lock(self):
        body = 'if [[ "$1" == ca && " $* " == *" -in "* ]]; then\n' + shlex.quote(self.backend) + ' "$@" || exit\nkill -KILL "$PPID"\nexit 75\nfi'
        result = self.make('server', 'CN=killed.example', success=False, OPENSSL=self.wrapper(body))
        self.assertTrue((self.work / '.recovery/pending').exists())
        self.assertTrue((self.work / '.locks/root-ca.lock').exists())
        self.assertTrue((self.ca / 'newcerts/1000.pem').exists())
        self.run_cmd(['bash', 'bin/recovery.sh'])
        result = self.make('server', 'CN=killed.example', 'LOCK_TIMEOUT=0', success=False)
        self.assertIn('locks are never stolen', result.stderr)
        # The killed fixture process has exited; administrative stale-lock recovery only.
        shutil.rmtree(self.work / '.locks/root-ca.lock')
        self.make('server', 'CN=killed.example', success=False)
        self.acknowledge()
        self.make('server', 'CN=after-kill.example')
        self.assertEqual((self.ca / 'serial').read_text().strip(), '1002')

    def test_root_failure_preserves_key_and_requires_review(self):
        root = self.work / 'root'
        shutil.rmtree(root)  # Disposable fixture only: exercise a fresh root boundary.
        wrapper = self.wrapper('if [[ "$1" == req && " $* " == *" -x509 "* ]]; then exit 78; fi')
        self.make('root', 'CN=New Root', success=False, OPENSSL=wrapper)
        self.assertFalse((root / 'certs/ca.cert.pem').exists())
        key = (root / 'private/ca.key.pem').read_bytes()
        self.make('root', 'CN=New Root', success=False)
        self.acknowledge()
        self.make('root', 'CN=New Root')
        self.assertEqual(key, (root / 'private/ca.key.pem').read_bytes())
        self.assertTrue((root / 'ca.meta').exists())

    def test_metadata_replacement_failure_preserves_previous_file(self):
        previous = (self.ca / 'ca.meta').read_bytes()
        serial = (self.work / 'root/serial').read_text().strip()
        path = self.shim('mv', '[[ "$2" == */.meta.* && "$3" == */ca.meta ]]')
        self.make('int-web', 'CN=Recovery Web', 'ROTATE_KEY=1', success=False, PATH=path)
        self.assertEqual(previous, (self.ca / 'ca.meta').read_bytes())
        self.assertTrue((self.work / ('root/newcerts/' + serial + '.pem')).exists())
        self.assertTrue((self.work / '.recovery/pending').exists())
        self.assertTrue((self.ca / 'certs/ca-1000.cert.pem').exists())
        self.assertTrue((self.ca / ('certs/ca-' + serial + '.cert.pem')).exists())

    def test_final_expiry_guard_dry_run_and_advisory_semantics(self):
        self.make('server', 'CN=live.example')
        before = snapshot(self.work)
        self.final(success=False)
        self.assertEqual(before, snapshot(self.work))
        self.final(DRY_RUN='1', ALLOW_REMAINING_LEAFS='1')
        self.assertEqual(before, snapshot(self.work))
        # OpenSSL-issued expired certificate deliberately retains V in the index.
        self.make('revoke', 'KIND=web', 'CN=live.example', 'CRL_UPDATE=0')
        self.run_cmd([self.backend, 'ca', '-batch', '-config', str(self.ca / 'openssl.cnf'),
                      '-in', str(self.ca / 'csr/live.example.csr.pem'), '-subj', '/CN=expired.example',
                      '-extensions', 'server_ec', '-startdate', '20000101000000Z', '-enddate', '20010101000000Z',
                      '-out', str(self.ca / 'certs/expired.cert.pem')])
        old_index = (self.ca / 'index.txt').read_bytes()
        self.final(CRL_HOURS='2', CRL_DAYS='99')
        self.assertEqual(old_index, (self.ca / 'index.txt').read_bytes())
        self.assertFalse((self.ca / '.disabled').exists())
        dates = self.run_cmd([self.backend, 'crl', '-in', str(self.ca / 'crl/ca.crl.pem'), '-noout', '-lastupdate', '-nextupdate']).stdout
        import ssl
        times = [ssl.cert_time_to_seconds(line.split('=', 1)[1]) for line in dates.splitlines()]
        self.assertEqual(times[1] - times[0], 7200)
        self.make('server', 'CN=still-enabled.example')
        self.make('crl', 'KIND=web')

    def test_digest_encodings_backend_and_publication_retry(self):
        wrapper = self.wrapper('printf "%s\\n" "$1" >> backend-calls')
        remote = self.work / 'remote'; remote.mkdir()
        command = 'if [[ %FILE% == ca.crl.pem ]]; then exit 76; fi; cp -fL %FILE% ' + shlex.quote(str(remote)) + '/'
        result = self.final(success=False, OPENSSL=wrapper, PUBLISH_CMD=command)
        self.assertIn('artifact=ca.crl.pem status=failed', result.stderr)
        self.assertIn('Local CRL committed', result.stderr)
        pem = next((self.ca / 'crl').glob('ca-*.crl.pem'))
        der = pem.with_suffix('')
        decoded = subprocess.check_output([self.backend, 'crl', '-in', str(pem), '-outform', 'DER'])
        self.assertEqual(decoded, der.read_bytes())
        digest = hashlib.sha256(decoded).digest()
        self.assertEqual(Path(str(pem) + '.sha256').read_bytes(), digest.hex().upper().encode() + b'\n')
        self.assertEqual(Path(str(der) + '.sha256').read_bytes(), base64.b64encode(digest) + b'\n')
        calls = ''.join(p.read_text() for p in self.work.rglob('backend-calls'))
        self.assertIn('base64', calls)
        counter = (self.ca / 'crlnumber').read_bytes()
        self.final(FINAL_CRL=str(pem), PUBLISH_CMD='cp -fL %FILE% ' + shlex.quote(str(remote)) + '/')
        self.assertEqual(counter, (self.ca / 'crlnumber').read_bytes())
        self.assertEqual(len(list(remote.iterdir())), 6)
        self.assertEqual((remote / 'ca.crl.pem').read_bytes(), pem.read_bytes())

    def test_failed_der_and_alias_preserve_latest_and_resume(self):
        self.final()
        old = os.readlink(self.ca / 'crl/ca.crl.pem')
        wrapper = self.wrapper('if [[ "$1" == crl && " $* " == *" -outform DER "* ]]; then exit 77; fi')
        self.final(success=False, OPENSSL=wrapper)
        self.assertEqual(old, os.readlink(self.ca / 'crl/ca.crl.pem'))
        pem = next(p for p in (self.ca / 'crl').glob('ca-*.crl.pem') if p.name != old)
        counter = (self.ca / 'crlnumber').read_bytes()
        path = self.shim('mv', '[[ "$2" == */.alias.*/link && "$3" == */ca.crl.pem ]]')
        self.final(success=False, FINAL_CRL=str(pem), PATH=path)
        self.assertEqual(old, os.readlink(self.ca / 'crl/ca.crl.pem'))
        self.final(FINAL_CRL=str(pem))
        self.assertEqual(counter, (self.ca / 'crlnumber').read_bytes())
        self.assertEqual(pem.name, os.readlink(self.ca / 'crl/ca.crl.pem'))

    def test_resume_refuses_new_revocations_and_newer_crls(self):
        self.make('server', 'CN=revoked.example')
        self.final(ALLOW_REMAINING_LEAFS='1')
        old = next((self.ca / 'crl').glob('ca-*.crl.pem'))
        self.make('revoke', 'KIND=web', 'CN=revoked.example', 'CRL_UPDATE=0')
        before = snapshot(self.work)
        result = self.final(success=False, FINAL_CRL=str(old))
        self.assertIn('CRL resume state changed', result.stderr)
        self.assertEqual(before, snapshot(self.work))
        self.final()
        newer = next(p for p in (self.ca / 'crl').glob('ca-*.crl.pem') if p != old)
        self.make('crl-root')
        before = snapshot(self.work)
        self.final(success=False, FINAL_CRL=str(old), PUBLISH_CMD='touch must-not-publish')
        self.assertEqual(before, snapshot(self.work))
        result = self.make('verify', 'KIND=web', 'CN=revoked.example', 'VERIFY_CRL=1', success=False)
        self.assertIn('VERIFY STATUS: REVOKED', result.stdout)
        # A later CRL, even with identical revoked entries, prevents rollback.
        self.final()
        before = snapshot(self.work)
        self.final(success=False, FINAL_CRL=str(newer))
        self.assertEqual(before, snapshot(self.work))

    def test_resume_requires_unchanged_record_and_refresh_failure_preserves_aliases(self):
        self.final()
        archive = next((self.ca / 'crl').glob('ca-*.crl.pem'))
        state = Path(str(archive) + '.resume-state')
        saved = state.read_bytes()
        state.unlink()
        before = snapshot(self.work)
        self.final(success=False, FINAL_CRL=str(archive))
        self.assertEqual(before, snapshot(self.work))
        state.write_bytes(saved)
        wrapper = self.wrapper('if [[ "$1" == crl && " $* " == *" -outform DER "* ]]; then exit 77; fi')
        before = snapshot(self.ca / 'crl')
        self.make('crl', 'KIND=web', success=False, OPENSSL=wrapper)
        self.assertEqual(before, snapshot(self.ca / 'crl'))
        # Failed generation may consume a counter: conservative retry requires a new CRL.
        self.final(success=False, FINAL_CRL=str(archive))
        self.final()

    def test_forced_first_key_has_matching_canonical_and_serial_artifacts(self):
        self.make('server', 'CN=first.example', 'FORCE_NEW_KEY=1')
        for directory, suffix in [('private', 'key.pem'), ('csr', 'csr.pem'),
                                  ('certs', 'cert.pem'), ('certs', 'fullchain.cert.pem')]:
            self.assertEqual((self.ca / directory / ('first.example.' + suffix)).read_bytes(),
                             (self.ca / directory / ('srl-1000-first.example.' + suffix)).read_bytes())
        self.make('verify', 'KIND=web', 'CN=first.example')

    def test_refresh_preserves_final_archives_and_updates_both_formats(self):
        self.make('server', 'CN=refresh.example')
        self.final(ALLOW_REMAINING_LEAFS='1')
        archive = next((self.ca / 'crl').glob('ca-*.crl.pem'))
        files = [archive, archive.with_suffix(''), Path(str(archive) + '.sha256'),
                 Path(str(archive.with_suffix('')) + '.sha256'), Path(str(archive) + '.resume-state')]
        old = {p: p.read_bytes() for p in files}
        self.make('revoke', 'KIND=web', 'CN=refresh.example')
        for p, data in old.items(): self.assertEqual(data, p.read_bytes(), str(p))
        for command in [None, ('crl', 'KIND=web'), ('crl-all', 'CRL_HISTORY=1')]:
            if command: self.make(*command)
            for p, data in old.items(): self.assertEqual(data, p.read_bytes(), str(p))
            pem = self.ca / 'crl/ca.crl.pem'
            der = self.ca / 'crl/ca.crl'
            self.assertFalse(pem.is_symlink())
            self.assertFalse(der.is_symlink())
            decoded = subprocess.check_output([self.backend, 'crl', '-in', str(pem), '-outform', 'DER'])
            self.assertEqual(decoded, der.read_bytes())
        self.make('crl-root')
        result = self.make('verify', 'KIND=web', 'CN=refresh.example', 'VERIFY_CRL=1', success=False)
        self.assertIn('VERIFY STATUS: REVOKED', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
