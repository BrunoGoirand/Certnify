#!/usr/bin/env python3
"""Hold release, verified recovery and workspace relocation; disposable PKIs only."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Maintenance(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage10-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')
        self.make('root', 'CN=Maintenance Root')
        self.make('int-web', 'CN=Maintenance Web')

    @property
    def ca(self):
        return self.work / 'intm-web-ca'

    def run_cmd(self, command, success=True, **env):
        r = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                           capture_output=True, text=True, timeout=180)
        self.assertEqual(r.returncode == 0, success, r.stdout + r.stderr)
        return r

    def make(self, *args, success=True, **env):
        return self.run_cmd(['make', *args], success, **env)

    def recover(self, action='resume', success=True, **env):
        return self.run_cmd(['bash', 'bin/recovery.sh'], success, RECOVERY_ACTION=action, **env)

    def shim(self, condition, after=False):
        directory = self.work / 'shims'
        directory.mkdir(exist_ok=True)
        real = shlex.quote(shutil.which('mv')) + ' "$@"'
        path = directory / 'mv'
        path.write_text('#!/bin/bash\nif ' + condition + '; then\n' +
                        (real + '\n' if after else '') + 'exit 71\nfi\nexec ' + real + '\n')
        path.chmod(0o700)
        return str(directory) + os.pathsep + self.env['PATH']

    def leaf(self, name='held.example'):
        self.make('server', 'CN=' + name)

    def release(self, success=True, **env):
        return self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=removeFromCRL', success=success, **env)

    def test_leaf_hold_release_and_permanent_revocation(self):
        self.leaf()
        self.make('crl-root')
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=certificateHold')
        self.make('verify', 'KIND=web', 'CN=held.example', 'VERIFY_CRL=1', success=False)
        self.run_cmd(['bash', 'bin/intm-publish-final-crl.sh'], KIND='web', ALLOW_REMAINING_LEAFS='1')
        archived = (self.ca / 'crl/ca.crl.pem').resolve()
        archived_bytes = archived.read_bytes()
        before = snapshot(self.work)
        self.release(DRY_RUN='1')
        self.assertEqual(before, snapshot(self.work))
        self.release(success=False, CRL_UPDATE='0')
        self.assertEqual(before, snapshot(self.work))
        serial = (self.ca / 'serial').read_bytes()
        cert = (self.ca / 'certs/held.example.cert.pem').read_bytes()
        self.release()
        self.assertEqual(serial, (self.ca / 'serial').read_bytes())
        self.assertEqual(cert, (self.ca / 'certs/held.example.cert.pem').read_bytes())
        self.assertEqual(archived_bytes, archived.read_bytes())
        current_crl = (self.ca / 'crl/ca.crl.pem').read_bytes()
        self.run_cmd(['bash', 'bin/intm-publish-final-crl.sh'], success=False, KIND='web',
                     FINAL_CRL=str(archived), ALLOW_REMAINING_LEAFS='1')
        self.assertEqual(current_crl, (self.ca / 'crl/ca.crl.pem').read_bytes())
        der_pem = self.run_cmd([self.backend, 'crl', '-inform', 'DER', '-in', str(self.ca / 'crl/ca.crl'), '-outform', 'PEM']).stdout
        self.assertEqual(der_pem.encode(), current_crl)
        self.make('verify', 'KIND=web', 'CN=held.example', 'VERIFY_CRL=1')
        self.assertTrue((self.ca / 'index.txt').read_text().startswith('V\t'))
        text = self.run_cmd([self.backend, 'crl', '-in', str(self.ca / 'crl/ca.crl.pem'), '-noout', '-text']).stdout
        self.assertIn('No Revoked Certificates', text)
        self.assertNotIn('Remove From CRL', text)
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=keyCompromise')
        before = snapshot(self.work)
        self.release(success=False)
        self.assertEqual(before, snapshot(self.work))

    def test_intermediate_release_preserves_independent_disable_marker(self):
        self.make('revoke-intermediate', 'KIND=web', 'REASON=certificateHold')
        self.assertIn('certificateHold:', (self.ca / '.disabled').read_text())
        self.make('server', 'CN=blocked.example', success=False)
        self.make('revoke-intermediate', 'KIND=web', 'REASON=removeFromCRL')
        self.assertFalse((self.ca / '.disabled').exists())
        self.leaf()
        self.make('revoke-intermediate', 'KIND=web', 'REASON=certificateHold')
        (self.ca / '.disabled').write_text('operator maintenance\n')
        self.make('revoke-intermediate', 'KIND=web', 'REASON=removeFromCRL')
        self.assertEqual((self.ca / '.disabled').read_text(), 'operator maintenance\n')

    def test_historical_release_preserves_current_issuer_crl(self):
        self.leaf()
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=certificateHold')
        self.make('int-web', 'CN=Maintenance Web', 'ROTATE_KEY=1')
        self.make('crl-all', 'CRL_HISTORY=1')
        before = (self.ca / 'crl/ca.crl.pem').read_bytes()
        self.release()
        self.assertEqual(before, (self.ca / 'crl/ca.crl.pem').read_bytes())
        self.make('verify', 'KIND=web', 'CN=held.example', 'VERIFY_CRL=1')

    def test_hold_interruption_after_index_commit_resumes_without_new_crl(self):
        self.leaf()
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=certificateHold')
        path = self.shim('[[ "$1" == -f && "$2" == */.install.* && "$3" == */intm-web-ca/index.txt ]]', after=True)
        self.release(success=False, PATH=path)
        self.assertTrue((self.ca / 'index.txt').read_text().startswith('V\t'))
        counters = [(self.ca / n).read_bytes() for n in ('serial', 'crlnumber')]
        self.recover()
        self.assertFalse((self.work / '.recovery/pending').exists())
        self.assertEqual(counters, [(self.ca / n).read_bytes() for n in ('serial', 'crlnumber')])
        self.make('crl-root')
        self.make('verify', 'KIND=web', 'CN=held.example', 'VERIFY_CRL=1')

    def test_leaf_replacement_recovery_and_evidence_drift(self):
        self.leaf()
        path = self.shim('[[ "$1" == -f && "$2" == */.install.* && "$3" == */certs/held.example.cert.pem ]]')
        self.make('server', 'CN=held.example', 'ALLOW_DUPLICATE_CN=1', 'FORCE_NEW_KEY=1', success=False, PATH=path)
        pending = self.work / '.recovery/pending'
        self.assertTrue((pending / 'ready').exists())
        before = snapshot(self.work)
        self.make('verify', 'KIND=web', 'FILE=certs/held.example.cert.pem',
                  'AUTO_RECOVER=1', 'DRY_RUN=1', success=False)
        self.assertEqual(before, snapshot(self.work))
        serial = (self.ca / 'serial').read_bytes()
        (self.ca / 'serial').write_text('2000\n')
        before = snapshot(self.work)
        self.assertIn('evidence changed', self.recover(success=False).stderr)
        self.assertEqual(before, snapshot(self.work))
        (self.ca / 'serial').write_bytes(serial)
        self.make('verify', 'KIND=web', 'FILE=certs/held.example.cert.pem', 'AUTO_RECOVER=1')
        self.assertEqual(serial, (self.ca / 'serial').read_bytes())
        self.assertFalse(pending.exists())
        for directory, suffix in [('private', 'key.pem'), ('csr', 'csr.pem'), ('certs', 'cert.pem'), ('certs', 'fullchain.cert.pem')]:
            self.assertEqual((self.ca / directory / ('held.example.' + suffix)).read_bytes(),
                             (self.ca / directory / ('srl-1001-held.example.' + suffix)).read_bytes())
        self.recover()

    def test_unsealed_and_corrupt_plans_remain_blocked(self):
        path = self.shim('[[ "$1" == -f && "$2" == */.install.* && "$3" == */certs/held.example.cert.pem ]]')
        self.make('server', 'CN=held.example', success=False, PATH=path)
        pending = self.work / '.recovery/pending'
        ready = (pending / 'ready').read_bytes()
        (pending / 'ready').unlink()
        before = snapshot(self.work)
        self.recover(success=False)
        self.assertEqual(before, snapshot(self.work))
        (pending / 'ready').write_bytes(ready)
        # A valid sealed plan must also refuse an unexpected destination.
        destination = self.ca / 'certs/held.example.cert.pem'
        destination.write_text('unexpected external write')
        before = snapshot(self.work)
        self.recover(success=False)
        self.assertEqual(before, snapshot(self.work))
        destination.unlink()
        # Time is evidence too: do not publish an artifact after its validity.
        directory = self.work / 'clock-shim'
        directory.mkdir()
        date = directory / 'date'
        date.write_text('#!/bin/bash\nif [[ "$*" == "-u +%s" ]]; then echo 253402300799; else exec /bin/date "$@"; fi\n')
        date.chmod(0o700)
        before = snapshot(self.work)
        self.assertIn('expired', self.recover(success=False, PATH=str(directory) + os.pathsep + self.env['PATH']).stderr)
        self.assertEqual(before, snapshot(self.work))
        source = pending / 'files/1'
        source.chmod(0o600); source.write_text('corrupted')
        before = snapshot(self.work)
        self.recover(success=False)
        self.assertEqual(before, snapshot(self.work))

    def test_expired_hold_release_retains_expired_status(self):
        self.leaf()
        self.run_cmd([self.backend, 'ca', '-batch', '-config', str(self.ca / 'openssl.cnf'),
                      '-in', str(self.ca / 'csr/held.example.csr.pem'), '-subj', '/CN=expired.example',
                      '-extensions', 'server_ec', '-startdate', '20000101000000Z',
                      '-enddate', '20010101000000Z', '-out', str(self.ca / 'certs/expired.example.cert.pem')])
        common = ('revoke', 'KIND=web', 'FILE=certs/expired.example.cert.pem')
        self.make(*common, 'REASON=certificateHold')
        serial = (self.ca / 'serial').read_bytes()
        self.make(*common, 'REASON=removeFromCRL')
        rows = [line.split('\t') for line in (self.ca / 'index.txt').read_text().splitlines()]
        self.assertEqual(rows[1][0:3], ['E', '010101000000Z', ''])
        self.assertEqual(serial, (self.ca / 'serial').read_bytes())
        self.make('verify', 'KIND=web', 'FILE=certs/expired.example.cert.pem', success=False)

    def test_recovery_checks_contents_behind_key_alias(self):
        self.leaf()
        key = self.ca / 'private/held.example.key.pem'
        retained = self.ca / 'private/shared.key.pem'
        key.rename(retained)
        key.symlink_to('shared.key.pem')
        path = self.shim('[[ "$1" == -f && "$2" == */.install.* && "$3" == */certs/srl-1001-held.example.cert.pem ]]')
        self.make('server', 'CN=held.example', 'ALLOW_DUPLICATE_CN=1', success=False, PATH=path)
        self.assertTrue((self.work / '.recovery/pending/ready').exists())
        retained.chmod(0o600)
        retained.write_text('changed key target')
        before = snapshot(self.work)
        self.assertIn('evidence changed', self.recover(success=False).stderr)
        self.assertEqual(before, snapshot(self.work))

    def move_workspace(self):
        original = self.work
        self.work = original.with_name('relocated workspace')
        original.rename(self.work)
        original.mkdir()
        (original / 'sentinel').write_text('leave old location untouched')
        return original

    def test_relocation_preserves_nested_authorities_and_absolute_aliases(self):
        self.leaf()
        self.make('rollover-web', 'INT_CN=Replacement Web')
        legacy = next(self.work.glob('intm-web-ca-legacy-*'))
        self.make('intermediate', 'INT_DIR=pki-data/custom', 'CN=Nested CA')
        self.make('crl', 'KIND=web')
        (self.ca / 'crl/absolute-alias.pem').symlink_to(self.ca / 'crl/ca.crl.pem')
        (self.work / 'web-alias').symlink_to(legacy, target_is_directory=True)
        preserved = {p.relative_to(self.work).as_posix(): p.read_bytes() for p in self.work.rglob('*')
                     if p.is_file() and (p.name in ('index.txt', 'serial', 'crlnumber') or p.suffix == '.pem')}
        old = self.move_workspace()
        before = snapshot(self.work)
        self.recover('relocate')
        self.assertEqual(before, snapshot(self.work))
        self.recover('relocate', RELOCATE_APPLY='1')
        for name, data in preserved.items(): self.assertEqual(data, (self.work / name).read_bytes(), name)
        self.assertEqual((old / 'sentinel').read_text(), 'leave old location untouched')
        self.assertEqual(os.readlink(self.ca / 'crl/absolute-alias.pem'), str((self.ca / 'crl/ca.crl.pem').resolve()))
        self.make('server', 'INT_DIR=pki-data/custom', 'CN=after-move.example')
        self.make('verify', 'INT_DIR=' + legacy.name, 'CN=held.example')
        self.make('verify', 'INT_DIR=web-alias', 'CN=held.example')

    def test_relocation_interruption_is_resumable(self):
        (self.work / 'web-alias').symlink_to(self.ca, target_is_directory=True)
        self.move_workspace()
        path = self.shim('[[ "$1" == -f && "$2" == */.install.* && "$3" == */root/openssl.cnf ]]', after=True)
        self.recover('relocate', success=False, RELOCATE_APPLY='1', PATH=path)
        self.assertTrue((self.work / '.recovery/pending/ready').exists())
        # Interrupt again after unlinking a directory alias but before recreating it.
        shim = self.work / 'shims/ln'
        shim.write_text('#!/bin/bash\nif [[ "${!#}" == */web-alias ]]; then exit 72; fi\nexec /bin/ln "$@"\n')
        shim.chmod(0o700)
        self.recover(success=False, PATH=path)
        self.assertFalse((self.work / 'web-alias').is_symlink())
        self.recover()
        self.assertTrue((self.work / 'web-alias').is_symlink())
        self.make('crl-root')
        self.leaf()

    def test_relocation_preflight_rejects_unsafe_configuration(self):
        self.move_workspace()
        config = self.ca / 'openssl.cnf'
        config.write_text(config.read_text() + '\n.include /outside/config.cnf\n')
        before = snapshot(self.work)
        self.recover('relocate', success=False, RELOCATE_APPLY='1')
        self.assertEqual(before, snapshot(self.work))


if __name__ == '__main__':
    unittest.main(verbosity=2)
