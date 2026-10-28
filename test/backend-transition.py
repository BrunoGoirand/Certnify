#!/usr/bin/env python3
"""Opt-in 3.x/4.1.x lifecycle and verified-resume checks; disposable PKIs only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Transition(unittest.TestCase):
    backends = ()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-backend-transition-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = {key: os.environ[key] for key in ('PATH', 'TMPDIR') if key in os.environ}
        self.env.update(LC_ALL='C', KEY_ALG='EC')

    def fresh(self, name, backend):
        self.work = self.base / name
        copy_sources(SOURCE, self.work)
        self.backend = backend
        self.make('root', 'CN=Transition Root')
        self.make('int-web', 'CN=Transition Web')

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work,
                                env=dict(self.env, OPENSSL=self.backend, **env),
                                capture_output=True, text=True, timeout=180)
        # Failure reports must not dump keys, backend text or recovery journals.
        self.assertEqual(result.returncode == 0, success,
                         'Unexpected exit {} for {}'.format(result.returncode, command))
        return result

    def make(self, *args, **env):
        return self.run_cmd(['make', *args], **env)

    def number(self, name, base='intm-web-ca'):
        return int((self.work / base / name).read_text(), 16)

    def digest(self, name):
        return hashlib.sha256((self.work / name).read_bytes()).hexdigest()

    def verify(self, name, success=True, base='intm-web-ca'):
        return self.make('verify', 'INT_DIR=' + base, 'CN=' + name,
                         'VERIFY_MODE=strict', 'VERIFY_DNS=' + name,
                         'VERIFY_PURPOSE=sslserver', 'VERIFY_CRL=1', success=success)

    def assert_read_only_verification(self, names, revoked=(), base='intm-web-ca'):
        before = snapshot(self.work)
        for backend in self.backends:
            self.backend = backend
            for name in names:
                self.verify(name, base=base)
            for name in revoked:
                self.verify(name, success=False, base=base)
        self.assertEqual(before, snapshot(self.work))

    def test_upgrade_lifecycle_and_switch_back(self):
        old, new = self.backends
        self.fresh('lifecycle', old)
        self.make('server', 'CN=keep.example', 'KEY_ALG=RSA', 'KEY_SIZE=2048',
                  'O=Équipe / PKI', 'SAN=DNS:keep.example,URI:urn:transition:keep')
        self.make('server', 'CN=held.example')
        self.make('server', 'CN=revoked.example')
        self.make('crl-root')
        self.make('crl', 'KIND=web')
        immutable = ['root/private/ca.key.pem', 'root/certs/ca.cert.pem',
                     'intm-web-ca/private/ca.key.pem', 'intm-web-ca/certs/ca.cert.pem']
        for name in ('keep', 'held', 'revoked'):
            immutable += ['intm-web-ca/private/' + name + '.example.key.pem',
                          'intm-web-ca/certs/' + name + '.example.cert.pem']
        preserved = {path: self.digest(path) for path in immutable}
        bindings = {p.name: p.read_text().splitlines()[0]
                    for p in (self.work / 'intm-web-ca/issuers').iterdir()
                    if p.name in ('1000', '1001', '1002')}
        self.assertEqual(len(bindings), 3)
        self.assert_read_only_verification(['keep.example', 'held.example', 'revoked.example'])

        self.backend = new
        serial = self.number('serial')
        self.make('server', 'CN=fresh.example')
        self.assertEqual(self.number('serial'), serial + 1)
        crl_number = self.number('crlnumber')
        self.make('crl', 'KIND=web')
        self.assertEqual(self.number('crlnumber'), crl_number + 1)
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=certificateHold')
        self.assert_read_only_verification(['fresh.example'], ['held.example'])
        self.backend = new
        before = snapshot(self.work)
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=removeFromCRL', DRY_RUN='1')
        self.assertEqual(before, snapshot(self.work))
        self.make('revoke', 'KIND=web', 'CN=held.example', 'REASON=removeFromCRL')
        self.make('revoke', 'KIND=web', 'CN=revoked.example', 'REASON=keyCompromise')
        before = snapshot(self.work)
        self.make('revoke', 'KIND=web', 'CN=revoked.example', 'REASON=removeFromCRL', success=False)
        self.assertEqual(before, snapshot(self.work))
        self.assertEqual(self.number('serial'), serial + 1)
        self.assert_read_only_verification(['keep.example', 'held.example', 'fresh.example'], ['revoked.example'])
        for path, digest in preserved.items():
            self.assertEqual(self.digest(path), digest, path)

        self.backend = new
        root_serial = self.number('serial', 'root')
        old_serial = self.number('serial')
        self.make('rollover-web', 'INT_CN=Transition Replacement')
        legacy = next(self.work.glob('intm-web-ca-legacy-*')).name
        self.assertEqual(self.number('serial', 'root'), root_serial + 1)
        self.assertEqual(self.number('serial', legacy), old_serial)
        for path, digest in preserved.items():
            self.assertEqual(self.digest(path.replace('intm-web-ca/', legacy + '/')), digest)
        for serial_hex, binding in bindings.items():
            self.assertEqual((self.work / legacy / 'issuers' / serial_hex).read_text().splitlines()[0], binding)
        history = snapshot(self.work / legacy)
        self.make('list-leafs-web')
        next_serial = self.number('serial')
        before = snapshot(self.work)
        self.make('reissue-leafs-web', DRY_RUN='1')
        self.assertEqual(before, snapshot(self.work))
        result = self.make('reissue-leafs-web')
        self.assertTrue('completed=3' in result.stdout)
        self.assertEqual(self.number('serial'), next_serial + 3)
        self.assertEqual(history, snapshot(self.work / legacy))
        before = snapshot(self.work)
        result = self.make('reissue-leafs-web')
        self.assertTrue('already_completed=3' in result.stdout)
        self.assertEqual(before, snapshot(self.work))
        rows = (self.work / 'intm-web-ca/index.txt').read_text().splitlines()
        self.assertEqual(len({row.split('\t')[3] for row in rows}), 3)
        for serial_hex in [row.split('\t')[3] for row in rows]:
            binding = (self.work / 'intm-web-ca/issuers' / serial_hex).read_text().splitlines()[0]
            self.assertNotIn(binding, set(bindings.values()))
        # Preserving reissuance uses serial-prefixed artifact names. Compare the
        # committed certificate history, not an assumed canonical filename.
        certificates = [legacy + '/newcerts/1000.pem',
                        'intm-web-ca/newcerts/{:X}.pem'.format(next_serial)]
        for option in [('-subject', '-nameopt', 'RFC2253'), ('-ext', 'subjectAltName')]:
            texts = [self.run_cmd([new, 'x509', '-in', cert,
                                  '-noout', *option]).stdout for cert in certificates]
            self.assertEqual(texts[0], texts[1])
        public_keys = [self.run_cmd([new, 'x509', '-in', cert, '-noout', '-pubkey']).stdout
                       for cert in certificates]
        self.assertNotEqual(public_keys[0], public_keys[1])
        self.make('crl', 'KIND=web')
        self.assert_read_only_verification(['keep.example', 'held.example', 'fresh.example'])
        self.assert_read_only_verification(['keep.example', 'held.example'], ['revoked.example'], base=legacy)

        # Switching the executable back must allow new operations, not just reads.
        self.backend = old
        serial = self.number('serial')
        self.make('server', 'CN=back.example')
        self.assertEqual(self.number('serial'), serial + 1)
        self.make('revoke', 'KIND=web', 'CN=fresh.example', 'REASON=keyCompromise')
        self.make('crl-root')
        self.make('crl', 'KIND=web')
        self.assert_read_only_verification(['back.example', 'keep.example'], ['fresh.example'])
        self.assertEqual(history, snapshot(self.work / legacy))

    def test_verified_resume_across_backend_change_both_directions(self):
        for index, (signer, resumer) in enumerate([self.backends, self.backends[::-1]]):
            with self.subTest(direction=index):
                self.fresh('resume-' + str(index), signer)
                shims = self.base / ('shims-' + str(index))
                shims.mkdir()
                move = shims / 'mv'
                move.write_text('#!/bin/bash\n'
                    'if [[ "$1" == -f && "$2" == */.install.* && "$3" == */certs/resume.example.cert.pem ]]; then exit 71; fi\n'
                    'exec ' + shlex.quote(shutil.which('mv')) + ' "$@"\n')
                move.chmod(0o700)
                self.make('server', 'CN=resume.example', success=False,
                          PATH=str(shims) + os.pathsep + self.env['PATH'])
                self.assertTrue((self.work / '.recovery/pending/ready').is_file())
                # This is an orderly injected installation failure: no stale
                # lock is removed and no recovery evidence is edited or erased.
                self.assertFalse((self.work / '.locks/root-ca.lock').exists())
                committed = {name: snapshot(self.work / 'intm-web-ca' / name)
                             for name in ('newcerts', 'issuers')}
                counters = {name: self.digest('intm-web-ca/' + name)
                            for name in ('serial', 'index.txt', 'crlnumber')}
                self.backend = resumer
                before = snapshot(self.work)
                result = self.make('server', 'CN=blocked.example', success=False)
                self.assertTrue('Unresolved operation' in result.stderr)
                self.assertEqual(before, snapshot(self.work))
                verifier = shims / 'verify-only'
                verifier.write_text('#!/bin/bash\n'
                    'case "$1" in ca|req|genpkey) exit 96;; esac\n'
                    'exec ' + shlex.quote(resumer) + ' "$@"\n')
                verifier.chmod(0o700)
                self.backend = str(verifier)
                self.run_cmd(['/bin/bash', 'bin/recovery.sh'], RECOVERY_ACTION='resume')
                self.assertFalse((self.work / '.recovery/pending').exists())
                self.assertFalse((self.work / '.recovery/power-loss').exists())
                for name, value in counters.items():
                    self.assertEqual(self.digest('intm-web-ca/' + name), value)
                for name, value in committed.items():
                    self.assertEqual(snapshot(self.work / 'intm-web-ca' / name), value)
                self.assertEqual(self.digest('intm-web-ca/certs/resume.example.cert.pem'),
                                 self.digest('intm-web-ca/newcerts/1000.pem'))
                self.backend = resumer
                self.make('crl-root')
                self.make('crl', 'KIND=web')
                self.assert_read_only_verification(['resume.example'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl3', required=True)
    parser.add_argument('--openssl41', required=True)
    parser.add_argument('--test', choices=unittest.defaultTestLoader.getTestCaseNames(Transition),
                        help='Run one method; by default run the complete transition suite')
    args = parser.parse_args()
    os.umask(0o077)
    identities = []
    for value, family in [(args.openssl3, r'3\.[0-9]+\.[0-9]+'), (args.openssl41, r'4\.1\.[0-9]+')]:
        path = Path(value).expanduser().resolve(strict=True)
        env = {key: os.environ[key] for key in ('PATH', 'TMPDIR') if key in os.environ}
        env['LC_ALL'] = 'C'
        version = subprocess.check_output([str(path), 'version'], env=env, text=True, timeout=10).strip()
        fields = version.split()
        if len(fields) < 2 or fields[0] != 'OpenSSL' or not re.fullmatch(family, fields[1]):
            parser.error('Executable does not match its requested stable family: ' + str(path))
        identities.append(dict(path=str(path), version=version,
                               sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    if identities[0]['path'] == identities[1]['path']:
        parser.error('Two distinct real executables are required')
    print(json.dumps(dict(platform=platform.platform(), python=sys.version.split()[0],
                          backends=identities)), flush=True)
    Transition.backends = tuple(item['path'] for item in identities)
    suite = (unittest.TestSuite([Transition(args.test)]) if args.test else
             unittest.defaultTestLoader.loadTestsFromTestCase(Transition))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return int(not result.wasSuccessful())


if __name__ == '__main__':
    sys.exit(main())
