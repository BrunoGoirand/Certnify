#!/usr/bin/env python3
"""Authority issuance categories; disposable PKIs, no production state."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class IssuanceCategories(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='certnify-stage12-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name) / 'work'
        copy_sources(SOURCE, self.work)
        self.backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
        self.env = dict(PATH=os.environ['PATH'], OPENSSL=self.backend, LC_ALL='C', KEY_ALG='EC')
        self.run_cmd(['make', 'root', 'CN=Category Root'])
        self.run_cmd(['make', 'int-web', 'CN=Category Web'])
        self.ca = self.work / 'intm-web-ca'

    def run_cmd(self, command, success=True, **env):
        result = subprocess.run(command, cwd=self.work, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def refuse_unchanged(self, command, **env):
        before = snapshot(self.work)
        result = self.run_cmd(command, False, **env)
        self.assertEqual(before, snapshot(self.work))
        return result

    def test_cross_category_routes_and_environment_overrides(self):
        for command, env in [
            (['make', 'dev', 'INT_DIR=intm-web-ca', 'CN=wrong'], {}),
            (['make', 'server', 'CN=wrong', 'PROFILE=code_sign'], {}),
            (['bin/gen-leaf.sh'], dict(INT_DIR='intm-web-ca', CN='wrong', EXT_SECTION='code_sign')),
            (['bin/gen-leaf.sh'], dict(INT_DIR='intm-web-ca', KIND='generic', CN='wrong',
                                     EXT_SECTION='code_sign', REQUIRE_STRICT_KIND='0', ALLOW_KIND_FROM_DIR='0')),
        ]:
            with self.subTest(command=command, env=env):
                self.assertIn('Issuance category', self.refuse_unchanged(command, **env).stderr)
        self.run_cmd(['make', 'server', 'CN=allowed.example'])

    def test_compiled_custom_profiles_missing_multiple_and_oid_alias_ekus(self):
        config = self.ca / 'openssl.cnf'
        original = config.read_text()
        prefix = ('\n[ custom ]\nbasicConstraints=critical,CA:false\n'
                  'keyUsage=critical,digitalSignature\n')
        for extension in ['', 'extendedKeyUsage=codeSigning\n',
                          'extendedKeyUsage=serverAuth,codeSigning\n',
                          'extendedKeyUsage=anyExtendedKeyUsage\n',
                          '2.5.29.37=DER:30:0A:06:08:2B:06:01:05:05:07:03:03\n',
                          'extendedKeyUsage=serverAuth\n2.5.29.37=DER:30:0A:06:08:2B:06:01:05:05:07:03:03\n']:
            config.write_text(original + prefix + extension)
            with self.subTest(extension=extension):
                self.refuse_unchanged(['make', 'server', 'CN=wrong.example', 'PROFILE=custom'])
        # The installed section name is not trusted either.
        config.write_text(original.replace('extendedKeyUsage       = serverAuth',
                                           'extendedKeyUsage       = codeSigning'))
        self.refuse_unchanged(['make', 'server', 'CN=wrong.example'])
        config.write_text(original + prefix + 'extendedKeyUsage=critical,1.3.6.1.5.5.7.3.1\n')
        self.run_cmd(['make', 'server', 'CN=custom.example', 'PROFILE=custom'])

    def test_all_categories_and_generic_opt_in(self):
        for kind, action, options in [
            ('auth', 'user', []), ('code', 'dev', []),
            ('smime', 'email', ['SMIME_MODE=sign']),
            ('archive', 'doc', ['ARCHIVE_MODE=seal']),
        ]:
            self.run_cmd(['make', 'int-' + kind, 'CN=Category ' + kind])
            self.run_cmd(['make', action, 'CN=allowed-' + kind, *options])
            self.refuse_unchanged(['bin/gen-leaf.sh'], INT_DIR='intm-' + kind + '-ca',
                                  CN='wrong.example', EXT_SECTION='server_ec')
        self.run_cmd(['make', 'doc', 'CN=Timestamp', 'ARCHIVE_MODE=timestamp'])
        self.run_cmd(['make', 'intermediate', 'INT_DIR=pki-data/general', 'KIND=generic', 'CN=Generic'])
        self.run_cmd(['make', 'server', 'INT_DIR=pki-data/general', 'CN=generic.example'])
        self.run_cmd(['make', 'dev', 'INT_DIR=pki-data/general', 'CN=Generic Code'])

    def test_metadata_custom_paths_aliases_and_reclassification(self):
        self.run_cmd(['make', 'intermediate', 'INT_DIR=pki-data/web', 'KIND=web', 'CN=Custom Web'])
        (self.work / 'web-alias').symlink_to('pki-data/web', target_is_directory=True)
        for directory in ['pki-data/web', 'web-alias']:
            self.refuse_unchanged(['make', 'dev', 'INT_DIR=' + directory, 'KIND=code', 'CN=wrong'])
        self.refuse_unchanged(['make', 'intermediate', 'INT_DIR=pki-data/web', 'KIND=generic',
                              'CN=Custom Web', 'FORCE_REISSUE=1'])
        self.refuse_unchanged(['make', 'rollback-code', 'LEGACY_DIR=pki-data/web'])
        meta = self.work / 'pki-data/web/ca.meta'
        original = meta.read_text()
        meta.chmod(0o600)
        for contents in [original.replace('KIND=web\n', ''), original + 'KIND=generic\n',
                         original.replace('KIND=web\n', 'KIND=unknown\n')]:
            meta.write_text(contents)
            self.refuse_unchanged(['make', 'server', 'INT_DIR=pki-data/web', 'CN=wrong.example'])
        meta.write_text(original)
        self.run_cmd(['make', 'server', 'INT_DIR=pki-data/web', 'CN=custom-path.example'])
        # Old canonical authorities retain their category without rewriting metadata.
        canonical_meta = self.ca / 'ca.meta'
        canonical_meta.unlink()
        self.refuse_unchanged(['make', 'dev', 'INT_DIR=intm-web-ca', 'CN=wrong'])
        self.run_cmd(['make', 'server', 'CN=legacy.example'])

    def test_preserving_batch_rejects_incompatible_destination_before_claim(self):
        # A legacy unrestricted issuer can contain code certificates. The new web
        # issuer must reject them during whole-batch preflight, including dry-run.
        self.run_cmd(['make', 'intermediate', 'INT_DIR=pki-data/old', 'KIND=generic', 'CN=Old'])
        self.run_cmd(['make', 'dev', 'INT_DIR=pki-data/old', 'CN=Old Code'])
        self.run_cmd(['make', 'list-leafs-web', 'INT_DIR=pki-data/old'])
        for extra in [[], ['DRY_RUN=1']]:
            result = self.refuse_unchanged(['make', 'reissue-leafs-web', 'LEGACY_DIR=pki-data/old', *extra])
            self.assertIn('Issuance category web', result.stderr)

    def test_unexpected_signed_usage_blocks_publication_and_fences_next_command(self):
        unexpected = self.work / 'unexpected.pem'
        self.run_cmd([self.backend, 'req', '-new', '-x509', '-key', 'root/private/ca.key.pem',
                      '-subj', '/CN=Unexpected', '-config', 'intm-web-ca/openssl.cnf',
                      '-extensions', 'code_sign', '-days', '1', '-out', str(unexpected)])
        wrapper = self.work / 'probe-openssl'
        wrapper.write_text('#!/bin/bash\nset -e\n' +
            'if [[ "$1" == ca && " $* " == *" -extensions "* ]]; then\n' +
            '  ' + shlex.quote(self.backend) + ' "$@"\n' +
            '  while [[ $# -gt 0 ]]; do\n' +
            '    if [[ "$1" == -out ]]; then cp ' + shlex.quote(str(unexpected)) + ' "$2"; exit; fi\n' +
            '    shift\n  done\n  exit 91\nfi\nexec ' + shlex.quote(self.backend) + ' "$@"\n')
        wrapper.chmod(0o700)
        result = self.run_cmd(['make', 'server', 'CN=interrupted.example'], False, OPENSSL=str(wrapper))
        self.assertIn('Issuance category web rejects profile', result.stderr)
        self.assertFalse((self.ca / 'certs/interrupted.example.cert.pem').exists())
        pending = self.work / '.recovery/pending'
        self.assertIn('signing-outcome-uncertain', (pending / 'phase').read_text())
        self.assertFalse((pending / 'ready').exists())
        self.refuse_unchanged(['make', 'server', 'CN=next.example'])

    def test_generic_command_explicit_profiles_and_custom_authority(self):
        self.run_cmd(['make', 'int-generic'])
        ca = self.work / 'intm-generic-ca'
        self.assertIn('KIND=generic\n', (ca / 'ca.meta').read_text())
        self.run_cmd(['make', 'generic', 'CN=Generic Signing Key', 'PROFILE=code_sign',
                      'KEY_ALG=Ed25519', 'DAYS=30'])
        result = self.run_cmd([self.backend, 'x509', '-in', str(ca / 'certs/Generic Signing Key.cert.pem'),
                               '-noout', '-text']).stdout
        self.assertIn('Code Signing', result)
        self.assertIn('ED25519', result)
        self.assertNotIn('Subject Alternative Name', result)
        self.run_cmd(['make', 'generic', 'CN=generic.example', 'PROFILE=code_sign',
                      'EXT_SECTION=server_ec', 'SAN_DNS=generic.example'])
        result = self.run_cmd([self.backend, 'x509', '-in', str(ca / 'certs/generic.example.cert.pem'),
                               '-noout', '-text']).stdout
        self.assertIn('TLS Web Server Authentication', result)
        self.assertIn('DNS:generic.example', result)
        self.run_cmd(['make', 'int-generic', 'INT_DIR=pki-data/general', 'CN=Custom Generic'])
        self.run_cmd(['bin/gen-generic.sh'], INT_DIR='pki-data/general', CN='Direct Generic',
                     EXT_SECTION='client_ec', ACTION='dev', TYPE='server')
        self.assertTrue((self.work / 'pki-data/general/certs/Direct Generic.cert.pem').exists())

    def test_generic_command_refuses_missing_profile_and_restricted_authority(self):
        self.run_cmd(['make', 'int-generic'])
        for command, env in [
            (['make', 'generic', 'CN=missing'], {}),
            (['bin/gen-generic.sh'], dict(CN='missing')),
            (['make', 'generic', 'PROFILE=code_sign'], {}),
            (['make', 'generic', 'CN=wrong.example', 'INT_DIR=intm-web-ca', 'PROFILE=server_ec'], {}),
            (['make', 'generic', 'CN=wrong', 'KIND=web', 'PROFILE=code_sign'], {}),
            (['bin/gen-leaf.sh'], dict(CN='missing', ACTION='generic', KIND='generic')),
            (['make', 'generic', 'CN=invalid', 'PROFILE=missing_section'], {}),
            (['make', 'generic', 'CN=invalid', 'PROFILE=v3_intermediate_ca'], {}),
        ]:
            with self.subTest(command=command):
                self.refuse_unchanged(command, **env)


if __name__ == '__main__':
    unittest.main()
