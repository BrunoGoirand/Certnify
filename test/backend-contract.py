#!/usr/bin/env python3
"""Portable real-backend CRL parsing checks in disposable workspaces."""
import base64
import datetime
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from workspace import copy_sources, snapshot

SOURCE = Path(__file__).resolve().parent.parent


class Backend(unittest.TestCase):
    def test_crl_signature_issuer_and_time_boundaries(self):
        with tempfile.TemporaryDirectory(prefix='certnify-backend-') as directory:
            work = Path(directory) / 'work'
            copy_sources(SOURCE, work)
            backend = shutil.which(os.environ.get('OPENSSL', 'openssl'))
            env = {key: os.environ[key] for key in ('PATH', 'TMPDIR') if key in os.environ}
            env.update(OPENSSL=backend, LC_ALL='C', KEY_ALG='EC')

            def run(command, success=True, **values):
                result = subprocess.run(command, cwd=work, env=dict(env, **values),
                                        capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                return result

            run(['make', 'root', 'CN=Backend Root'])
            run(['make', 'int-web', 'CN=Backend Issuer'])
            run(['make', 'crl', 'KIND=web'])
            crl = 'intm-web-ca/crl/ca.crl.pem'
            cert = 'intm-web-ca/certs/ca.cert.pem'
            run([backend, 'crl', '-in', crl, '-outform', 'DER', '-out', 'valid.der'])
            der = bytearray((work / 'valid.der').read_bytes())
            # Corrupt the signature without relying on version-specific CLI flags.
            der[-1] ^= 1
            (work / 'bad.crl').write_bytes(b'-----BEGIN X509 CRL-----\n' +
                                          base64.encodebytes(der) + b'-----END X509 CRL-----\n')
            (work / 'malformed.crl').write_text('malformed\n')
            dates = run([backend, 'crl', '-in', crl, '-noout', '-lastupdate', '-nextupdate']).stdout
            self.assertIn('lastUpdate=', dates)
            self.assertIn('nextUpdate=', dates)
            decoded = {key: datetime.datetime.strptime(value, '%b %d %H:%M:%S %Y GMT')
                       for key, value in (line.split('=', 1) for line in dates.splitlines())}
            first, last = decoded['lastUpdate'], decoded['nextUpdate']
            stamp = lambda value: value.strftime('%Y%m%d%H%M%S')
            command = ['/bin/bash', '-c', 'source bin/pki-env.sh; pki_begin read; '
                       'validate_crl "$PROBE_CRL" "$PROBE_ISSUER" "${PROBE_TIME:-}"']
            for file, issuer, reference, success in [
                (crl, cert, '', True),
                (crl, cert, stamp(first), True),
                (crl, cert, stamp(first - datetime.timedelta(seconds=1)), False),
                (crl, cert, stamp(last - datetime.timedelta(seconds=1)), True),
                (crl, cert, stamp(last), False),
                (crl, 'root/certs/ca.cert.pem', '', False),
                ('bad.crl', cert, '', False),
                ('malformed.crl', cert, '', False),
                ('missing.crl', cert, '', False),
            ]:
                with self.subTest(file=file, issuer=issuer, reference=reference):
                    before = snapshot(work)
                    run(command, success, PROBE_CRL=file, PROBE_ISSUER=issuer, PROBE_TIME=reference)
                    self.assertEqual(before, snapshot(work))


if __name__ == '__main__':
    unittest.main(verbosity=2)
