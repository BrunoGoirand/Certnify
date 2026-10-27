"""Feature selection for backend tools, after the runtime admission gate."""
import re


def supports_preserving_migration(version):
    # This selects a test/benchmark, not a substitute for require_openssl.
    # Admission validates the complete banner and executable/library agreement.
    fields = version.split()
    return (len(fields) >= 2 and fields[0] == 'OpenSSL'
            and re.fullmatch(r'(3\.[0-9]+|4\.1)\.[0-9]+', fields[1]) is not None)
