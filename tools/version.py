#!/usr/bin/env python3
"""Source version maintenance; deliberately independent of PKI bootstrap."""
import argparse
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def read_version(root):
    path = root / 'VERSION'
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('VERSION must be a regular file, not a symlink')
    value = path.read_bytes().decode('ascii')
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\n', value):
        raise ValueError('VERSION must contain MAJOR.MINOR.PATCH and one newline')
    return value.rstrip('\n')


def bump(root, level):
    if level not in ('patch', 'minor', 'major'):
        raise ValueError('LEVEL is required: patch, minor or major')
    lock = root / '.version-bump.lock'
    # A separate source-maintenance lock avoids involving operational CA state.
    lock.mkdir()
    temporary = None
    try:
        old = read_version(root)
        parts = [int(part) for part in old.split('.')]
        index = {'major': 0, 'minor': 1, 'patch': 2}[level]
        parts[index] += 1
        for lower in range(index + 1, 3):
            parts[lower] = 0
        new = '.'.join(map(str, parts))
        descriptor, temporary = tempfile.mkstemp(prefix='.version-', suffix='.tmp', dir=root)
        with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
            stream.write(new + '\n')
            stream.flush()
            os.fchmod(stream.fileno(), stat.S_IMODE((root / 'VERSION').stat().st_mode))
            os.fsync(stream.fileno())
        os.replace(temporary, root / 'VERSION')
        print('[OK ] {} -> {}'.format(old, new))
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('show', 'bump'))
    args = parser.parse_args()
    try:
        if args.operation == 'show':
            print(read_version(ROOT))
        else:
            bump(ROOT, os.environ.get('LEVEL', ''))
    except (OSError, ValueError, UnicodeError) as error:
        print('[ERR] ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
