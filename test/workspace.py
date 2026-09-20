#!/usr/bin/env python3
"""Source-only test workspaces and state snapshots (Python 3.8+, test-only)."""
import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
from pathlib import Path, PurePosixPath


def source_paths(source):
    manifest = source / 'test/source-manifest.txt'
    paths = []
    for line in manifest.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        path = PurePosixPath(line)
        if path.is_absolute() or '..' in path.parts or str(path) != line:
            raise ValueError('Unsafe manifest path: ' + line)
        if line in paths:
            raise ValueError('Duplicate manifest entry: ' + line)
        probe = source
        for part in path.parts:
            probe = probe / part
            if probe.is_symlink():
                raise ValueError('Symlink in source path: ' + line)
        if not probe.is_file():
            raise ValueError('Missing source file: ' + line)
        paths.append(line)
    if 'profiles/root/base.cnf' not in paths:
        raise ValueError('Root profile missing from manifest')
    return paths


def copy_sources(source, destination):
    source = Path(source).resolve()
    destination = Path(destination)
    # Validate the entire manifest before creating/copying anything.
    paths = source_paths(source)
    if destination.is_symlink() or (destination.exists() and any(destination.iterdir())):
        raise ValueError('Destination must be absent or an empty directory')
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in paths:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(source / name, target)


def snapshot(root):
    """Snapshot disposable fixtures only; private file bytes are never reported."""
    root = Path(root)
    result = {}
    def visit(directory):
        for path in sorted(directory.iterdir()):
            name = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            entry = {'mode': format(stat.S_IMODE(mode), '04o')}
            if path.is_symlink():
                entry.update(type='symlink', target=os.readlink(path))
            elif path.is_dir():
                entry['type'] = 'directory'
            elif path.is_file():
                data = path.read_bytes()
                entry.update(type='file', sha256=hashlib.sha256(data).hexdigest())
                if path.name in ('index.txt', 'serial', 'crlnumber', 'serial.last'):
                    entry['content'] = data.decode('utf-8', errors='replace')
                if path.suffix == '.pem' and 'private' not in path.parts:
                    blocks = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', data, re.S)
                    entry['certificate_der_sha256'] = [
                        hashlib.sha256(ssl.PEM_cert_to_DER_cert(block.decode('ascii'))).hexdigest()
                        for block in blocks
                    ]
            else:
                raise ValueError('Unsupported fixture entry: ' + name)
            result[name] = entry
            if entry['type'] == 'directory':
                visit(path)
    visit(root)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['copy', 'snapshot', 'diff'])
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    if args.operation == 'copy':
        copy_sources(args.source, args.destination)
    elif args.operation == 'snapshot':
        args.destination.write_text(json.dumps(snapshot(args.source), indent=2, sort_keys=True) + '\n')
        args.destination.chmod(0o600)
    else:
        before = json.loads(args.source.read_text())
        after = json.loads(args.destination.read_text())
        for name in sorted(before.keys() | after.keys()):
            if before.get(name) != after.get(name):
                print(name + ': ' + ('added' if name not in before else 'removed' if name not in after else 'changed'))


if __name__ == '__main__':
    main()
