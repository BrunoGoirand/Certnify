#!/usr/bin/env python3
"""Authoritative engine naming and read-only workspace resolution."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import unicodedata


def name(cn):
    normalized = unicodedata.normalize('NFKD', cn)
    normalized = ''.join(c for c in normalized if not unicodedata.combining(c))
    slug = re.sub('[^a-z0-9]+', '-', normalized.lower()).strip('-')
    result = 'certnify-' + slug
    if not slug or len(result) > 80:
        raise ValueError('Choose an explicit PKI identifier; CN has no usable bounded ASCII slug')
    return result


def resolve(source, selector=None):
    source = Path(source).resolve(strict=True)
    if not source.is_dir():
        raise ValueError('Source base must be a directory')
    base = source.parent if source.name == '.certnify' else source
    if selector is None:
        if any(p.is_dir() or p.is_symlink()
               for directory in {source, base} for p in directory.glob('certnify-*')):
            raise ValueError('Select a named workspace explicitly with PKI=certnify-<name>')
        workspace = source
    else:
        if not re.fullmatch(r'certnify-[a-z0-9]+(?:-[a-z0-9]+)*', selector) or len(selector) > 80:
            raise ValueError('Invalid PKI selector')
        # Do not strand an existing legacy hierarchy by mixing layout modes.
        legacy = ['root', 'intermediate', 'pki-data', 'out', '.locks', '.recovery']
        if any(os.path.lexists(source / n) for n in legacy) or any(source.glob('intm-*')):
            raise ValueError('Legacy PKI state exists in source base; named workspaces require a source-only installation')
        workspace = base / selector
        # Keep existing nested installations usable; never silently choose a duplicate.
        nested = source / selector
        if base != source and os.path.lexists(nested):
            if os.path.lexists(workspace):
                raise ValueError('Ambiguous PKI selector: both nested and sibling workspaces exist')
            workspace = nested
        if workspace.is_symlink() or (workspace.exists() and not workspace.is_dir()):
            raise ValueError('PKI workspace must be a physical directory, never a symlink')
        if workspace.exists() and workspace.resolve() != workspace:
            raise ValueError('PKI workspace physical identity changed')
    guards = {n: os.path.lexists(workspace / n) for n in (
        '.locks/root-ca.lock', '.recovery/pending', '.recovery/power-loss', '.recovery/power-loss-error')}
    return dict(schema_version=1, source_base=str(source), selector=selector,
                workspace=str(workspace), exists=workspace.is_dir(),
                layout='legacy' if selector is None else 'named', guards=guards)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--info', action='store_true', help='Read-only JSON workspace resolution')
    parser.add_argument('--path', action='store_true', help='Resolved workspace path for engine bootstrap')
    args = parser.parse_args()
    try:
        if args.info or args.path:
            result = resolve(Path(__file__).resolve().parents[1], os.environ.get('PKI'))
            print(result['workspace'] if args.path else json.dumps(result, sort_keys=True))
        else:
            print(name(os.environ.get('CN', '')))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
