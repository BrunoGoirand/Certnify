#!/usr/bin/env python3
"""Publish a version commit and annotated tag to origin; --dry-run previews only."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from version import bump, read_version

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()


def release(level, dry_run=False):
    if Path(git('rev-parse', '--show-toplevel')).resolve() != ROOT:
        raise ValueError('Run from a standalone engine Git checkout')
    git('symbolic-ref', '--quiet', 'HEAD')
    if git('status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('Commit reviewed changes and changelog first; checkout must be clean')
    old = read_version(ROOT)
    if git('show', 'HEAD:VERSION') != old:
        raise ValueError('VERSION differs from HEAD')
    parts = list(map(int, old.split('.')))
    index = {'major': 0, 'minor': 1, 'patch': 2}[level]
    parts[index] += 1
    parts[index + 1:] = [0] * (2 - index)
    new = '.'.join(map(str, parts))
    tag = 'v' + new
    ref = 'refs/tags/' + tag
    if git('tag', '--list', tag):
        raise ValueError('Local tag already exists: ' + tag)
    destinations = git('remote', 'get-url', '--push', '--all', 'origin').splitlines()
    if len(destinations) != 1 or destinations[0].startswith('-'):
        raise ValueError('origin must have exactly one push destination')
    destination = destinations[0]
    if git('ls-remote', '--tags', destination, ref):
        raise ValueError('Remote tag already exists: ' + tag)
    git('var', 'GIT_AUTHOR_IDENT')
    git('var', 'GIT_COMMITTER_IDENT')
    print(json.dumps(dict(old=old, new=new, tag=tag, destination=destination,
                          dry_run=dry_run, effects='Commit VERSION, annotate and push only this tag')), flush=True)
    if dry_run:
        return
    head = git('rev-parse', 'HEAD')
    bump(ROOT, level)
    if read_version(ROOT) != new:
        raise ValueError('Version changed concurrently; stop and inspect')
    git('commit', '--only', '-m', 'Release ' + tag, '--', 'VERSION')
    if (git('rev-parse', 'HEAD^') != head or git('show', 'HEAD:VERSION') != new
            or git('diff', '--name-only', head, 'HEAD') != 'VERSION'
            or git('status', '--porcelain', '--untracked-files=normal')):
        raise ValueError('Unexpected release commit or working tree; stop and inspect')
    git('tag', '-a', tag, '-m', 'Release ' + tag)
    object_id = git('rev-parse', ref)
    git('push', '--no-follow-tags', destination, ref + ':' + ref)
    if git('ls-remote', '--tags', destination, ref).split() != [object_id, ref]:
        raise ValueError('Remote tag verification failed; publication may have succeeded')
    print('Published ' + tag, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('level', choices=('major', 'minor', 'patch'))
    parser.add_argument('--dry-run', action='store_true', help='Preview without changing VERSION, committing or publishing')
    args = parser.parse_args()
    lock = ROOT / '.release.lock'
    owned = False
    try:
        # Empty directories are not Git changes. Only this invocation removes its lock.
        lock.mkdir()
        owned = True
        release(args.level, args.dry_run)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, KeyboardInterrupt) as error:
        print('Release stopped: ' + str(error)
              + '\nPreserve partial state; inspect VERSION, HEAD and local/remote tags before any retry.'
                ' No automatic rollback or retry.', file=sys.stderr)
        return 1
    finally:
        if owned:
            lock.rmdir()


if __name__ == '__main__':
    sys.exit(main())
