#!/usr/bin/env python3
"""Checked persistence barriers and conservative interrupted-command fence (MIT).

Called only under the toolkit workspace lock, except read-only reporting. Never
repairs an OpenSSL database or replays a signing operation. No runtime test hooks.
"""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid


def sync_path(path, full=False):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return  # Persist the directory entry, never follow its target.
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise ValueError('Unsupported storage entry: ' + str(path))
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        os.fsync(fd)
        if full and sys.platform == 'darwin' and stat.S_ISREG(mode):
            # No silent fallback: fsync alone does not flush the device cache.
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    finally:
        os.close(fd)


def sync_tree(root):
    device = root.stat().st_dev
    anchor = None
    # Distribution inputs are not operational state. Keep exact manifest paths,
    # rather than excluding whole directories that could contain custom data.
    manifest = root / 'test' / 'source-manifest.txt'
    sources = set()
    if not manifest.is_symlink() and manifest.is_file():
        sources = {line for line in manifest.read_text().splitlines()
                   if line and not line.startswith('#')}
    def visit(path):
        nonlocal anchor
        if path.is_symlink():
            return
        if path.stat().st_dev != device:
            raise ValueError('Durability requires one filesystem; mounted entry: ' + str(path))
        if path.is_file() and path.relative_to(root).as_posix() in sources:
            return
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if path == root and child.name in ('.git', '.locks'):
                    continue
                visit(child)
        sync_path(path)
        if path.is_file():
            anchor = path
    visit(root)
    return anchor


class Store:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.journal = self.root / '.recovery'
        self.fence = self.journal / 'power-loss'
        self.error = self.journal / 'power-loss-error'
        self.retiring = None
        for path in (self.journal, self.fence, self.error):
            if path.is_symlink():
                raise ValueError('Unsafe durability path: ' + str(path))

    def load(self):
        data = json.loads(self.fence.read_text())
        if (not isinstance(data, dict) or data.get('schema') != 1
                or not isinstance(data.get('id'), str)
                or not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z-[0-9]+', data['id'])
                or (data.get('ready') is not None and
                    (not isinstance(data['ready'], str) or not re.fullmatch(r'[0-9a-f]{64}', data['ready'])))):
            raise ValueError('Invalid power-loss fence; preserve and review: ' + str(self.fence))
        return data

    def write(self, path, data):
        # Exclusive random sibling avoids following stale temporary aliases.
        temporary = path.parent / ('.durable-' + uuid.uuid4().hex)
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
        sync_path(temporary)
        os.replace(str(temporary), str(path))
        sync_path(path.parent)
        self.device_barrier()

    def device_barrier(self, anchor=None):
        # Directory fsync + a subsequent FULLFSYNC on the same filesystem also
        # orders directory updates before acknowledging them on macOS.
        if sys.platform == 'darwin':
            target = self.fence if self.fence.exists() else anchor
            if target is not None:
                sync_path(target, full=True)

    def flush(self):
        anchor = sync_tree(self.root)
        self.device_barrier(anchor)

    def begin(self, pid):
        if self.fence.exists() or self.error.exists():
            raise ValueError('Unresolved power-loss fence: ' + str(self.fence))
        created = not self.journal.exists()
        self.journal.mkdir(mode=0o700, exist_ok=True)
        data = dict(schema=1, id=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + pid,
                    created_directory=created, ready=None)
        fd = os.open(str(self.fence), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
        sync_path(self.fence)
        sync_path(self.journal)
        sync_path(self.root)
        self.device_barrier()
        return data['id']

    def ready_digest(self):
        path = self.journal / 'pending' / 'ready'
        if path.parent.is_symlink() or path.is_symlink() or not path.is_file():
            raise ValueError('No durable installation plan; manual review required')
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def seal(self):
        data = self.load()
        self.flush()
        data['ready'] = self.ready_digest()
        self.write(self.fence, json.dumps(data))

    def admit(self):
        data = self.load()
        if self.error.exists() or not data.get('ready') or data['ready'] != self.ready_digest():
            raise ValueError('No matching durable checkpoint; manual review required')
        return data['id']

    def finish(self, reviewed=False):
        data = self.load()
        if self.error.exists() and not reviewed:
            raise ValueError('Persistence barrier failed; manual review required: ' + str(self.error))
        self.flush()
        if reviewed and self.error.exists():
            self.error.unlink()
            sync_path(self.journal)
            self.device_barrier()
        # At this point all local data and directory changes precede completion.
        # Rename rather than unlink retains a file on which to FULLFSYNC after
        # synchronizing the removal of the blocking name.
        self.retiring = data
        receipt = self.journal / ('.durable-' + uuid.uuid4().hex)
        os.replace(str(self.fence), str(receipt))
        sync_path(self.journal)
        sync_path(receipt, full=True)
        receipt.unlink()
        sync_path(self.journal)
        if data.get('created_directory') and not any(self.journal.iterdir()):
            self.journal.rmdir()
            sync_path(self.root)

    def failure(self):
        # Best effort only: the already durable fence is the primary protection.
        if not self.fence.exists() and self.retiring is not None:
            try:
                self.journal.mkdir(mode=0o700, exist_ok=True)
                self.write(self.fence, json.dumps(self.retiring))
            except (OSError, ValueError):
                pass
        if self.fence.exists():
            try:
                self.write(self.error, 'Persistence failure; inspect storage and reconcile before acknowledgment.\n')
            except (OSError, ValueError):
                pass

    def acknowledge(self, identity, note):
        data = self.load()
        pending = self.journal / 'pending'
        if pending.is_symlink():
            raise ValueError('Unsafe pending journal')
        if pending.exists():
            operation = pending / 'operation'
            if operation.is_symlink() or operation.read_text().splitlines()[:1] != ['id=' + identity]:
                raise ValueError('Recovery ID mismatch')
        elif identity != data['id']:
            raise ValueError('Recovery ID mismatch')
        if not note.strip():
            raise ValueError('Nonempty recovery note required')
        receipt = self.journal / ('power-loss-reviewed-' + data['id'])
        content = json.dumps(dict(operation=data, review=note)) + '\n'
        if receipt.is_symlink() or (receipt.exists() and receipt.read_text() != content):
            raise ValueError('Conflicting review destination: ' + str(receipt))
        if not receipt.exists():
            self.write(receipt, content)
        self.finish(reviewed=True)


def main():
    os.umask(0o077)
    if sys.version_info < (3, 8) or sys.platform not in ('darwin', 'linux'):
        raise ValueError('Durability requires Python 3.8+ on macOS or Linux')
    store = Store(sys.argv[2])
    action = sys.argv[1]
    try:
        if action == 'begin':
            print(store.begin(sys.argv[3]))
        elif action == 'flush':
            store.flush()
        elif action == 'seal':
            store.seal()
        elif action == 'admit':
            print(store.admit())
        elif action == 'finish':
            store.finish()
        elif action == 'acknowledge':
            store.acknowledge(sys.argv[3], sys.argv[4])
        elif action == 'report':
            if store.fence.exists():
                print('Power-loss recovery required: ' + str(store.fence))
                print('id=' + store.load()['id'])
                print('Do not retry signing or reset counters. Resume only a durable verified plan, otherwise reconcile and acknowledge.')
            if store.error.exists():
                print('Persistence error requires manual review: ' + str(store.error))
        else:
            raise ValueError('Unknown durability operation')
    except OSError:
        if action not in ('report', 'admit'):
            store.failure()
        raise


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as error:
        print('[ERR] Durability: ' + str(error), file=sys.stderr)
        sys.exit(1)
