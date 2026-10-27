#!/usr/bin/env python3
"""Bounded CRL publication and byte-for-byte read-back (trusted POSIX hooks).

The fetch hook must read the consumer-facing destination, emitting only its
bytes on stdout. This checks that adapter's evidence, not its honesty.
"""
import hashlib
import os
from pathlib import Path
import selectors
import shlex
import signal
import subprocess
import sys
import time


class PublicationCancelled(Exception):
    """Explicit cancellation must not be swallowed by OS-error retry handlers."""


def timeout_value(value):
    if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 3600:
        raise ValueError('PUBLISH_TIMEOUT must be an integer from 1 to 3600 seconds')
    return int(value)


def fingerprint(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def run_hook(command, filename, deadline, expected=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('Publication deadline exceeded')
    command = command.replace('%FILE%', shlex.quote(filename))
    process = subprocess.Popen(['bash', '-c', command], start_new_session=True,
                               stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE if expected is not None else sys.stderr)
    try:
        if expected is not None:
            digest = hashlib.sha256()
            size = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError('Publication read-back deadline exceeded')
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > expected[0]:
                        raise ValueError('Remote content exceeds expected size')
                    digest.update(chunk)
            if (size, digest.hexdigest()) != expected:
                raise ValueError('Remote content differs from the local artifact')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Publication deadline exceeded')
        if process.wait(timeout=remaining) != 0:
            raise ValueError('Publication hook returned nonzero status')
    except subprocess.TimeoutExpired as error:
        raise ValueError('Publication deadline exceeded') from error
    finally:
        # Also reap ordinary background descendants on success. Hooks must not
        # daemonize or escape the group; this runner is not a security sandbox.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()


def main():
    if os.environ.get('ALLOW_ADMIN_HOOKS') != '1':
        raise ValueError('Administrator shell hooks require ALLOW_ADMIN_HOOKS=1')
    timeout = timeout_value(os.environ.get('PUBLISH_TIMEOUT') or '60')
    publish = os.environ.get('PUBLISH_CMD', '')
    fetch = os.environ.get('PUBLISH_FETCH_CMD', '')
    if not publish or not fetch:
        raise ValueError('Publication requires both PUBLISH_CMD and PUBLISH_FETCH_CMD')
    if sys.argv[1:] == ['check']:
        return
    deadline = time.monotonic() + timeout
    artifacts = {}
    for name in sys.argv[1:]:
        if Path(name).name != name:
            raise ValueError('Publication expects generated basenames')
        artifacts[name] = fingerprint(Path(name))
    for name, expected in artifacts.items():
        try:
            run_hook(publish, name, deadline)
            run_hook(fetch, name, deadline, expected)
            if fingerprint(Path(name)) != expected:
                raise ValueError('Local artifact changed during publication')
        except (OSError, ValueError, PublicationCancelled) as error:
            print('artifact=' + name + ' status=failed', flush=True)
            raise ValueError(name + ': ' + str(error)) from error
        print('artifact=' + name + ' status=verified sha256=' + expected[1], flush=True)
    if any(fingerprint(Path(name)) != expected for name, expected in artifacts.items()):
        raise ValueError('Local artifacts changed during publication')


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise PublicationCancelled('Publication interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main()
    except (OSError, ValueError, PublicationCancelled) as error:
        print('[ERR] ' + str(error), file=sys.stderr)
        sys.exit(1)
