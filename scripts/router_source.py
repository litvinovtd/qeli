"""Shared managed-source sync for maintainer-only router build helpers.
Source replacement is fail-closed for later helper runs, not atomic or locked.
"""
import posixpath
import re
from pathlib import Path
import shlex
from native_lab import LabConnection, sync_qeli_source


def _marker(remote_root):
    if not remote_root.startswith('/') or remote_root == '/' or '..' in remote_root.split('/'):
        raise ValueError(f'unsafe remote source root: {remote_root!r}')
    return posixpath.join(remote_root, '.router-sync-incomplete')


def require_router_source_ready(client, remote_root):
    marker = _marker(remote_root)
    LabConnection(client).checked(
        f'test ! -e {shlex.quote(marker)}',
        'router source sync incomplete; rerun with --sync', timeout=30)


def sync_router_source(client, local_root, remote_root):
    marker = _marker(remote_root)
    local_root = Path(local_root)
    # Check mandatory local inputs before any destructive remote operation.
    for relative in ('src/client_main.rs', '.cargo/config.toml', 'Cargo.toml', 'Cargo.lock'):
        if not (local_root / relative).is_file():
            raise RuntimeError(f'router build input is missing: {local_root / relative}')
    connection = LabConnection(client)
    connection.checked(
        f'mkdir -p {shlex.quote(remote_root)} && '
        f'(umask 077; : > {shlex.quote(marker)})',
        'mark router source sync incomplete', timeout=30)
    sftp = connection.open_sftp()
    try:
        count = sync_qeli_source(connection, sftp, local_root, remote_root)
    finally:
        sftp.close()
    # Every failure above preserves the marker, including SFTP close failure.
    connection.checked(f'rm -f {shlex.quote(marker)}', 'finish router source sync', timeout=30)
    return count


def create_router_checkout(client, kind):
    """Allocate a private retained run; never mutate an older/shared checkout."""
    if kind not in ('keenetic', 'openwrt'):
        raise ValueError(f'unknown router build kind: {kind!r}')
    connection = LabConnection(client)
    root = connection.checked(
        f'umask 077; mktemp -d /var/tmp/qeli-router-{kind}-XXXXXX',
        'allocate isolated router checkout', timeout=30).strip()
    if re.fullmatch(r'/var/tmp/qeli-router-' + kind + r'-[A-Za-z0-9]{6}', root) is None:
        raise RuntimeError(f'invalid router checkout path: {root!r}')
    connection.checked(
        f'test -d {shlex.quote(root)} && test ! -L {shlex.quote(root)}',
        'admit owned router checkout', timeout=30)
    return root


def restrict_router_crate_types(client, remote_root):
    """Restrict only the freshly uploaded run manifest; no shared backup."""
    if re.fullmatch(r'/var/tmp/qeli-router-(keenetic|openwrt)-[A-Za-z0-9]{6}', remote_root) is None:
        raise ValueError(f'unsafe isolated router checkout: {remote_root!r}')
    manifest = shlex.quote(posixpath.join(remote_root, 'Cargo.toml'))
    LabConnection(client).checked(
        f"sed -i 's/^crate-type = \\[\"rlib\", \"cdylib\", \"staticlib\"\\]$/"
        f"crate-type = [\"rlib\"]/' {manifest} && "
        f"grep -qxF 'crate-type = [\"rlib\"]' {manifest}",
        'restrict router dependency to rlib', timeout=30)
