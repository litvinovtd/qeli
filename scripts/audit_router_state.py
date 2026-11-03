#!/usr/bin/env python3
"""Opt-in router ELF startup/storage audit in private Linux namespaces and chroots.

Runs the real four client binaries (foreign targets via explicit QEMU, no binfmt
registration). This tests startup/recovery storage, NOT physical firmware or VPN
throughput. Never run against host /var: the outer process creates a private mount,
network and PID namespace before the fixture can create files or start clients.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

TARGETS = {"aarch64": ["qemu-aarch64"], "x86_64": [],
           "mipsel": ["qemu-mipsel"], "armv7": ["qemu-arm", "-cpu", "cortex-a15"]}


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True, timeout=30)


def namespace(kind):
    m = os.stat('/proc/self/ns/' + kind)
    return f'{m.st_dev}:{m.st_ino}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path, required=True)
    parser.add_argument('--qemu-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--strace', action='store_true')
    parser.add_argument('--arches', nargs='+', choices=TARGETS, default=list(TARGETS))
    parser.add_argument('--probe', action='store_true', help='test the real storage module alone, not full client startup')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside:
        assert os.geteuid() == 0, 'requires root in a disposable lab'
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_ROUTER_HOST_NET=namespace('net'),
                   QELI_ROUTER_HOST_MNT=namespace('mnt'))
        command = ['unshare', '--net', '--mount', '--pid', '--fork',
                   '--kill-child=KILL', '--mount-proc', sys.executable,
                   str(Path(__file__).resolve()), '--assets', str(args.assets.resolve()),
                   '--qemu-dir', str(args.qemu_dir.resolve()), '--output', str(args.output.resolve()), '--inside']
        if args.baseline:
            command.append('--baseline')
        if args.strace:
            command.append('--strace')
        command += ['--arches', *args.arches]
        if args.probe:
            command.append('--probe')
        raise SystemExit(subprocess.run(command, env=env, timeout=240).returncode)
    assert namespace('net') != os.environ['QELI_ROUTER_HOST_NET']
    assert namespace('mnt') != os.environ['QELI_ROUTER_HOST_MNT']
    run('mount', '--make-rprivate', '/')
    root = args.output / 'jail'
    root.mkdir(mode=0o700)
    for name in ('usr', 'proc', 'tmp', 'dev/net', 'etc', 'run', 'fixture'):
        (root / name).mkdir(mode=0o755, parents=True, exist_ok=True)
    run('mount', '-t', 'tmpfs', '-o', 'size=32m,mode=1777', 'tmpfs', str(root / 'tmp'))
    for name, target in [('var', 'tmp'), ('opt', 'tmp/entware'), ('bin', 'usr/bin'),
                         ('sbin', 'usr/sbin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib64')]:
        (root / name).symlink_to(target)
    (root / 'tmp/entware').mkdir()
    run('mount', '--bind', '/usr', str(root / 'usr'))
    run('mount', '-o', 'remount,bind,ro', str(root / 'usr'))
    run('mount', '--bind', '/proc', str(root / 'proc'))
    for name, major, minor in [('null', 1, 3), ('urandom', 1, 9), ('net/tun', 10, 200)]:
        os.mknod(root / 'dev' / name, stat.S_IFCHR | 0o600, os.makedev(major, minor))
    (root / 'etc/hosts').write_text('127.0.0.1 localhost\n')
    (root / 'etc/resolv.conf').write_text('nameserver 127.0.0.1\n')
    run('ip', 'link', 'set', 'lo', 'up')
    fixture = root / 'fixture'
    for runner in ('qemu-aarch64', 'qemu-mipsel', 'qemu-arm'):
        shutil.copy2(args.qemu_dir / runner, fixture / runner)
    (fixture / 'client.conf').write_text(
        '[qeli]\nserver=127.0.0.1:24443\nproto=tcp\nmode=plain\nuser=fixture\n'
        'pass=fixture-only\nbind_static=false\ngateway=false\ndns=off\nipv6=off\n'
        'dev=qeli205\nreconnect=true\ntimeout=1\n')
    (fixture / 'client.conf').chmod(0o600)
    rows = []
    cases = ['default', 'real-root'] if args.baseline else [
        'default', 'real-root', 'real-var', 'linked-child', 'foreign-parent', 'writable-leaf', 'retained-journal']
    if args.probe:
        cases.remove('retained-journal')
    for arch, runner in TARGETS.items():
        if arch not in args.arches:
            continue
        binary = args.assets / (('router-state-probe-' if args.probe else 'qeli-client-openwrt-') + arch)
        shutil.copy2(binary, fixture / 'client')
        (fixture / 'client').chmod(0o700)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        command = ['chroot', str(root)]
        command += ['/fixture/' + runner[0], *runner[1:]] if runner else []
        if runner and args.strace:
            command.append('-strace')
        command += ['/fixture/client']
        if not args.probe:
            command += ['--config', '/fixture/client.conf']
        for case in cases:
            lib = root / 'tmp/lib'
            if lib.is_symlink():
                lib.unlink()
            elif lib.exists():
                shutil.rmtree(lib)
            var = root / 'var'
            if var.is_dir() and not var.is_symlink():
                shutil.rmtree(var)
            elif var.is_symlink():
                var.unlink()
            if case == 'real-var':
                var.mkdir()
                state = '/var/lib/qeli'
            else:
                var.symlink_to('tmp')
                state = '/tmp/lib/qeli'
            sentinel = None
            if case == 'linked-child':
                protected = fixture / 'protected'
                protected.mkdir(exist_ok=True)
                protected.chmod(0o755)
                sentinel = protected / 'sentinel'
                sentinel.write_text('unchanged')
                lib.symlink_to('/fixture/protected')
            elif case == 'foreign-parent':
                lib.mkdir(mode=0o755)
                os.chown(lib, 12345, 12345)
            elif case in ('writable-leaf', 'retained-journal'):
                (lib / 'qeli').mkdir(mode=0o700, parents=True)
                if case == 'writable-leaf':
                    (lib / 'qeli').chmod(0o777)
                else:
                    sentinel = lib / 'qeli/client-routes.state'
                    sentinel.write_text('incomplete-recovery-evidence')
                    sentinel.chmod(0o600)
            env = {'PATH': '/usr/bin:/usr/sbin:/bin:/sbin',
                   'QELI_DEVICE_ID_FILE': '/fixture/device-id',
                   'QELI_KNOWN_HOSTS': '/fixture/known-hosts', 'LC_ALL': 'C'}
            if case != 'default':
                env['STATE_DIRECTORY'] = state
            log_path = args.output / (arch + '-' + case + '.log')
            with log_path.open('w') as log:
                invocation = command + [('/var/lib/qeli' if case == 'default' else state)] if args.probe else command
                p = subprocess.Popen(invocation, env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 8
                    journal = root / state.lstrip('/') / 'client-routes.state'
                    while p.poll() is None and time.monotonic() < deadline:
                        if case in ('real-root', 'real-var') and journal.exists():
                            break
                        time.sleep(0.05)
                    live = p.poll() is None
                    if live:
                        p.send_signal(signal.SIGTERM)
                    code = p.wait(timeout=8)
                finally:
                    if p.poll() is None:
                        p.kill()
                        p.wait(timeout=5)
            output = log_path.read_text(errors='replace')
            expected_live = not args.baseline and case in ('real-root', 'real-var')
            if args.probe:
                passed = code == 0 and (root / state.lstrip('/')).is_dir() if expected_live else code != 0
            else:
                passed = (live and code == 0 and journal.is_file()) if expected_live else (not live and code != 0)
            if args.baseline or case == 'default':
                passed = passed and 'Not a directory' in output
            if sentinel:
                expected = 'incomplete-recovery-evidence' if case == 'retained-journal' else 'unchanged'
                passed = passed and sentinel.read_text() == expected
            if case == 'linked-child':
                passed = passed and (fixture / 'protected').stat().st_mode & 0o777 == 0o755
            if case == 'foreign-parent':
                passed = passed and lib.stat().st_uid == 12345 and not (lib / 'qeli').exists()
            if case == 'writable-leaf':
                passed = passed and (lib / 'qeli').stat().st_mode & 0o777 == 0o777
            row = dict(arch=arch, sha256=digest, case=case, passed=passed, storage_probe_only=args.probe,
                       alive_after_recovery=live, exit_code=code, log=log_path.name)
            rows.append(row)
            (args.output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(arch, case, 'PASS' if passed else 'FAIL', 'exit', code, flush=True)
    raise SystemExit(0 if all(row['passed'] for row in rows) else 1)


if __name__ == '__main__':
    main()
