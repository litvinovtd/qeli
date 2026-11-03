#!/usr/bin/env python3
"""Run the existing 19-cell packet matrix with real client mixed firewall probes.

No host services or firewall are altered. Each invocation creates private net/mount/PID
namespaces, and every matrix cell creates another three isolated network namespaces.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def namespace(kind):
    stat = os.stat('/proc/self/ns/' + kind)
    return f'{stat.st_dev}:{stat.st_ino}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qeli', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--ipv4', required=True, choices=['nft', 'legacy'])
    parser.add_argument('--ipv6', required=True, choices=['nft', 'legacy'])
    parser.add_argument('--firewalld', type=Path)
    parser.add_argument('--smoke', action='store_true', help='one DNS6 cell, no full-matrix certification')
    parser.add_argument('--hostname', action='store_true', help='resolve carrier through a private hosts file')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.artifacts.resolve()
    binary = args.qeli.resolve(strict=True)
    scripts = Path(__file__).resolve().parent
    if not args.inside:
        if os.geteuid() != 0:
            raise RuntimeError('root in a disposable Linux lab is required')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_CM_HOST_NET=namespace('net'), QELI_CM_HOST_MNT=namespace('mnt'))
        return subprocess.run(['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL',
                               '--mount-proc', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside'], env=env, timeout=2400).returncode
    if (not os.environ.get('QELI_CM_HOST_NET') or namespace('net') == os.environ['QELI_CM_HOST_NET']
            or namespace('mnt') == os.environ.get('QELI_CM_HOST_MNT')):
        raise RuntimeError('private NET/mount/PID context is mandatory')

    def run(argv):
        subprocess.run([str(a) for a in argv], check=True, timeout=20)

    run(['mount', '--make-rprivate', '/'])
    for mountpoint in ('/run', '/var/lib', '/var/log'):
        run(['mount', '-t', 'tmpfs', 'tmpfs', mountpoint])
    for directory in ('/run/netns', '/var/lib/qeli', '/var/log/qeli'):
        Path(directory).mkdir(mode=0o700)
    for name, target in [('tmp', '/tmp'), ('etc', '/etc/qeli')]:
        path = root / name
        path.mkdir(mode=0o700)
        run(['mount', '--bind', path, target])
    real = {}
    for backend in ('nft', 'legacy'):
        path = root / ('xtables-real-' + backend)
        shutil.copy2(Path(shutil.which('iptables-' + backend)).resolve(strict=True), path)
        real[backend] = str(path)
    config = dict(backends=[args.ipv4, args.ipv6], real=real, hostname=args.hostname,
                  host_net=os.environ['QELI_CM_HOST_NET'], host_mnt=os.environ['QELI_CM_HOST_MNT'],
                  firewalld=str(args.firewalld.resolve(strict=True)) if args.firewalld else None,
                  worker_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  scripts_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in sorted(scripts.iterdir()) if p.is_file()})
    configpath = root / 'fixture.json'
    configpath.write_text(json.dumps(config, indent=2))
    wrapper = root / 'wrapper'
    wrapper.write_text('#!/usr/bin/python3\nimport json,os,sys\n'
                       + f'config=json.load(open({str(configpath)!r}))\n'
                       + 'name=os.path.basename(sys.argv[0])\n'
                       + 'backend=config["backends"][int(name.startswith("ip6"))]\n'
                       + 'os.execv(config["real"][backend],[name,*sys.argv[1:]])\n')
    wrapper.chmod(0o700)
    targets = {Path(shutil.which(tool)).resolve(strict=True) for tool in ('iptables', 'ip6tables')}
    for target in targets:
        run(['mount', '--bind', wrapper, target])
    env = dict(os.environ, QELI_MIXED_FIREWALL_CONFIG=str(configpath), QELI_KEEP_WORK='1',
               QELI_DNS_CRASH_CHECK='1', QELI_DNS_KILL_SWITCH='1', QELI_ROUTE_CRASH_CHECK='1')
    # Inherited optional fault injection belongs to separate audits.
    for key in ('QELI_PERSIST_TUN_SHIM', 'QELI_ROUTE_IDENTITY_CHECK', 'QELI_IPT_DIR', 'TMPDIR'):
        env.pop(key, None)
    if args.hostname:
        hosts = root / 'hosts'
        hosts.write_text('127.0.0.1 localhost\n::1 localhost\n')
        run(['mount', '--bind', hosts, '/etc/hosts'])
        env['QELI_MATRIX_HOSTS_FILE'] = str(hosts)
    else:
        env.pop('QELI_MATRIX_HOSTS_FILE', None)
    if args.smoke:
        command = ['bash', str(scripts / 'ipv6_netns_case.sh'), str(binary), '4', 'dual', 'tcp', 'fake-tls', 'full', 'dns6']
    else:
        command = [sys.executable, str(scripts / 'run_ipv6_release_matrix.py'), str(binary),
                   '--include-special', '--evidence', str(root / 'results.json')]
    return subprocess.run(command, env=env, timeout=2200).returncode


if __name__ == '__main__':
    sys.exit(main())
