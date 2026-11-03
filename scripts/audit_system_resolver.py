#!/usr/bin/env python3
"""Reproduce stalled NSS shutdown against baseline/fixed clients in private Linux namespaces.

The test-only getaddrinfo shim delays one selected carrier lookup. No external DNS,
installed service, or host firewall is used. Reports retain both the negative control
and fixed results, including firewall, route, and journal observations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

SHIM = r'''
#define _GNU_SOURCE
#include <netdb.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
static atomic_uint calls;
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    int (*real)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = dlsym(RTLD_NEXT, "getaddrinfo");
    if (!node || strcmp(node, "qeli-audit-delay.invalid")) return real(node, service, hints, res);
    unsigned call = atomic_fetch_add(&calls, 1) + 1;
    if (call != (unsigned)atoi(getenv("QELI_TEST_DNS_CALL"))) return real("192.0.2.2", service, hints, res);
    int fd = open(getenv("QELI_TEST_DNS_READY"), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(112);
    dprintf(fd, "%u\n", call); close(fd);
    for (unsigned i=0; i<450; ++i) usleep(100000);
    return EAI_AGAIN;
}
'''


def ns(kind):
    info = os.stat('/proc/self/ns/' + kind)
    return f'{info.st_dev}:{info.st_ino}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qeli', required=True, type=Path)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--inside', choices=['engage', 'refresh', 'tcp', 'udp'], help=argparse.SUPPRESS)
    parser.add_argument('--version', choices=['baseline', 'fixed'], help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.artifacts.resolve()
    binaries = dict(baseline=args.baseline.resolve(strict=True), fixed=args.qeli.resolve(strict=True))
    if not args.inside:
        if os.geteuid() != 0:
            raise RuntimeError('root in a disposable Linux lab is required')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_SR_HOST_NET=ns('net'), QELI_SR_HOST_MNT=ns('mnt'))
        rows = []
        for case in ['engage', 'refresh', 'tcp', 'udp']:
            for version in ['baseline', 'fixed']:
                work = root / (case + '-' + version)
                work.mkdir(mode=0o700)
                command = ['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL',
                           '--mount-proc', sys.executable, str(Path(__file__).resolve()),
                           '--qeli', str(binaries['fixed']), '--baseline', str(binaries['baseline']),
                           '--artifacts', str(work), '--inside', case, '--version', version]
                with (work / 'fixture.log').open('w') as log:
                    process = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=60)
                report = work / 'result.json'
                rows.append(dict(case=case, version=version, exit_code=process.returncode,
                                 result=json.loads(report.read_text()) if report.exists() else None))
                (root / 'results.json').write_text(json.dumps(rows, indent=2))
                print(case, version, process.returncode, flush=True)
        assert all(r['exit_code'] == 0 for r in rows), rows
        return 0
    if (not os.environ.get('QELI_SR_HOST_NET') or ns('net') == os.environ['QELI_SR_HOST_NET']
            or ns('mnt') == os.environ.get('QELI_SR_HOST_MNT')):
        raise RuntimeError('private network/mount/PID context is mandatory')
    commands = []

    def run(argv):
        process = subprocess.run([str(a) for a in argv], check=False, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, timeout=15)
        commands.append(dict(argv=[str(a) for a in argv], rc=process.returncode, output=process.stdout))
        (root / 'commands.json').write_text(json.dumps(commands, indent=2))
        if process.returncode:
            raise RuntimeError(f'{argv}: {process.stdout}')
        return process.stdout

    run(['mount', '--make-rprivate', '/'])
    for target in ['/run', '/var/lib', '/var/log', '/tmp']:
        run(['mount', '-t', 'tmpfs', 'tmpfs', target])
    configdir = root / 'etc-qeli'
    configdir.mkdir(mode=0o700)
    run(['mount', '--bind', configdir, '/etc/qeli'])
    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['ip', 'link', 'add', 'wan0', 'type', 'dummy'])
    run(['ip', 'link', 'set', 'wan0', 'up'])
    run(['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'wan0'])
    run(['ip', 'route', 'add', 'default', 'dev', 'wan0'])
    for tool in ['iptables', 'ip6tables']:
        run([tool, '-N', 'OPERATOR_SENTINEL'])
        run([tool, '-A', 'OPERATOR_SENTINEL', '-j', 'RETURN'])
        run([tool, '-A', 'OUTPUT', '-j', 'OPERATOR_SENTINEL'])

    def snapshot(label):
        data = dict(firewall=[run([tool, '-S']) for tool in ['iptables', 'ip6tables']],
                    routes=[run(['ip', family, 'route', 'show', 'table', 'all']) for family in ['-4', '-6']],
                    links=json.loads(run(['ip', '-j', 'link'])),
                    journals=sorted(str(p.relative_to(root)) for p in root.rglob('*.state')))
        (root / (label + '.json')).write_text(json.dumps(data, indent=2))
        return data

    source = root / 'resolver-delay.c'
    source.write_text(SHIM)
    shim = root / 'resolver-delay.so'
    run(['cc', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC', source, '-o', shim, '-ldl'])
    state = root / 'state'
    state.mkdir(mode=0o700)
    ready = root / 'nss.ready'
    config = configdir / 'client.ini'
    ks = args.inside in ['engage', 'refresh']
    config.write_text(f'''[qeli]
server = qeli-audit-delay.invalid:24443
proto = {'udp' if args.inside == 'udp' else 'tcp'}
user = audit-user
pass = audit-fixture-pass
mode = fake-tls
dev = qeli-dns0
bind_static = false
gateway = true
dns = off
kill_switch = {str(ks).lower()}
timeout = 20
[logging]
level = debug
''')
    config.chmod(0o600)
    binary = binaries[args.version]
    env = dict(os.environ, STATE_DIRECTORY=str(state), LD_PRELOAD=str(shim),
               QELI_TEST_DNS_CALL='2' if args.inside == 'refresh' else '1',
               QELI_TEST_DNS_READY=str(ready))
    before = snapshot('before')
    with (root / 'client.log').open('w') as log:
        client = subprocess.Popen([str(binary), 'client', '-c', str(config)], env=env,
                                  stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 20
            while not ready.exists():
                assert client.poll() is None, (root / 'client.log').read_text()
                assert time.monotonic() < deadline, 'NSS fixture did not start'
                time.sleep(.02)
            assert int(ready.read_text()) == (2 if args.inside == 'refresh' else 1)
            active = snapshot('stalled')
            assert any('QELI_KS' in rules for rules in active['firewall']) == (args.inside == 'refresh')
            started = time.monotonic()
            client.send_signal(signal.SIGTERM)
            timed_out = False
            try:
                rc = client.wait(timeout=3)
            except subprocess.TimeoutExpired:
                timed_out = True
                client.kill()
                rc = client.wait(timeout=5)
            elapsed = time.monotonic() - started
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
    after = snapshot('after')
    clean = (after['firewall'] == before['firewall'] and after['routes'] == before['routes']
             and not after['journals'] and all(link['ifname'] != 'qeli-dns0' for link in after['links']))
    result = dict(case=args.inside, version=args.version, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  namespace=dict(net=ns('net'), mount=ns('mnt')), stalled_call=int(ready.read_text()),
                  forced_kill=timed_out, exit_code=rc, stop_seconds=elapsed, clean=clean)
    (root / 'result.json').write_text(json.dumps(result, indent=2))
    if args.version == 'baseline':
        assert timed_out, 'negative control unexpectedly stopped; reproduction invalid'
    else:
        assert not timed_out and rc == 0, result
        assert clean, 'fixed stop must restore operator firewall/routes and release journals'
    return 0


if __name__ == '__main__':
    sys.exit(main())
