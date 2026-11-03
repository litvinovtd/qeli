#!/usr/bin/env python3
"""Optional client firewall lifecycle probes for ipv6_netns_case.sh.

Invoked only in that fixture's client/router NET namespaces, under a runner's private
mount/PID namespace. Uses real backends, real private firewalld and UDP echo traffic.
"""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import time


def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes')}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def echo(root):
    selector = selectors.DefaultSelector()
    for family, address in [(socket.AF_INET, '10.46.1.1'), (socket.AF_INET6, 'fd46:1::1')]:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.bind((address, 43889))
        selector.register(sock, selectors.EVENT_READ)
    (root / 'echo.ready').write_text('ready')
    with (root / 'received.log').open('a', buffering=1) as log:
        while True:
            for key, _ in selector.select():
                payload, peer = key.fileobj.recvfrom(4096)
                log.write(payload.decode('ascii') + '\n')
                key.fileobj.sendto(payload, peer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['echo', 'init', 'active', 'crashed', 'restarted', 'stopped'])
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--tun', default='')
    parser.add_argument('--interface', default='')
    parser.add_argument('--routing', choices=['full', 'split'], default='full')
    args = parser.parse_args()
    root = args.work / 'mixed-firewall'
    root.mkdir(mode=0o700, exist_ok=True)
    if args.stage == 'echo':
        return echo(root)
    config = json.loads(Path(os.environ['QELI_MIXED_FIREWALL_CONFIG']).read_text())
    # The outer runner must isolate mounts/PIDs; the case must isolate NET again.
    for kind in ('net', 'mnt'):
        stat = os.stat('/proc/self/ns/' + kind)
        if f'{stat.st_dev}:{stat.st_ino}' == config['host_' + kind]:
            raise RuntimeError('refusing host namespace: ' + kind)
    commands, checks = [], []

    def run(argv, *, check=True, executable=None, env=None):
        result = subprocess.run([str(a) for a in argv], executable=executable, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        commands.append(dict(argv=[str(a) for a in argv], executable=executable,
                             rc=result.returncode, output=result.stdout))
        (root / (args.stage + '-commands.json')).write_text(json.dumps(commands, indent=2))
        if check and result.returncode:
            raise RuntimeError(f'{argv}: {result.returncode}: {result.stdout}')
        return result

    def record(name, passed, **detail):
        checks.append(dict(name=name, passed=bool(passed), **detail))
        (root / (args.stage + '-results.json')).write_text(json.dumps(checks, indent=2))
        print(name, 'PASS' if passed else 'FAIL', flush=True)
        if not passed:
            raise AssertionError(name)

    def wait_for(predicate):
        until = time.monotonic() + 20
        while time.monotonic() < until:
            if predicate():
                return True
            time.sleep(.1)
        return False

    fwenv = None
    if config['firewalld']:
        package = Path(config['firewalld'])
        fwenv = dict(os.environ, PYTHONPATH=str(package / 'usr/lib/python3/dist-packages'),
                     GI_TYPELIB_PATH=str(package / 'usr/lib/x86_64-linux-gnu/girepository-1.0'),
                     LD_LIBRARY_PATH=str(package / 'usr/lib/x86_64-linux-gnu'),
                     DBUS_SYSTEM_BUS_ADDRESS='unix:path=' + str(root / 'bus'))
        fwcmd = [sys.executable, package / 'usr/bin/firewall-cmd']

    def snapshot(label):
        native = json.loads(run(['nft', '-j', 'list', 'ruleset']).stdout)['nftables']
        native = [normalize(obj) for obj in native if 'metainfo' not in obj]
        # Reload re-creates firewalld's table at another position in the dump.
        # Sort object groups only; stable sorting preserves rule order within each
        # chain, which is semantically significant and must not become a multiset.
        def group(obj):
            kind, body = next(iter(obj.items()))
            return (body.get('family', ''), body.get('table', body.get('name', '')),
                    kind, body.get('chain', body.get('name', '')))
        native.sort(key=group)
        saves, foreign = {}, []
        for backend in ('nft', 'legacy'):
            for tool in ('iptables', 'ip6tables'):
                lines = run([tool, '-S'], executable=config['real'][backend]).stdout.splitlines()
                saves[backend + ':' + tool] = lines
                foreign.extend(backend + ':' + tool + ':' + line for line in lines if 'operator-' in line)
        foreign.extend(json.dumps(obj, sort_keys=True) for obj in native
                       if next(iter(obj.values())).get('table', next(iter(obj.values())).get('name'))
                       in ('audit_operator', 'firewalld'))
        state = dict(native=native, saves=saves, foreign=sorted(foreign))
        (root / (label + '.json')).write_text(json.dumps(state, indent=2))
        return state

    def probe(label, blocked):
        for family, tool, address in [(socket.AF_INET, 'iptables', '10.46.1.1'),
                                       (socket.AF_INET6, 'ip6tables', 'fd46:1::1')]:
            def drops():
                lines = run([tool + '-save', '-c']).stdout
                matches = re.findall(r'^\[(\d+):\d+\] -A ' + re.escape('QELI_KS_' + args.tun)
                                     + r' -j DROP$', lines, re.MULTILINE)
                if len(matches) != 1:
                    raise AssertionError('missing unique DROP counter: ' + tool)
                return int(matches[0])
            before = drops() if blocked else None
            replies, sent, failures = 0, 0, []
            tokens = []
            for index in range(4):
                token = f'{args.stage}-{label}-{tool}-{index}'
                tokens.append(token)
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    # Adjacent router + explicit physical device bypasses tunnel and
                    # default/blackhole routes: a negative result must hit the firewall.
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.interface.encode() + b'\0')
                    sock.settimeout(.15 if blocked else 1)
                    try:
                        sock.sendto(token.encode(), (address, 43889))
                        sent += 1
                        data, _ = sock.recvfrom(4096)
                        replies += data == token.encode()
                    except TimeoutError:
                        pass
                    except OSError as error:
                        failures.append(str(error))
            received = (root / 'received.log').read_text().splitlines()
            hits = sum(token in received for token in tokens)
            after = drops() if blocked else None
            # sendto may report EPERM for a real local firewall DROP. The counter
            # and receiver independently prove all four attempts reached the barrier.
            passed = (replies == 0 and hits == 0 and after - before >= 4) if blocked else (replies == 4 and hits == 4)
            record(f'{label}: {tool} physical UDP ' + ('blocked' if blocked else 'reachable'), passed,
                   attempts=4, sent=sent, replies=replies, received=hits, errors=failures,
                   drop_before=before, drop_after=after)

    if args.stage == 'init':
        record('router echo is ready', wait_for(lambda: (root / 'echo.ready').exists()))
        if fwenv:
            busconf = root / 'dbus.conf'
            busconf.write_text('<busconfig><type>system</type><listen>' + fwenv['DBUS_SYSTEM_BUS_ADDRESS']
                               + '</listen><auth>EXTERNAL</auth><policy context="default"><allow user="root"/>'
                               '<allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
            def launch(argv, name, env=None):
                with (root / (name + '.log')).open('w') as log:
                    process = subprocess.Popen([str(a) for a in argv], stdout=log,
                                               stderr=subprocess.STDOUT, env=env, start_new_session=True)
                (root / (name + '.pid')).write_text(str(process.pid))
                return process
            bus = launch(['dbus-daemon', '--config-file=' + str(busconf), '--nofork', '--nopidfile'], 'dbus')
            record('private root-only bus starts', wait_for(lambda: (root / 'bus').exists()) and bus.poll() is None)
            fwconfig = root / 'config'
            fwconfig.mkdir(mode=0o700)
            (fwconfig / 'firewalld.conf').write_text('DefaultZone=trusted\nFirewallBackend=nftables\nCleanupOnExit=yes\n')
            daemon = launch([sys.executable, package / 'usr/sbin/firewalld', '--nofork', '--nopid',
                             '--system-config', fwconfig, '--default-config', package / 'usr/lib/firewalld',
                             '--log-target', 'console'], 'firewalld', fwenv)
            record('real private firewalld starts', wait_for(lambda: run(fwcmd + ['--state'], check=False,
                   env=fwenv).returncode == 0) and daemon.poll() is None)
            run(fwcmd + ['--permanent', '--zone=trusted', '--add-port=15443/tcp'], env=fwenv)
            run(fwcmd + ['--reload'], env=fwenv)
        for backend in ('nft', 'legacy'):
            for tool in ('iptables', 'ip6tables'):
                run([tool, '-A', 'OUTPUT', '-p', 'udp', '--dport', '43889', '-m', 'comment',
                     '--comment', 'operator-echo', '-j', 'ACCEPT'], executable=config['real'][backend])
        run(['nft', 'add', 'table', 'inet', 'audit_operator'])
        run(['nft', 'add', 'chain', 'inet', 'audit_operator', 'output',
             '{ type filter hook output priority 20; policy accept; }'])
        run(['nft', 'add', 'rule', 'inet', 'audit_operator', 'output', 'counter', 'accept',
             'comment', '"operator-native"'])
        for tool, backend in zip(('iptables', 'ip6tables'), config['backends']):
            version = run([tool, '--version']).stdout
            record(tool + ' runs real ' + backend, ('nf_tables' if backend == 'nft' else 'legacy') in version)
        snapshot('initial')
        probe('baseline', False)
        return

    before = snapshot(args.stage + '-before')
    initial = json.loads((root / 'initial.json').read_text())
    record(args.stage + ' preserves foreign rules in both backends', before['foreign'] == initial['foreign'])
    blocked = args.routing == 'full' and args.stage != 'stopped'
    probe('before-reload', blocked)
    if fwenv and args.stage in ('active', 'crashed'):
        run(fwcmd + ['--reload'], env=fwenv)
        after = snapshot(args.stage + '-after-reload')
        record('reload preserves real native/legacy rules', before == after)
        probe('after-reload', blocked)
    if args.stage == 'stopped':
        record('all backends are free of client rules and guards', not any(
            'QELI_KS_' in line or 'qeli-ks-rebuild:' in line for lines in before['saves'].values() for line in lines))


if __name__ == '__main__':
    main()
