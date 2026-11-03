#!/usr/bin/env python3
"""Real nft/legacy coexistence and firewalld reload around Qeli worker SIGKILL.

All mutations occur after fresh net/mount/PID isolation. Package extraction for an
optional private firewalld runtime is external to this runner; no service is installed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def ns(kind):
    info = os.stat('/proc/self/ns/' + kind)
    return f'{info.st_dev}:{info.st_ino}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qeli', required=True, type=Path)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--ipv4', choices=['nft', 'legacy'], required=True)
    parser.add_argument('--ipv6', choices=['nft', 'legacy'], required=True)
    parser.add_argument('--drift', choices=['4', '6'], required=True)
    parser.add_argument('--firewalld', type=Path, help='extracted package root, never a host daemon')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.qeli.resolve(strict=True)
    root = args.artifacts.resolve()
    if not args.inside:
        if os.geteuid() != 0:
            raise RuntimeError('requires root in an isolated Linux lab')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_MIXED_PARENT_NET=ns('net'), QELI_MIXED_PARENT_MNT=ns('mnt'))
        return subprocess.run(['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL',
                               '--mount-proc', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside'], env=env, timeout=180).returncode
    if (not os.environ.get('QELI_MIXED_PARENT_NET') or
            ns('net') == os.environ['QELI_MIXED_PARENT_NET'] or
            ns('mnt') == os.environ.get('QELI_MIXED_PARENT_MNT')):
        raise RuntimeError('fresh network/mount/PID fixture is mandatory')
    commands, checks, processes = [], [], []
    identity = {'worker_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'backends': [args.ipv4, args.ipv6], 'drift': args.drift,
                'firewalld': str(args.firewalld) if args.firewalld else None,
                'network': ns('net')}

    def run(argv, *, check=True, executable=None, env=None):
        result = subprocess.run([str(a) for a in argv], executable=executable, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        commands.append({'argv': [str(a) for a in argv], 'executable': str(executable) if executable else None,
                         'rc': result.returncode, 'output': result.stdout})
        (root / 'commands.json').write_text(json.dumps(commands, indent=2))
        if check and result.returncode:
            raise RuntimeError(f'{argv}: {result.returncode}: {result.stdout}')
        return result

    def record(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})
        (root / 'results.json').write_text(json.dumps(dict(identity, checks=checks), indent=2))
        print(f'{name}: {"PASS" if condition else "FAIL"}', flush=True)
        if not condition:
            raise AssertionError(name)

    def wait_for(predicate, seconds=20):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return True
            time.sleep(.05)
        return False

    def launch(argv, path, env=None):
        with path.open('w') as log:
            process = subprocess.Popen([str(a) for a in argv], env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process

    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    run(['mount', '--make-rprivate', '/'])
    for mountpoint in ['/run', '/var/lib', '/var/log']:
        run(['mount', '-t', 'tmpfs', 'tmpfs', mountpoint])
    for directory in ['/var/lib/qeli', '/var/log/qeli', '/run/qeli-audit']:
        Path(directory).mkdir(mode=0o700)
    configdir, state = root / 'etc-qeli', root / 'state'
    configdir.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    if not Path('/etc/qeli').is_dir():
        raise RuntimeError('existing /etc/qeli mount point required')
    run(['mount', '--bind', configdir, '/etc/qeli'])
    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['ip', 'link', 'add', 'wan0', 'type', 'dummy'])
    run(['ip', 'link', 'set', 'wan0', 'up'])
    run(['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'wan0'])
    run(['ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'wan0', 'nodad'])
    run(['ip', '-6', 'route', 'add', 'default', 'dev', 'wan0'])
    (configdir / 'users.conf').write_text('')
    # The test administrator keeps its own original descriptor across worker death.
    # Qeli cannot recover this witness from its durable journal (the D02 boundary).
    ra_path = '/proc/sys/net/ipv6/conf/wan0/accept_ra'
    ra_fd = os.open(ra_path, os.O_RDWR | os.O_CLOEXEC)
    ra_original = os.pread(ra_fd, 128, 0).decode().strip()


    real = {}
    for backend in ['nft', 'legacy']:
        multi = Path(shutil.which('iptables-' + backend)).resolve(strict=True)
        real[backend] = root / ('xtables-real-' + backend)
        shutil.copy2(multi, real[backend])
        identity[backend + '_binary_sha256'] = hashlib.sha256(real[backend].read_bytes()).hexdigest()
    selection = root / 'backends.json'
    selection.write_text(json.dumps([args.ipv4, args.ipv6]))
    wrapper = root / 'iptables-wrapper'
    wrapper.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\n'
                       + f'root=Path({str(root)!r})\n'
                       + 'name=os.path.basename(sys.argv[0])\n'
                       + 'family=1 if name.startswith("ip6") else 0\n'
                       + 'backend=json.loads((root/"backends.json").read_text())[family]\n'
                       + 'os.execv(str(root/("xtables-real-"+backend)),[name,*sys.argv[1:]])\n')
    wrapper.chmod(0o700)
    # Default iptables and ip6tables resolve to the same nft multi-call executable
    # on this lab. Overlay it only in the private mount namespace; direct snapshots
    # below use copies and cannot be redirected by backend drift.
    targets = {Path(shutil.which(tool)).resolve(strict=True) for tool in ['iptables', 'ip6tables']}
    for target in targets:
        run(['mount', '--bind', wrapper, target])

    def legacy(family):
        tool = 'ip6tables-save' if family else 'iptables-save'
        return run([tool], executable=real['legacy']).stdout.splitlines()

    def nft_objects():
        return json.loads(run(['nft', '-j', 'list', 'ruleset']).stdout)['nftables']

    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()
                    if key not in ['handle', 'packets', 'bytes']}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    foreign_handles = set()

    def snapshot(label):
        nft = nft_objects()
        old = [legacy(0), legacy(1)]
        owned = [[], []]
        foreign = []
        for obj in nft:
            kind, body = next(iter(obj.items()))
            if kind == 'metainfo':
                continue
            comment = body.get('comment', '')
            key = (body.get('family'), body.get('table'), body.get('chain'), body.get('handle'))
            if (body.get('table', body.get('name')) in ['audit_operator', 'firewalld'] or
                    comment.startswith('operator-') or kind == 'rule' and key in foreign_handles):
                foreign.append(normalize(obj))
            elif kind == 'rule':
                # nft JSON omits the payload of an xt comment match. In this
                # private fixture, rule identities present before Qeli are foreign;
                # new rules outside the two operator tables must belong to Qeli.
                owned[int(body['family'] == 'ip6')].append(normalize(obj))
        for family, lines in enumerate(old):
            owned[family].extend(line for line in lines if line.startswith('-A ') and 'qeli-nat:' in line)
            foreign.extend(f'legacy{family}:{line}' for line in lines if line.startswith('-A ') and 'operator-' in line)
        result = {'owned': owned, 'foreign': sorted(foreign, key=lambda item: json.dumps(item, sort_keys=True))}
        (root / (label + '.json')).write_text(json.dumps(result, indent=2))
        return result

    def config(name, active):
        path = configdir / (name + '.ini')
        path.write_text(f'''[auth]
users_file = /etc/qeli/users.conf
[web]
enabled = false
[logging]
level = debug
[profile:{name}]
identity_key = /etc/qeli/{name}.key
bind.address = 127.0.0.1
bind.port = 24443
bind.transport = tcp
tun.name = qmixed0
tun.address = 10.74.0.1
tun.ip_mode = {'dual' if active else 'ipv4'}
{'tun.ipv6_address = fd74::1' if active else ''}
tun.queues = 1
pool.cidr = 10.74.0.0/24
{'pool.ipv6.cidr = fd74::/64' if active else ''}
routing.nat.enabled = {'true' if active else 'false'}
routing.nat.interface = wan0
routing.forward_private = {'true' if active else 'false'}
routing.ipv6.mode = {'nat66' if active else 'off'}
routing.ipv6.interface = wan0
routing.post_up = printf up > {root / (name + '.up')}
dns.enabled = {'true' if active else 'false'}
dns.listen = 10.74.0.1
{'dns.listen_ipv6 = fd74::1' if active else ''}
dns.port = 1053
obf.mode = fake-tls
''')
        path.chmod(0o600)
        return path

    def worker(name, active=False):
        path = config(name, active)
        env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_CONTROL_SOCKET='/run/qeli-audit/' + name + '.sock')
        proc = launch([binary, '_worker', '-c', path], root / (name + '.log'), env)
        return proc, path

    def ready(name, process):
        return wait_for(lambda: process.poll() is not None or
                        f"Profile '{name}' listening on" in (root / (name + '.log')).read_text()) and process.poll() is None

    try:
        if args.firewalld:
            package = args.firewalld.resolve(strict=True)
            fwenv = dict(os.environ, PYTHONPATH=str(package / 'usr/lib/python3/dist-packages'),
                         GI_TYPELIB_PATH=str(package / 'usr/lib/x86_64-linux-gnu/girepository-1.0'),
                         LD_LIBRARY_PATH=str(package / 'usr/lib/x86_64-linux-gnu'),
                         DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/qeli-audit-bus')
            busconf = root / 'dbus.conf'
            busconf.write_text('<busconfig><type>system</type><listen>unix:path=/run/qeli-audit-bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="root"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
            launch(['dbus-daemon', '--config-file=' + str(busconf), '--nofork', '--nopidfile'], root / 'dbus.log')
            record('private bus starts', wait_for(lambda: Path('/run/qeli-audit-bus').exists()))
            fwconfig = root / 'firewalld-config'
            fwconfig.mkdir(mode=0o700)
            (fwconfig / 'firewalld.conf').write_text('DefaultZone=trusted\nFirewallBackend=nftables\nCleanupOnExit=yes\n')
            daemon = launch([sys.executable, package / 'usr/sbin/firewalld', '--nofork', '--nopid',
                             '--system-config', fwconfig, '--default-config', package / 'usr/lib/firewalld',
                             '--log-target', 'console'], root / 'firewalld.log', fwenv)
            fwcmd = [sys.executable, package / 'usr/bin/firewall-cmd']
            record('real private firewalld starts', wait_for(lambda: daemon.poll() is not None or
                   run(fwcmd + ['--state'], check=False, env=fwenv).returncode == 0) and daemon.poll() is None)
            run(fwcmd + ['--permanent', '--zone=trusted', '--add-port=15443/tcp'], env=fwenv)
            run(fwcmd + ['--reload'], env=fwenv)
        # Independent operator rules exist in both backend families, even when Qeli
        # is configured to use only one. Native rules are outside Qeli's tag namespace.
        for backend in ['nft', 'legacy']:
            for tool in ['iptables', 'ip6tables']:
                run([tool, '-A', 'FORWARD', '-m', 'comment', '--comment', 'operator-kept', '-j', 'ACCEPT'], executable=real[backend])
        run(['nft', 'add', 'table', 'inet', 'audit_operator'])
        run(['nft', 'add', 'chain', 'inet', 'audit_operator', 'forward', '{ type filter hook forward priority 20; policy accept; }'])
        run(['nft', 'add', 'rule', 'inet', 'audit_operator', 'forward', 'counter', 'accept', 'comment', '"operator-native-table"'])
        for sysctl in ['/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding']:
            Path(sysctl).write_text('0')
        for obj in nft_objects():
            rule = obj.get('rule')
            if rule and rule['table'] not in ['audit_operator', 'firewalld']:
                foreign_handles.add((rule['family'], rule['table'], rule['chain'], rule['handle']))
        initial_foreign = snapshot('before-worker')['foreign']
        first, path = worker('first', True)
        record('dual-stack NAT and DNS worker starts', ready('first', first))
        active = snapshot('active')
        record('both families own NAT and DNS rules', all(len(rules) >= 9 for rules in active['owned']))
        record('setup preserves all foreign rules', active['foreign'] == initial_foreign)
        if args.firewalld:
            run(fwcmd + ['--reload'], env=fwenv)
            reloaded = snapshot('firewalld-reloaded')
            record('firewalld reload preserves both Qeli families', reloaded['owned'] == active['owned'])
            record('firewalld reload retains operator configuration', reloaded['foreign'] == initial_foreign)
        # Genuine nft expressions make iptables-nft enumeration incompatible while
        # exact -C/-D remain usable. No fabricated command errors are involved.
        for family in ['ip', 'ip6']:
            run(['nft', 'add', 'rule', family, 'filter', 'FORWARD', 'meta', 'mark', 'set',
                 'numgen', 'inc', 'mod', '2', 'comment', '"operator-opaque"'])
        for family, tool in enumerate(['iptables', 'ip6tables']):
            listing = run([tool, '-S', 'FORWARD'], executable=real['nft'], check=False)
            record(f'native nft family {family} really rejects listing', listing.returncode != 0 and 'incompatible' in listing.stdout)
        before = snapshot('before-crash')
        journal = state / 'server-firewall.state'
        pending = json.loads(journal.read_bytes())
        record('journal records every exact rule and both backends',
               sum(len(g['rules']) for g in pending['namespaces'].values()) == sum(map(len, before['owned'])) and
               all(g['backends'] == [args.ipv4, args.ipv6] for g in pending['namespaces'].values()))
        exact_present = True
        for group in pending['namespaces'].values():
            for rule in group['rules']:
                family = int(rule['ipv6'])
                tool = 'ip6tables' if family else 'iptables'
                observed = run([tool, '-t', rule['table'], '-C', rule['chain'], *rule['args']],
                               executable=real[group['backends'][family]], check=False)
                exact_present = exact_present and observed.returncode == 0
        record('every journal specification matches an exact kernel rule', exact_present)
        first.kill()
        first.wait(timeout=5)
        path.unlink()
        record('SIGKILL preserves exact rules and foreign state', snapshot('after-crash') == before)
        changed = int(args.drift == '6')
        backends = [args.ipv4, args.ipv6]
        backends[changed] = 'legacy' if backends[changed] == 'nft' else 'nft'
        selection.write_text(json.dumps(backends))
        failed, _ = worker('refused')
        record('actual backend switch refuses worker startup', wait_for(lambda: failed.poll() is not None) and
               failed.returncode != 0 and 'iptables backend changed' in (root / 'refused.log').read_text())
        record('refused worker never reaches profile hook', not (root / 'refused.up').exists())
        partial = snapshot('partial-recovery')
        record('drifted family rules remain in original backend', partial['owned'][changed] == before['owned'][changed])
        record('unchanged family kernel rules are removed despite native listing failure', not partial['owned'][1-changed])
        record('failed recovery preserves all foreign rules', partial['foreign'] == before['foreign'])
        remaining = json.loads(journal.read_bytes())
        def uncertain_nft(rule):
            return ([args.ipv4, args.ipv6][int(rule['ipv6'])] == 'nft' and
                    rule['table'] == 'filter' and rule['chain'] == 'FORWARD')

        def records(document):
            return sorted(json.dumps(rule, sort_keys=True)
                          for group in document['namespaces'].values() for rule in group['rules'])

        original_rules = [r for g in pending['namespaces'].values() for r in g['rules']]
        expected = sorted(json.dumps(r, sort_keys=True) for r in original_rules
                          if int(r['ipv6']) == changed or uncertain_nft(r))
        record('journal retains backend conflicts and unconfirmed nft absence', records(remaining) == expected and
               all(g['backends'][int(r['ipv6'])] == [args.ipv4, args.ipv6][int(r['ipv6'])]
                   for g in remaining['namespaces'].values() for r in g['rules']))
        selection.write_text(json.dumps([args.ipv4, args.ipv6]))
        expected_foreign = before['foreign']
        if 'nft' in [args.ipv4, args.ipv6]:
            incompatible, _ = worker('incompatible')
            record('unreadable nft absence still refuses startup after backend restoration',
                   wait_for(lambda: incompatible.poll() is not None) and incompatible.returncode != 0 and
                   'Parsing nftables rule failed' in (root / 'incompatible.log').read_text() and
                   not (root / 'incompatible.up').exists())
            observed = snapshot('unconfirmed-absence')
            record('kernel rules are removed but unknown absence does not discard evidence',
                   not any(observed['owned']) and
                   records(json.loads(journal.read_bytes())) ==
                   sorted(json.dumps(r, sort_keys=True) for r in original_rules if uncertain_nft(r)))
            record('incompatible recovery leaves all operator rules intact', observed['foreign'] == before['foreign'])
            repaired_families = ['ip6' if i else 'ip' for i, backend in enumerate([args.ipv4, args.ipv6]) if backend == 'nft']
            # Explicit operator repair of only the test-owned opaque expressions.
            # Qeli must never treat a parse error as absence or flush this chain.
            opaque = [obj['rule'] for obj in nft_objects() if 'rule' in obj and
                      obj['rule'].get('comment') == 'operator-opaque' and obj['rule']['family'] in repaired_families]
            record('operator repair identifies exactly the incompatible test rules',
                   len(opaque) == len(repaired_families))
            for rule in opaque:
                run(['nft', 'delete', 'rule', rule['family'], rule['table'], rule['chain'], 'handle', str(rule['handle'])])
            expected_foreign = [obj for obj in before['foreign'] if not isinstance(obj, dict) or
                                obj.get('rule', {}).get('comment') != 'operator-opaque' or
                                obj['rule']['family'] not in repaired_families]
            record('operator repair preserves every other foreign rule',
                   snapshot('operator-repaired')['foreign'] == expected_foreign)
        sysctl_refused, _ = worker('sysctl-refused')
        record('firewall recovery completes before the known lost-sysctl-witness refusal',
               wait_for(lambda: sysctl_refused.poll() is not None) and sysctl_refused.returncode != 0 and
               'lost live per-interface sysctl evidence' in (root / 'sysctl-refused.log').read_text() and
               not json.loads(journal.read_bytes())['namespaces'])
        sysctls = state / 'sysctls.state'
        data = sysctls.read_bytes()
        (root / 'sysctls-before-manual.state').write_bytes(data)
        document = json.loads(data)
        entries = [entry for group in document['namespaces'].values() for entry in group['entries'].items()]
        record('only the original WAN accept_ra requires explicit operator recovery',
               len(entries) == 1 and entries[0][0] == ra_path and entries[0][1]['original'] == ra_original and
               not entries[0][1]['owners'] and os.pread(ra_fd, 128, 0).decode().strip() == entries[0][1]['managed'])
        # Restore through the administrator's retained ORIGINAL fd, then retire only
        # this verified fixture record. No live worker or other journal entries exist.
        os.pwrite(ra_fd, (ra_original + '\n').encode(), 0)
        for key, group in list(document['namespaces'].items()):
            group['entries'].pop(ra_path, None)
            if not group['entries']:
                del document['namespaces'][key]
        sysctls.write_text(json.dumps(document))
        (root / 'sysctls-after-manual.state').write_bytes(sysctls.read_bytes())
        record('operator restores original accept_ra before retiring its known record',
               os.pread(ra_fd, 128, 0).decode().strip() == ra_original and not document['namespaces'])
        recovered, _ = worker('recovered')
        record('original backend resumes recovery of deleted profile', ready('recovered', recovered))
        restored = snapshot('recovered')
        record('both families have no remaining Qeli rules', not any(restored['owned']))
        record('recovery preserves native, opposite-backend and firewalld rules', restored['foreign'] == expected_foreign)
        record('successful recovery empties the journal', not json.loads(journal.read_bytes())['namespaces'])
        stop(recovered)
        record('recovered worker stops cleanly', recovered.returncode == 0)
        record('clean stop preserves foreign state', snapshot('stopped')['foreign'] == expected_foreign)
        record('IPv4 and IPv6 forwarding return to baseline', all(Path(p).read_text().strip() == '0' for p in
               ['/proc/sys/net/ipv4/ip_forward', '/proc/sys/net/ipv6/conf/all/forwarding']))
    finally:
        for process in reversed(processes):
            stop(process)
        os.close(ra_fd)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
