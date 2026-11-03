#!/usr/bin/env python3
"""Four real dual-stack profiles in private NET/mount/PID namespaces.
Invoke through audit_release_matrix_lab.ISOLATED. DNS probes originate on the
server host; this checks proxy/listener composition, not encrypted VPN traffic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import threading
import time

from dns_test_server import build_query, build_response, parse_answer


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('qeli', 'sha256', 'artifacts', 'parent-net', 'parent-mnt', 'parent-pid'):
        ap.add_argument('--' + name, required=True)
    ap.add_argument('--backend', choices=('nft', 'legacy'), required=True)
    ap.add_argument('--transitions',action='store_true',help='Check all 36 mode/NDP/address-family configurations and 16 stop/restart mode transitions')
    ap.add_argument('--firewalld', help='read-only extracted private runtime; enables mixed backends and packet policy probes')
    ap.add_argument('--ipv4', choices=('nft', 'legacy'))
    ap.add_argument('--ipv6', choices=('nft', 'legacy'))
    args = ap.parse_args()
    assert bool(args.firewalld) == bool(args.ipv4 and args.ipv6)
    for kind in ('net', 'mnt', 'pid'):
        assert os.readlink('/proc/self/ns/' + kind) != getattr(args, 'parent_' + kind)
    binary = Path(args.qeli).resolve(strict=True)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256
    root = Path(args.artifacts)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    results, commands = [], []
    worker = None
    mixed = None
    completed = False

    def run(argv, check=True, env=None, executable=None):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=25, env=env, executable=executable)
        commands.append(dict(argv=argv, executable=executable, exit_code=p.returncode, output=p.stdout + p.stderr))
        (root / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if check:
            assert p.returncode == 0, (argv, p.stdout, p.stderr)
        return p

    def record(name, ok, detail=None):
        results.append(dict(name=name, passed=bool(ok), detail=detail))
        (root / 'checks.json').write_text(json.dumps(results, indent=2) + '\n')
        assert ok, (name, detail)
        print('PASS', name, flush=True)

    def until(predicate, seconds=30):
        end = time.monotonic() + seconds
        while not predicate():
            if worker is not None and worker.poll() is not None:
                raise RuntimeError('worker exited; inspect worker log')
            assert time.monotonic() < end, 'readiness timeout'
            time.sleep(.05)

    if args.firewalld:
        from audit_firewalld_profiles import MixedFirewall
        mixed = MixedFirewall(root, args.firewalld, args.ipv4, args.ipv6, run, record)
    if args.backend == 'legacy' and mixed is None:
        # The standard iptables family shares this multicall binary on this lab.
        # Private mount only; dispatch on argv0 preserves iptables/ip6tables/save.
        target = Path('/usr/sbin/iptables').resolve(strict=True)
        assert target.name == 'xtables-nft-multi', target
        wrapper = root / 'xtables-wrapper'
        wrapper.write_text('#!/bin/sh\nexec /usr/sbin/xtables-legacy-multi "$(basename "$0")" "$@"\n')
        wrapper.chmod(0o700)
        run(['mount', '--bind', str(wrapper), str(target)])
    version = run(['iptables', '--version']).stdout.strip()
    record('selected real firewall backend', ('legacy' if (args.ipv4 or args.backend) == 'legacy' else 'nf_tables') in version, version)
    for cmd in (['ip', 'link', 'set', 'lo', 'up'], ['ip', 'link', 'add', 'wan0', 'type', 'dummy'],
                ['ip', 'link', 'set', 'wan0', 'up'], ['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'wan0'],
                ['ip', '-6', 'addr', 'add', '2001:db8:ffff::1/64', 'dev', 'wan0', 'nodad']):
        run(cmd)
    for family in ('ipv4/ip_forward', 'ipv6/conf/all/forwarding', 'ipv6/conf/default/forwarding'):
        Path('/proc/sys/net/' + family).write_text('0')
    for tool in ('iptables', 'ip6tables'):
        # A read-only query does not instantiate unused nft tables. Create and
        # remove a private empty chain before taking the exact rules baseline.
        for table in ('nat', 'mangle'):
            run([tool, '-t', table, '-N', 'audit-prime'])
            run([tool, '-t', table, '-X', 'audit-prime'])
        run([tool, '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
        run([tool, '-A', 'FORWARD', '-m', 'comment', '--comment', 'audit-foreign', '-j', 'DROP'])
        run([tool, '-P', 'INPUT', 'DROP'])
        run([tool, '-P', 'FORWARD', 'DROP'])
    if mixed:
        try:
            mixed.prepare()
        except BaseException:
            mixed.close()
            (root / 'result.json').write_text(json.dumps(dict(status='FAIL', backends=mixed.backends, check_count=len(results), checks=results), indent=2) + '\n')
            raise
    until(lambda:'scope link' in run(['ip','-6','addr','show','dev','wan0']).stdout and 'tentative' not in run(['ip','-6','addr','show','dev','wan0']).stdout)

    def snapshot():
        rules = {}
        for family, tool in (('v4', 'iptables-save'), ('v6', 'ip6tables-save')):
            rules[family] = re.sub(r'\[\d+:\d+\]', '[COUNTERS]', '\n'.join(
                x for x in run([tool]).stdout.splitlines() if not x.startswith('#')))
        return dict(rules=rules, routes4=run(['ip', '-4', 'route', 'show', 'table', 'all']).stdout,
                    routes6=run(['ip', '-6', 'route', 'show', 'table', 'all']).stdout,
                    links=json.loads(run(['ip', '-j', 'link']).stdout),
                    mixed_firewall=mixed.snapshot() if mixed else None,
                    sysctls={name:Path('/proc/sys/net/' + name).read_text().strip() for name in
                             ('ipv4/ip_forward', 'ipv6/conf/all/forwarding', 'ipv6/conf/default/forwarding', 'ipv6/conf/wan0/accept_ra')})

    before = snapshot()
    (root / 'network-before.json').write_text(json.dumps(before, indent=2))
    state = root / 'state'
    state.mkdir(mode=0o700)
    cfg = Path('/etc/qeli/server.conf')
    Path('/etc/qeli/users.conf').write_text('')
    modes = ('off', 'manual', 'route', 'nat66')
    base = '[auth]\nusers_file = /etc/qeli/users.conf\n[web]\nenabled = false\n[logging]\nlevel = debug\n'

    def profile(i, mode, ndp_iface='wan0'):
        return f'''[profile:{mode}]
identity_key = /etc/qeli/{mode}.key
bind.address = 127.0.0.1
bind.port = {25443+i}
bind.transport = {'tcp' if i % 2 == 0 else 'udp'}
tun.name = qmx{i}
tun.address = 10.{81+i}.0.1
tun.ip_mode = dual
tun.ipv6_address = 2001:db8:{81+i}::1
tun.queues = 1
pool.cidr = 10.{81+i}.0.0/24
pool.ipv6.cidr = 2001:db8:{81+i}::/64
routing.nat.enabled = true
routing.nat.interface = wan0
routing.forward_private = true
routing.ipv6.mode = {mode}
routing.ipv6.interface = wan0
routing.ipv6.ndp_proxy = {'required' if mode in ('manual','route') else 'off'}
routing.ipv6.ndp_proxy_interface = {ndp_iface}
routing.post_up = printf up >> {root}/up-{mode}
routing.post_down = printf down >> {root}/down-{mode}
dns.enabled = true
dns.listen = 10.{81+i}.0.1
dns.listen_ipv6 = 2001:db8:{81+i}::1
dns.port = {10530+i}
dns.upstream = 127.0.0.1
dns.cache_size = 16
obf.mode = fake-tls
'''

    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(('127.0.0.1', 53))
    upstream.settimeout(.2)
    stop = threading.Event()
    queries = []

    def serve():
        while not stop.is_set():
            try:
                packet, peer = upstream.recvfrom(65535)
            except socket.timeout:
                continue
            response, name, qtype = build_response(packet)
            queries.append(dict(name=name, qtype=qtype))
            upstream.sendto(response, peer)

    thread = threading.Thread(target=serve)
    thread.start()
    env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_CONTROL_SOCKET=str(root / 'control.sock'))

    def launch(text, label, indices):
        nonlocal worker
        cfg.write_text(text)
        cfg.chmod(0o600)
        run([str(binary), 'check-config', '-c', str(cfg)])
        previous = {m:len((root / ('up-' + m)).read_text()) if (root / ('up-' + m)).exists() else 0 for _, m in indices}
        with (root / (label + '.log')).open('w') as log:
            worker = subprocess.Popen([str(binary), '_worker', '-c', str(cfg)], env=env, stdout=log, stderr=subprocess.STDOUT)
        until(lambda:all((root / ('up-' + m)).exists() and len((root / ('up-' + m)).read_text()) > previous[m] for _, m in indices))
        until(lambda:all((':' + str(25443+i)) in run(['ss', '-lnt' if i % 2 == 0 else '-lnu']).stdout for i, _ in indices))

    def halt(label):
        nonlocal worker
        worker.send_signal(signal.SIGTERM)
        rc = worker.wait(timeout=35)
        worker = None
        record(label + ' clean worker exit', rc == 0, rc)
        after = snapshot()
        (root / ('network-' + label + '.json')).write_text(json.dumps(after, indent=2))
        record(label + ' restores network and foreign rules', after == before)
        record(label + ' removes journal and control socket', not (state / 'sysctls.state').exists() and not (root / 'control.sock').exists())

    def query(i, mode, ipv6, tcp, qtype):
        address = f'2001:db8:{81+i}::1' if ipv6 else f'10.{81+i}.0.1'
        txid = (i+1)*100 + qtype*2 + int(tcp)
        payload = build_query('matrix.invalid', qtype, txid)
        with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            if tcp:
                sock.connect((address, 10530+i))
                sock.sendall(struct.pack('!H', len(payload)) + payload)
                def receive(n):
                    value = b''
                    while len(value) < n:
                        part = sock.recv(n-len(value))
                        assert part, 'DNS TCP closed early'
                        value += part
                    return value
                response = receive(struct.unpack('!H', receive(2))[0])
            else:
                sock.sendto(payload, (address, 10530+i))
                response, peer = sock.recvfrom(65535)
                assert peer[0] == address
        actual = parse_answer(response, txid, qtype)
        expected = '192.0.2.80' if qtype == 1 else '2001:db8::80'
        record(f'{mode} DNS IPv{6 if ipv6 else 4} {"TCP" if tcp else "UDP"} {"A" if qtype == 1 else "AAAA"}', actual == expected, actual)

    try:
        text = base + ''.join(profile(i, m) for i, m in enumerate(modes))
        launch(text, 'four-profiles', list(enumerate(modes)))
        active = snapshot()
        (root / 'network-active.json').write_text(json.dumps(active, indent=2))
        record('four mixed-mode TCP/UDP profiles ready', worker.poll() is None)
        rules6 = active['rules']['v6']
        lines6 = rules6.splitlines()
        record('off has two mandatory transit DROP rules', sum('qeli-nat:off' in line and 'FORWARD' in line and '-j DROP' in line for line in lines6) == 2)
        record('manual publishes no IPv6 firewall rules', 'qeli-nat:manual' not in rules6)
        record('route preserves addresses without MASQUERADE', not any('qeli-nat:route' in x and 'MASQUERADE' in x for x in lines6))
        record('nat66 has MASQUERADE and off-WAN DROP', any('qeli-nat:nat66' in x and 'MASQUERADE' in x for x in lines6) and any('qeli-nat:nat66' in x and '! -o wan0' in x and '-j DROP' in x for x in lines6))
        forward = [x for x in lines6 if x.startswith('-A FORWARD')]
        first_permit = next((i for i, line in enumerate(forward) if '-j ACCEPT' in line), len(forward))
        record('all managed transit DROP guards precede permits', all(i < first_permit for i, x in enumerate(forward) if 'qeli-nat:' in x and '-j DROP' in x))
        log = (root / 'four-profiles.log').read_text()
        record('both required NDP responders started', all("Profile '" + m + "': session-aware IPv6 NDP proxy active" in log for m in ('manual', 'route')), log[-3000:])
        record('shared forwarding and RA ownership active', active['sysctls']['ipv6/conf/all/forwarding'] == '1' and active['sysctls']['ipv6/conf/wan0/accept_ra'] == '2')
        for i, m in enumerate(modes):
            for ipv6 in (False, True):
                for tcp in (False, True):
                    for qtype in (1, 28):
                        query(i, m, ipv6, tcp, qtype)
        record('DNS cache remains independent per profile', len(queries) == 8, queries)
        if mixed:
            mixed.reload(active['mixed_firewall'], 'active-firewalld-reload')
            mixed.policy_transition(active['mixed_firewall'])
            for i, m in enumerate(modes):
                query(i, 'post-firewalld-' + m, True, True, 1)
            record('firewalld policy changes preserve DNS cache', len(queries) == 8)
        cfg.write_text(text + 'tun.mtu = broken\n')
        worker.send_signal(signal.SIGHUP)
        until(lambda:"SIGHUP: refusing to apply" in (root / 'four-profiles.log').read_text())
        record('invalid reload preserves all active profiles', worker.poll() is None and all(run(['ip', 'link', 'show', f'qmx{i}'], False).returncode == 0 for i in range(4)))
        cfg.write_text(text)
        worker.send_signal(signal.SIGHUP)
        until(lambda:"SIGHUP: reloaded users database" in (root / 'four-profiles.log').read_text())
        record('valid reload preserves network generation', snapshot() == active)
        halt('four-profile-stop')
        if mixed:
            mixed.reload(before['mixed_firewall'], 'stopped-firewalld-reload')
            launch(text, 'four-profile-restart', list(enumerate(modes)))
            restarted = snapshot()
            record('four-profile restart restores ordered profile rules and foreign firewall', mixed.restart_equivalent(active['mixed_firewall'], restarted['mixed_firewall']))
            mixed.reload(restarted['mixed_firewall'], 'restarted-firewalld-reload')
            for i, m in enumerate(modes):
                query(i, 'restart-' + m, True, False, 28)
            halt('four-profile-restart-stop')
        launch(base + profile(1, 'manual'), 'manual-only', [(1, 'manual')])
        standalone = snapshot()
        record('manual required NDP preserves administrator forwarding and RA', standalone['sysctls']['ipv6/conf/all/forwarding'] == before['sysctls']['ipv6/conf/all/forwarding'] and standalone['sysctls']['ipv6/conf/wan0/accept_ra'] == before['sysctls']['ipv6/conf/wan0/accept_ra'])
        record('manual-only leaves IPv6 firewall unchanged', standalone['rules']['v6'] == before['rules']['v6'])
        for tcp in (False, True):
            query(1, 'manual-only', True, tcp, 1)
        halt('manual-stop')
        if args.transitions:
            for family in ('ipv4','dual','ipv6'):
                for mode in modes:
                    for ndp in ('off','auto','required'):
                        text=base+profile(0,mode).replace('tun.ip_mode = dual','tun.ip_mode = '+family).replace('dns.enabled = true','dns.enabled = false')
                        old_ndp='required' if mode in ('manual','route') else 'off'
                        text=text.replace('routing.ipv6.ndp_proxy = '+old_ndp,'routing.ipv6.ndp_proxy = '+ndp)
                        if family=='ipv6':text=text.replace('routing.nat.enabled = true','routing.nat.enabled = false')
                        (root/f'config-{family}-{mode}-{ndp}.ini').write_text(text)
                        cfg.write_text(text);cfg.chmod(0o600)
                        accepted=(family!='ipv4' and (ndp=='off' or mode in ('manual','route'))) or (family=='ipv4' and mode=='off' and ndp=='off')
                        result=run([str(binary),'check-config','-c',str(cfg)],check=False)
                        record(f'configuration {family}/{mode}/{ndp}',(result.returncode==0)==accepted,result.stdout+result.stderr if (result.returncode==0)!=accepted else None)
            for previous_mode in modes:
                for next_mode in modes:
                    # Routing changes require restart, not live SIGHUP. Keep one
                    # profile name, TUN, identity, listener and pool for every transition.
                    for step,mode in enumerate((previous_mode,next_mode)):
                        text=(base+profile(0,mode)).replace('[profile:'+mode+']','[profile:transition]').replace('/etc/qeli/'+mode+'.key','/etc/qeli/transition.key')
                        label=f'transition-{previous_mode}-{next_mode}-{step}'
                        launch(text,label,[(0,mode)])
                        active=snapshot();v6=active['rules']['v6']
                        if mode=='manual':ok=v6==before['rules']['v6'] and active['sysctls']['ipv6/conf/all/forwarding']==before['sysctls']['ipv6/conf/all/forwarding']
                        elif mode=='off':ok=sum('qeli-nat:transition' in line and 'FORWARD' in line and '-j DROP' in line for line in v6.splitlines())==2
                        elif mode=='route':ok='qeli-nat:transition' in v6 and 'MASQUERADE' not in v6 and active['sysctls']['ipv6/conf/all/forwarding']=='1'
                        else:ok='qeli-nat:transition' in v6 and 'MASQUERADE' in v6 and active['sysctls']['ipv6/conf/all/forwarding']=='1'
                        record(label+' mode boundary',ok)
                        halt(label)
        cfg.write_text(base + profile(1, 'manual', 'missing0'))
        previous_up = (root / 'up-manual').read_text()
        with (root / 'required-ndp-refusal.log').open('w') as log:
            worker = subprocess.Popen([str(binary), '_worker', '-c', str(cfg)], env=env, stdout=log, stderr=subprocess.STDOUT)
        # Profile setup errors are retried inside the worker. Required NDP means
        # no admission without the responder, not termination of every profile.
        until(lambda:"Profile 'manual' will restart" in (root / 'required-ndp-refusal.log').read_text())
        error_log = (root / 'required-ndp-refusal.log').read_text()
        record('required NDP failure refuses profile admission', 'required' in error_log and 'missing0' in error_log and (root / 'up-manual').read_text() == previous_up, error_log[-2500:])
        halt('required-ndp-refusal-stop')
        record('NDP refusal leaves no profile listener', ':25444' not in run(['ss', '-lnu']).stdout)
        completed = True
    finally:
        if worker is not None and worker.poll() is None:
            worker.kill()
            worker.wait(timeout=5)
        stop.set()
        thread.join(timeout=2)
        upstream.close()
        if mixed:
            mixed.close()
        (root / 'upstream-queries.json').write_text(json.dumps(queries, indent=2))
        (root / 'result.json').write_text(json.dumps(dict(status='PASS' if completed else 'FAIL', backend=args.backend, backends=mixed.backends if mixed else [args.backend,args.backend], artifact_sha256=args.sha256, check_count=len(results), checks=results), indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
