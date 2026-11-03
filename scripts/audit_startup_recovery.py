#!/usr/bin/env python3
"""Verify joined startup recovery on a current-thread client in private Linux namespaces.

Requires root in a disposable lab. Holds the real route journal flock, sends SIGTERM,
checks executor liveness, competing namespace claims, retained errors and resources.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import time

CASES = ['clean-open', 'clean-protected', 'route-error', 'dns-error', 'deadline', 'attach-dns']


def namespace(kind):
    return os.readlink('/proc/self/ns/' + kind)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--driver', required=True, type=Path)
    ap.add_argument('--baseline-driver', required=True, type=Path)
    ap.add_argument('--artifacts', required=True, type=Path)
    ap.add_argument('--inside', choices=CASES, help=argparse.SUPPRESS)
    ap.add_argument('--version', choices=['baseline', 'fixed'], default='fixed', help=argparse.SUPPRESS)
    args = ap.parse_args()
    root = args.artifacts.resolve()
    if not args.inside:
        assert os.geteuid() == 0, 'requires root in a disposable Linux lab'
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_SR_HOST_NET=namespace('net'), QELI_SR_HOST_MNT=namespace('mnt'))
        rows = []
        for version, case in [('baseline', c) for c in CASES[:2]] + [('fixed', c) for c in CASES]:
            work = root / (version + '-' + case)
            work.mkdir(mode=0o700)
            cmd = ['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                   sys.executable, str(Path(__file__).resolve()), '--driver', str(args.driver.resolve(strict=True)),
                   '--baseline-driver', str(args.baseline_driver.resolve(strict=True)), '--version', version,
                   '--artifacts', str(work), '--inside', case]
            with (work / 'fixture.log').open('w') as log:
                proc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=55)
            report = work / 'result.json'
            rows.append(dict(version=version, case=case, exit_code=proc.returncode,
                             result=json.loads(report.read_text()) if report.exists() else None))
            (root / 'results.json').write_text(json.dumps(rows, indent=2))
            print(version, case, proc.returncode, flush=True)
        assert len(rows) == 8 and all(r['exit_code'] == 0 for r in rows), rows
        return
    assert os.environ.get('QELI_SR_HOST_NET') and namespace('net') != os.environ['QELI_SR_HOST_NET']
    assert namespace('mnt') != os.environ['QELI_SR_HOST_MNT']
    # Resolve alternatives before replacing /etc. Preserve argv[0] dispatch for
    # xtables multi-call binaries by copying them under the ordinary tool names.
    tools = root / 'tools'
    tools.mkdir(mode=0o700)
    for tool in ['iptables', 'ip6tables']:
        shutil.copy2(Path(shutil.which(tool)).resolve(strict=True), tools / tool)
    commands = []

    def run(argv):
        argv = [tools / argv[0], *argv[1:]] if argv[0] in ['iptables', 'ip6tables'] else argv
        p = subprocess.run(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        commands.append(dict(argv=list(map(str, argv)), rc=p.returncode, output=p.stdout))
        (root / 'commands.json').write_text(json.dumps(commands, indent=2))
        assert p.returncode == 0, p.stdout
        return p.stdout

    run(['mount', '--make-rprivate', '/'])
    for name, target in [('etc', '/etc'), ('state', '/var/lib'), ('run', '/run'), ('log', '/var/log'), ('tmp', '/tmp')]:
        source = root / name
        source.mkdir(mode=0o700)
        run(['mount', '--bind', source, target])
    state = Path('/var/lib/qeli')
    state.mkdir(mode=0o700)
    Path('/etc/qeli').mkdir(mode=0o700)
    resolver = Path('/etc/resolv.conf')
    resolver.write_text('# operator resolver\nnameserver 192.0.2.53\n')
    run(['ip', 'link', 'set', 'lo', 'up'])
    for tool in ['iptables', 'ip6tables']:
        run([tool, '-N', 'OPERATOR_SENTINEL'])
        run([tool, '-A', 'OPERATOR_SENTINEL', '-j', 'RETURN'])
        run([tool, '-A', 'OUTPUT', '-j', 'OPERATOR_SENTINEL'])

    def snapshot(name):
        value = dict(routes=[run(['ip', f, 'route', 'show', 'table', 'all']) for f in ['-4', '-6']],
                     rules=[run([t, '-S']) for t in ['iptables', 'ip6tables']],
                     links=[(l['ifindex'], l['ifname']) for l in json.loads(run(['ip', '-j', 'link']))],
                     resolver=digest(resolver))
        (root / (name + '.json')).write_text(json.dumps(value, indent=2))
        return value

    protected = args.inside == 'clean-protected'
    attach = args.inside == 'attach-dns'
    journal = state / 'client-routes.state'
    backup = state / 'dns-backup.json'
    if args.inside in ['route-error', 'attach-dns']:
        journal.write_bytes(b'{invalid-route-journal')
        journal.chmod(0o600)
    if args.inside in ['dns-error', 'attach-dns']:
        backup.write_bytes(b'legacy-evidence-must-survive')
        backup.chmod(0o600)
    markers = {}
    busy_lock = None
    if args.inside.startswith('clean-'):
        info = os.stat('/proc/self/ns/net')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as scope_socket:
            cookie = int.from_bytes(scope_socket.getsockopt(socket.SOL_SOCKET, 71, 8), sys.byteorder)
        scope = dict(boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                     device=info.st_dev, inode=info.st_ino, network_cookie=cookie)
        for kind, index in [('stale', 2147483647), ('busy', 2147483646), ('foreign', 2147483645), ('live', 1)]:
            owner = dict(scope, network_cookie=cookie + 1) if kind == 'foreign' else scope
            marker = state / ('dns-link-v2-' + '-'.join(str(owner[k]) for k in ['boot', 'device', 'inode', 'network_cookie']) + f'-{index}.state')
            marker.write_text(json.dumps(dict(version=2, token='0' * 32, link=dict(scope=owner, index=index, name='lo' if kind == 'live' else 'gone0'))))
            marker.chmod(0o600)
            markers[kind] = marker
            if kind == 'busy':
                busy_lock = marker.with_suffix('.lock').open('w')
                marker.with_suffix('.lock').chmod(0o600)
                fcntl.flock(busy_lock, fcntl.LOCK_EX)
        markers['legacy'] = state / 'dns-link-v1-retained.state'
        markers['legacy'].write_text('legacy marker evidence')
        markers['legacy'].chmod(0o600)
    markers_before = {kind: digest(path) for kind, path in markers.items()}
    evidence_before = dict(journal=digest(journal), backup=digest(backup))
    lock = state / 'client-routes.state.lock'
    held = lock.open('w')
    lock.chmod(0o600)
    fcntl.flock(held, fcntl.LOCK_EX)
    config = root / 'client.ini'
    config.write_text('[qeli]\nserver = 127.0.0.1:24443\nproto = udp\nuser = audit\npass = fixture-password\n'
                      f'mode = fake-tls\ndev = qrecover0\ndns = off\nkill_switch = {str(protected).lower()}\n'
                      f'dev_attach = {str(attach).lower()}\ntimeout = 2\n')
    config.chmod(0o600)
    driver = (args.baseline_driver if args.version == 'baseline' else args.driver).resolve(strict=True)
    status = root / 'status.json'
    beat = root / 'heartbeat'
    env = dict(os.environ, QELI_IPT_DIR=str(tools), STATE_DIRECTORY=str(root / 'run'), QELI_CLIENT_STATUS=str(status),
               QELI_KNOWN_HOSTS=str(root / 'known-hosts'), QELI_DEVICE_ID_FILE=str(root / 'device-id'))
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(('127.0.0.1', 24443))
    receiver.setblocking(False)
    before = snapshot('before')
    started = time.monotonic()
    process = None
    try:
        with (root / 'client.log').open('w') as log:
            process = subprocess.Popen([str(driver), str(config), str(beat)], env=env, stdout=log, stderr=subprocess.STDOUT)
            work_ticks = stop_ticks = None
            contender = None
            held_after_stop = None
            if not attach:
                until = time.monotonic() + 5
                while '@qeli.client.routes:qrecover0' not in Path('/proc/net/unix').read_text():
                    assert process.poll() is None, (root / 'client.log').read_text()
                    assert time.monotonic() < until, 'route claim did not appear'
                    time.sleep(.02)

                def ticks():
                    try:
                        return int(beat.read_text())
                    except (FileNotFoundError, ValueError):
                        return 0

                count = ticks()
                time.sleep(.8)
                work_ticks = ticks() - count
                process.send_signal(signal.SIGTERM)
                count = ticks()
                time.sleep(.8)
                stop_ticks = ticks() - count
                held_after_stop = process.poll() is None
                competitor_config = root / 'competitor.ini'
                competitor_config.write_text(config.read_text().replace('qrecover0', 'qrecover1') if protected else config.read_text())
                competitor_config.chmod(0o600)
                competitor_env = dict(env, QELI_CLIENT_STATUS=str(root / 'competitor-status.json'))
                competitor = subprocess.run([str(driver), str(competitor_config), str(root / 'competitor-beat')],
                                            env=competitor_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
                (root / 'competitor.log').write_text(competitor.stdout)
                contender = dict(exit_code=competitor.returncode, error=competitor.stdout)
                assert competitor.returncode == 1
                assert ('cannot exclusively own' if protected else 'cannot reserve TUN') in competitor.stdout
                assert held_after_stop
                if args.version == 'baseline':
                    assert work_ticks <= 1 and stop_ticks <= 1, (work_ticks, stop_ticks)
                else:
                    assert work_ticks >= 5 and stop_ticks >= 5, (work_ticks, stop_ticks)
                if args.inside != 'deadline':
                    held.close()
            rc = process.wait(timeout=22)
        seconds = time.monotonic() - started
        log = (root / 'client.log').read_text()
        final_status = json.loads(status.read_text())
        clean = args.inside.startswith('clean-')
        assert rc == (0 if clean else 1), log
        assert final_status['state'] == ('stopped' if clean else 'failed'), final_status
        if args.inside in ['dns-error', 'attach-dns']:
            assert 'legacy global DNS state' in log and 'administrator recovery' in log, log
        if args.inside == 'deadline':
            assert ('timed out' in log or 'deadline' in log) and 'lock' in log, log
            assert 14 <= seconds < 20, seconds
        if attach:
            assert seconds < 3, seconds
        if evidence_before['journal']:
            assert digest(journal) == evidence_before['journal']
        assert digest(backup) == evidence_before['backup']
        markers_after = {kind: digest(path) for kind, path in markers.items()}
        if markers:
            assert markers_after['stale'] is None
            assert all(markers_after[k] == markers_before[k] for k in ['busy', 'foreign', 'live', 'legacy'])
        packets = 0
        while True:
            try:
                receiver.recvfrom(65536)
                packets += 1
            except BlockingIOError:
                break
        if args.version == 'fixed':
            assert packets == 0, 'stopped/failed recovery must not dial'
        for name in ['qeli.client.tun:qrecover0', 'qeli.client.kill-switch']:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as claim:
                claim.bind('\0' + name)
        after = snapshot('after')
        assert before == after
        result = dict(case=args.inside, version=args.version, sha256=digest(driver), work_ticks=work_ticks,
                      stop_ticks=stop_ticks, held_after_stop=held_after_stop, competitor=contender, exit_code=rc,
                      status=final_status, seconds=round(seconds, 3), packets=packets, clean=True,
                      markers_before=markers_before, markers_after=markers_after,
                      evidence_before=evidence_before, evidence_after=dict(journal=digest(journal), backup=digest(backup)))
        (root / 'result.json').write_text(json.dumps(result, indent=2))
    finally:
        held.close()
        if busy_lock:
            busy_lock.close()
        receiver.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=3)


if __name__ == '__main__':
    main()
