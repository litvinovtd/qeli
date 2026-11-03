#!/usr/bin/env python3
"""Isolated two-profile worker stop, resource churn, crash, and recovery check."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def namespace(kind):
    stat = os.stat('/proc/self/ns/' + kind)
    return f'{stat.st_dev}:{stat.st_ino}'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--qeli', required=True)
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = Path(args.qeli).resolve(strict=True)
    root = Path(args.artifacts).resolve()
    if not args.inside:
        if os.geteuid() != 0:
            raise RuntimeError('requires root in disposable Linux lab')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_AUDIT_PARENT_NET=namespace('net'),
                   QELI_AUDIT_PARENT_MNT=namespace('mnt'))
        cmd = ['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL',
               '--mount-proc', sys.executable, str(Path(__file__).resolve()),
               '--qeli', str(binary), '--artifacts', str(root), '--inside']
        return subprocess.run(cmd, env=env, timeout=180).returncode
    if (namespace('net') == os.environ.get('QELI_AUDIT_PARENT_NET') or
            namespace('mnt') == os.environ.get('QELI_AUDIT_PARENT_MNT') or
            not os.environ.get('QELI_AUDIT_PARENT_NET')):
        raise RuntimeError('fresh network and mount namespaces are mandatory')

    results = []
    commands = []
    sha = hashlib.sha256(binary.read_bytes()).hexdigest()

    def run(argv, check=True):
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=20)
        commands.append(dict(argv=argv, rc=proc.returncode, output=proc.stdout))
        (root / 'commands.json').write_text(json.dumps(commands, indent=2))
        if check and proc.returncode:
            raise RuntimeError(f'{argv}: {proc.returncode}: {proc.stdout}')
        return proc

    def record(name, ok, detail=''):
        results.append(dict(name=name, passed=bool(ok), detail=detail))
        (root / 'results.json').write_text(json.dumps(dict(
            artifact_sha256=sha, network=namespace('net'), results=results), indent=2))
        if not ok:
            raise AssertionError(name + ': ' + detail)
        print(name, 'PASS', flush=True)

    def wait_for(predicate, seconds=25):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(.1)
        return False

    def snapshot():
        def rules(tool):
            return [line for line in run([tool]).stdout.splitlines()
                    if line.startswith('-A ') or (line.startswith(':') and ' - ' in line)]
        return dict(firewall4=rules('iptables-save'), firewall6=rules('ip6tables-save'),
                    routes4=run(['ip', '-4', 'route', 'show', 'table', 'all']).stdout,
                    routes6=run(['ip', '-6', 'route', 'show', 'table', 'all']).stdout,
                    links=sorted(item['ifname'] for item in json.loads(run(['ip', '-j', 'link']).stdout)),
                    forwarding4=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip())

    def resources(pid):
        proc = Path('/proc') / str(pid)
        fds = list((proc / 'fd').iterdir())
        socket_fd = 0
        for fd in fds:
            try:
                socket_fd += os.readlink(fd).startswith('socket:[')
            except FileNotFoundError:
                pass
        rss = next(line for line in (proc / 'status').read_text().splitlines()
                   if line.startswith('VmRSS:'))
        return dict(fd=len(fds), socket_fd=socket_fd,
                    tasks=len(list((proc / 'task').iterdir())), rss_kib=int(rss.split()[1]))

    run(['mount', '--make-rprivate', '/'])
    for mountpoint in ['/run', '/var/lib', '/var/log']:
        run(['mount', '-t', 'tmpfs', 'tmpfs', mountpoint])
    for path in ['/var/lib/qeli', '/var/log/qeli']:
        Path(path).mkdir(mode=0o700)
    configdir = root / 'etc-qeli'
    configdir.mkdir(mode=0o700)
    if not Path('/etc/qeli').is_dir():
        raise RuntimeError('existing /etc/qeli mount point required')
    run(['mount', '--bind', str(configdir), '/etc/qeli'])
    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['ip', 'link', 'add', 'wan0', 'type', 'dummy'])
    run(['ip', 'link', 'set', 'wan0', 'up'])
    run(['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'wan0'])
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0')
    (configdir / 'users.conf').write_text('')
    state = root / 'state'
    state.mkdir(mode=0o700)
    runtime = root / 'run'
    runtime.mkdir(mode=0o700)
    cfg = configdir / 'server.conf'

    def profile(name, number, transport):
        return f'''[profile:{name}]
identity_key = /etc/qeli/{name}.key
bind.address = 127.0.0.1
bind.port = {24443 + number}
bind.transport = {transport}
tun.name = qmulti{number}
tun.address = 10.{74 + number}.0.1
tun.ip_mode = ipv4
tun.queues = 1
pool.cidr = 10.{74 + number}.0.0/24
routing.nat.enabled = true
routing.nat.interface = wan0
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = printf up >> {root / (name + '-up')}
routing.post_down = printf down >> {root / (name + '-down')}
dns.enabled = true
dns.listen = 10.{74 + number}.0.1
dns.port = 1053
obf.mode = fake-tls
'''

    base = '[auth]\nusers_file = /etc/qeli/users.conf\n[web]\nenabled = false\n[logging]\nlevel = info\n'
    both = base + profile('alpha', 0, 'tcp') + profile('beta', 1, 'udp')
    cfg.write_text(both)
    cfg.chmod(0o600)
    run([str(binary), 'check-config', '-c', str(cfg)])
    before = snapshot()
    (root / 'network-before.json').write_text(json.dumps(before, indent=2))
    env = dict(os.environ, STATE_DIRECTORY=str(state),
               QELI_CONTROL_SOCKET=str(runtime / 'control.sock'))

    def launch(log_name):
        with (root / log_name).open('w') as log:
            return subprocess.Popen([str(binary), '_worker', '-c', str(cfg)],
                                    env=env, stdout=log, stderr=subprocess.STDOUT)

    def ready(worker, names, min_up=1):
        return (worker.poll() is None and
                all((root / (name + '-up')).exists() and
                    len((root / (name + '-up')).read_text()) >= 2 * min_up and
                    run(['ip', 'link', 'show', 'qmulti' + str(number)], False).returncode == 0
                    for name, number in names))

    def owned(snap):
        return '\n'.join(snap['firewall4'] + snap['firewall6'])

    worker = None
    try:
        worker = launch('worker-two.log')
        record('two TCP/UDP profiles ready',
               wait_for(lambda: ready(worker, [('alpha', 0), ('beta', 1)])),
               (root / 'worker-two.log').read_text()[-4000:])
        active = snapshot()
        (root / 'network-two-active.json').write_text(json.dumps(active, indent=2))
        record('two profiles own rules and shared forwarding',
               all('qeli-nat:' + name in owned(active) for name in ('alpha', 'beta')) and
               active['forwarding4'] == '1')
        record('two listeners and control socket active',
               ':24443' in run(['ss', '-lnt']).stdout and
               ':24444' in run(['ss', '-lnu']).stdout and
               (runtime / 'control.sock').exists())
        cfg.write_text(both + 'tun.mtu = broken\n')
        worker.send_signal(signal.SIGHUP)
        time.sleep(.5)
        record('invalid reload preserves both profiles',
               ready(worker, [('alpha', 0), ('beta', 1)]) and
               run([str(binary), 'list-clients', '--socket',
                    str(runtime / 'control.sock')], False).returncode == 0)
        cfg.write_text(both)
        samples = [resources(worker.pid)]
        for _ in range(10):
            worker.send_signal(signal.SIGHUP)
            time.sleep(.4)
            if not ready(worker, [('alpha', 0), ('beta', 1)]):
                raise AssertionError('profile disappeared during valid reload')
            samples.append(resources(worker.pid))
        (root / 'resource-samples.json').write_text(json.dumps(samples, indent=2))
        first, last = samples[0], samples[-1]
        peak = max(sample['rss_kib'] for sample in samples)
        record('ten reloads retain fd/socket/tasks/RSS budget',
               all(last[key] <= first[key] + 2 for key in ('fd', 'socket_fd', 'tasks')) and
               peak - first['rss_kib'] <= 32768,
               f'first={first}, last={last}, peak_rss_kib={peak}')
        worker.send_signal(signal.SIGTERM)
        record('two-profile graceful stop exits cleanly', worker.wait(timeout=25) == 0)
        worker = None
        record('both post-down hooks ran once',
               all((root / (name + '-down')).read_text() == 'down'
                   for name in ('alpha', 'beta')))
        stopped = snapshot()
        (root / 'network-after-stop.json').write_text(json.dumps(stopped, indent=2))
        record('shared network state restored after stop',
               stopped == before and not (runtime / 'control.sock').exists() and
               not (state / 'sysctls.state').exists())

        worker = launch('worker-crash.log')
        record('both profiles restart for crash test',
               wait_for(lambda: ready(worker, [('alpha', 0), ('beta', 1)], 2)),
               (root / 'worker-crash.log').read_text()[-4000:])
        worker.kill()
        worker.wait(timeout=5)
        worker = None
        crashed = snapshot()
        (root / 'network-after-crash.json').write_text(json.dumps(crashed, indent=2))
        record('crash leaves recoverable journal and both orphan rules',
               (state / 'sysctls.state').exists() and
               all('qeli-nat:' + name in owned(crashed) for name in ('alpha', 'beta')))
        cfg.write_text(base + profile('alpha', 0, 'tcp'))
        run([str(binary), 'check-config', '-c', str(cfg)])
        worker = launch('worker-recover.log')
        record('remaining profile recovers after sibling removal',
               wait_for(lambda: ready(worker, [('alpha', 0)], 3)),
               (root / 'worker-recover.log').read_text()[-4000:])
        recovered = snapshot()
        (root / 'network-recovered.json').write_text(json.dumps(recovered, indent=2))
        record('recovery removes deleted sibling resources',
               'qeli-nat:alpha' in owned(recovered) and
               'qeli-nat:beta' not in owned(recovered) and
               run(['ip', 'link', 'show', 'qmulti1'], False).returncode != 0)
        worker.send_signal(signal.SIGTERM)
        record('recovered profile stops cleanly', worker.wait(timeout=25) == 0)
        worker = None
        final = snapshot()
        (root / 'network-final.json').write_text(json.dumps(final, indent=2))
        record('final network/control/journal restored',
               final == before and not (runtime / 'control.sock').exists() and
               not (state / 'sysctls.state').exists())
    finally:
        if worker is not None and worker.poll() is None:
            worker.kill()
            worker.wait(timeout=5)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
