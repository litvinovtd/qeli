#!/usr/bin/env python3
"""Real client SIGKILL/rebuild failures in private Linux network/mount/PID namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time


def namespace(kind):
    stat = os.stat('/proc/thread-self/ns/' + kind)
    return f'{stat.st_dev}:{stat.st_ino}'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qeli', required=True)
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = Path(args.qeli).resolve(strict=True)
    root = Path(args.artifacts).resolve()
    if not args.inside:
        if os.geteuid() != 0:
            raise RuntimeError('requires root in a disposable Linux lab')
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_KS_PARENT_NET=namespace('net'), QELI_KS_PARENT_MNT=namespace('mnt'))
        return subprocess.run(['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL',
            '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--qeli', str(binary),
            '--artifacts', str(root), '--inside'], env=env, timeout=180).returncode
    if (not os.environ.get('QELI_KS_PARENT_NET') or namespace('net') == os.environ['QELI_KS_PARENT_NET']
            or namespace('mnt') == os.environ.get('QELI_KS_PARENT_MNT')):
        raise RuntimeError('fresh network/mount/PID namespaces are mandatory')
    commands, results, processes = [], [], []
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()

    def run(argv, check=True):
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        commands.append(dict(argv=argv, rc=p.returncode, output=p.stdout))
        (root/'commands.json').write_text(json.dumps(commands, indent=2))
        if check and p.returncode:
            raise RuntimeError(f'{argv}: {p.returncode}: {p.stdout}')
        return p

    def record(name, condition, detail=''):
        results.append(dict(name=name, passed=bool(condition), detail=detail))
        (root/'results.json').write_text(json.dumps(dict(artifact=str(binary), artifact_sha256=digest,
            network=namespace('net'), results=results), indent=2))
        if not condition:
            raise AssertionError(name + ': ' + str(detail))
        print(name, 'PASS', flush=True)

    def wait_for(predicate, seconds=25):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if predicate():
                return True
            time.sleep(.05)
        return False

    run(['mount', '--make-rprivate', '/'])
    for mountpoint in ['/run', '/var/lib', '/var/log']:
        run(['mount', '-t', 'tmpfs', 'tmpfs', mountpoint])
    for path in ['/var/lib/qeli', '/var/log/qeli']:
        Path(path).mkdir(mode=0o700)
    configdir = root/'etc-qeli'
    configdir.mkdir(mode=0o700)
    if not Path('/etc/qeli').is_dir():
        raise RuntimeError('existing /etc/qeli mount point required')
    run(['mount', '--bind', str(configdir), '/etc/qeli'])
    run(['ip', 'link', 'set', 'lo', 'up'])
    run(['ip', 'link', 'add', 'wan0', 'type', 'dummy'])
    run(['ip', 'link', 'set', 'wan0', 'up'])
    run(['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'wan0'])
    run(['ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'wan0', 'nodad'])
    for family in ['-4', '-6']:
        run(['ip', family, 'route', 'add', 'default', 'dev', 'wan0'])
    tun = 'qksaudit'
    chain = 'QELI_KS_' + tun
    comment = 'qeli-ks-rebuild:' + tun
    targets = ['203.0.113.9', '2001:db8:1::9']
    tools = [shutil.which(tool) for tool in ['iptables', 'ip6tables']]
    if not all(tools):
        raise RuntimeError('iptables and ip6tables required')
    for tool, address in zip(tools, targets):
        run([tool, '-N', 'OPERATOR_SENTINEL'])
        run([tool, '-A', 'OPERATOR_SENTINEL', '-j', 'RETURN'])
        run([tool, '-A', 'OUTPUT', '-p', 'udp', '-d', address, '--dport', '43889', '-m', 'comment',
             '--comment', 'audit-wan-sentinel', '-j', 'ACCEPT'])
    wrapper_dir = root/'wrappers'
    wrapper_dir.mkdir(mode=0o700)
    wrapper = r'''#!/usr/bin/python3
import os,signal,socket,subprocess,sys,time
from pathlib import Path
root=Path(ROOT_LITERAL)
args=sys.argv[1:]
mode=(root/'mode').read_text().strip() if (root/'mode').exists() else ''
with (root/'firewall-calls.log').open('a') as f:f.write(repr(sys.argv)+'\n')
if mode=='pause' and args==['-N','QELI_KS_qksaudit']:
 (root/'paused').write_text('ready')
 time.sleep(12)
if mode=='fail-drop' and os.path.basename(sys.argv[0])=='ip6tables' and args==['-A','QELI_KS_qksaudit','-j','DROP']:
 print('injected DROP failure',file=sys.stderr);code=1
else:
 code=subprocess.run([REAL_LITERAL,*args],timeout=10).returncode
if args and args[0] in ['-N','-A','-I','-D','-F','-X']:
 for family,local,target in [(socket.AF_INET,('0.0.0.0',0),('203.0.113.9',43889)),(socket.AF_INET6,('::',0),('2001:db8:1::9',43889))]:
  with socket.socket(family,socket.SOCK_DGRAM) as s:
   s.bind(local)
   try:s.sendto(b'restart-barrier',target)
   except OSError:pass
sys.exit(code)
'''
    for tool in tools:
        path = wrapper_dir/Path(tool).name
        path.write_text(wrapper.replace('ROOT_LITERAL', repr(str(root))).replace('REAL_LITERAL', repr(tool)))
        path.chmod(0o700)
    config = configdir/'client.conf'
    config.write_text(f"""[qeli]
server = 203.0.113.7:443
user = audit
pass = audit-fixture-only
proto = tcp
mode = fake-tls
roaming = off
dev = {tun}
gateway = true
kill_switch = true
dns = off
ipv6 = auto
allow_ipv4_leak = false
allow_ipv6_leak = false
timeout = 2
[logging]
level = info
""")
    config.chmod(0o600)

    def launch(name):
        env = dict(os.environ, QELI_IPT_DIR=str(wrapper_dir), QELI_KNOWN_HOSTS=str(root/'known-hosts'),
                   QELI_DEVICE_ID_FILE=str(root/'device-id'), STATE_DIRECTORY=str(root/'state'))
        with (root/(name+'.log')).open('w') as log:
            p = subprocess.Popen([str(binary), 'client', '-c', str(config)], env=env,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(p)
        return p

    def armed(name, process):
        return wait_for(lambda: 'Kill-switch ENGAGED' in (root/(name+'.log')).read_text() or process.poll() is not None) and process.poll() is None and 'Kill-switch ENGAGED' in (root/(name+'.log')).read_text()

    def stop(process, sig):
        if process.poll() is None:
            os.killpg(process.pid, sig)
            process.wait(timeout=15)

    def guard(tool):
        return run([tool, '-C', 'OUTPUT', '-m', 'comment', '--comment', comment, '-j', 'DROP'], False).returncode == 0

    def ordinary(tool):
        return all(run([tool, *args], False).returncode == 0 for args in
                   [['-C', 'OUTPUT', '-j', chain], ['-C', chain, '-j', 'DROP']])

    def counters():
        values = []
        for tool in tools:
            lines = [line for line in run([tool, '-n', '-v', '-x', '-L', 'OUTPUT']).stdout.splitlines()
                     if 'audit-wan-sentinel' in line]
            if len(lines) != 1:
                raise RuntimeError('missing or duplicate WAN sentinel')
            values.append(int(lines[0].split()[0]))
        return values

    try:
        first = launch('first')
        record('first client arms both families', armed('first', first) and all(ordinary(t) for t in tools), (root/'first.log').read_text()[-3000:])
        stop(first, signal.SIGKILL)
        record('SIGKILL leaves both ordinary chains armed', all(ordinary(t) for t in tools))
        before = counters()
        (root/'mode').write_text('fail-drop')
        failed = launch('failed')
        record('injected rebuild failure refuses startup', wait_for(lambda: failed.poll() is not None) and failed.returncode != 0, (root/'failed.log').read_text()[-3000:])
        after = counters()
        (root/'wan-counters.json').write_text(json.dumps(dict(before=before, after=after)))
        record('rebuild and rollback never expose WAN probes', before == after, dict(before=before, after=after))
        record('failed rebuild retains both recovery guards', all(guard(t) for t in tools))
        (root/'mode').write_text('pause')
        interrupted = launch('interrupted')
        record('retry reaches guarded chain creation', wait_for(lambda: (root/'paused').exists()) and all(guard(t) for t in tools))
        stop(interrupted, signal.SIGKILL)
        record('SIGKILL during rebuild preserves recovery guards', all(guard(t) for t in tools))
        (root/'mode').unlink()
        recovered = launch('recovered')
        record('second retry arms both ordinary chains', armed('recovered', recovered) and all(ordinary(t) for t in tools), (root/'recovered.log').read_text()[-3000:])
        record('successful retry retires all temporary guards', all(not guard(t) for t in tools))
        record('all crash recovery probes remained blocked', counters() == before, dict(before=before, after=counters()))
        stop(recovered, signal.SIGTERM)
        record('clean stop exits successfully', recovered.returncode == 0, recovered.returncode)
        record('clean stop removes ordinary chains and guards', all(not guard(t) and run([t, '-S', chain],False).returncode != 0 for t in tools))
        record('operator rules survive recovery and stop', all(run([t, '-C', 'OPERATOR_SENTINEL', '-j', 'RETURN'],False).returncode == 0 for t in tools))
        prior = counters()
        for family, target in [(socket.AF_INET, ('203.0.113.9',43889)), (socket.AF_INET6, ('2001:db8:1::9',43889))]:
            with socket.socket(family,socket.SOCK_DGRAM) as s:
                s.sendto(b'clean-stop',target)
        record('clean stop restores direct egress', all(x > y for x,y in zip(counters(),prior)))
        return 0
    finally:
        for process in processes:
            if process.poll() is None:
                stop(process, signal.SIGKILL)


if __name__ == '__main__':
    sys.exit(main())
