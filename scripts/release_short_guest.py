#!/usr/bin/env python3
"""Metadata-only helper for release_short_test.py; run ONLY inside test guests."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(args, timeout=30, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=check)


def save(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def identity(pid):
    p = Path('/proc') / str(pid)
    fields = (p / 'stat').read_text().rsplit(')', 1)[1].split()
    return str((p / 'exe').resolve()), fields[19], fields[0]


def spawn(root, label, args, env=None):
    require(re.fullmatch(r'[a-zA-Z0-9_-]+', label), 'unsafe process label')
    receipt = root / 'owned' / (label + '.json')
    require(not receipt.exists(), 'existing owned process receipt')
    command = shutil.which(str(args[0]), path=os.pathsep.join(os.get_exec_path(env)))
    require(command is not None, 'child executable not found')
    expected_exe = str(Path(command).resolve(strict=True))
    with (root / (label + '.log')).open('xb') as log:
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                             start_new_session=True, env=env)
    try:
        exe, start, state = identity(p.pid)
    except FileNotFoundError:
        raise RuntimeError('child exited before identity receipt')
    # /proc/<pid>/exe can briefly retain the launching interpreter during exec.
    # Keep the intended executable
    # and original start time; never adopt a different PID or relax halt's checks.
    save(receipt, dict(pid=p.pid, exe=expected_exe, start=start, launching=True))
    deadline = time.monotonic() + 5
    current_start = start
    while True:
        require(current_start == start, 'PID reused during spawn; refuse adoption')
        require(state != 'Z' and p.poll() is None, 'child exited during startup')
        if exe == expected_exe:
            require(os.getpgid(p.pid) == p.pid, 'child process group changed')
            save(receipt, dict(pid=p.pid, exe=exe, start=start))
            return p.pid
        require(time.monotonic() < deadline, 'child executable did not settle; receipt retained')
        time.sleep(.01)
        exe, current_start, state = identity(p.pid)


def halt(root):
    for receipt in (root / 'owned').glob('*.json'):
        row = json.loads(receipt.read_text())
        try:
            exe, start, state = identity(row['pid'])
            require(start == row['start'], 'PID reused; refuse signal')
            if state != 'Z':
                require(exe == row['exe'] and os.getpgid(row['pid']) == row['pid'], 'process ownership changed')
                os.killpg(row['pid'], signal.SIGTERM)
                for _ in range(60):
                    try:
                        if identity(row['pid'])[2] == 'Z':
                            break
                    except FileNotFoundError:
                        break
                    time.sleep(.1)
                else:
                    os.killpg(row['pid'], signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError):
            pass
        receipt.unlink()


def processes(root=None):
    rows = {}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            exe, start, state = identity(int(p.name))
            if state == 'Z':
                continue
            name = Path(exe).name
            selected = (exe.startswith(str(root) + '/') if root else
                        name.startswith(('qeli', 'iperf3', 'rustc', 'cargo', 'qemu-system', 'emulator', 'adb')))
            if not selected:
                continue
            f = (p / 'stat').read_text().rsplit(')', 1)[1].split()
            status = dict(l.split(':', 1) for l in (p / 'status').read_text().splitlines())
            rows[p.name] = dict(exe=exe, start=start, ticks=int(f[11])+int(f[12]),
                                rss_kib=int(status.get('VmRSS', '0 kB').split()[0]))
        except (OSError, KeyError, ValueError):
            continue
    return rows


def snapshot(root):
    commands = dict(links=['ip', '-j', 'link'], addresses=['ip', '-j', 'addr'],
                    routes4=['ip', '-4', '-j', 'route', 'show', 'table', 'all'],
                    routes6=['ip', '-6', '-j', 'route', 'show', 'table', 'all'],
                    rules4=['ip', '-4', '-j', 'rule'], rules6=['ip', '-6', '-j', 'rule'],
                    qdiscs=['tc', '-j', 'qdisc', 'show'], iptables=['iptables-save'],
                    ip6tables=['ip6tables-save'], sysctls=['sysctl', 'net.ipv4.ip_forward',
                    'net.ipv6.conf.all.forwarding', 'net.ipv6.conf.all.accept_ra',
                    'net.ipv6.conf.default.accept_ra', 'net.ipv4.conf.all.rp_filter',
                    'net.core.rmem_max', 'net.core.wmem_max', 'net.core.netdev_max_backlog'])
    hashes = {}
    for path in Path('/opt').glob('qeli-*/**/*'):
        if path.is_file() and not path.is_relative_to(root):
            hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(hostname=Path('/etc/hostname').read_text().strip(), kernel=os.uname().release,
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                cpus=os.cpu_count(), processes=processes(), protected_files=hashes,
                **{k: run(v).stdout for k, v in commands.items()})


def sample(root, iface):
    link = run(['ip', '-s', '-j', 'link', 'show', 'dev', iface]).stdout
    return dict(t=time.monotonic(), processes=processes(root),
                cpu=[int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]],
                link=json.loads(link)[0], snmp=Path('/proc/net/snmp').read_text(),
                snmp6=Path('/proc/net/snmp6').read_text(),
                softnet=Path('/proc/net/softnet_stat').read_text(),
                qdisc=json.loads(run(['tc', '-s', '-j', 'qdisc', 'show', 'dev', iface]).stdout))


def observe(root, label, iface, seconds):
    folder = root / 'windows' / label
    samples = []
    (folder / 'ready').touch()
    end = time.monotonic() + seconds
    while not (folder / 'stop').exists() and time.monotonic() < end:
        started = time.monotonic()
        s = sample(root, iface)
        # Only known test data/carrier ports; SSH/management sockets excluded.
        s['ss'] = run(['ss', '-tinmeH', 'state', 'established',
                       '( sport = :5201 or dport = :5201 or sport = :5202 or dport = :5202 or sport = :443 or dport = :443 )']).stdout
        samples.append(s)
        time.sleep(max(0, .5-(time.monotonic()-started)))
    require((folder / 'stop').exists(), 'observer reached bounded deadline')
    save(folder / 'observations.json', dict(status='complete', clock_ticks=os.sysconf('SC_CLK_TCK'),
                                          samples=samples))


def owned_run(root, folder, label, command, timeout):
    """Register the traffic generator so controller cancellation can stop it too."""
    p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        exe,start,_=identity(p.pid)
        row=dict(pid=p.pid,exe=exe,start=start)
        save(root/'owned'/('measure-'+label+'.json'),row)
        save(folder/'process.json',row)
    except BaseException:
        try:
            os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        raise
    try:
        stdout,stderr=p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout,stderr=p.communicate()
        (folder/'iperf-timeout.stdout').write_text(stdout)
        (folder/'iperf-timeout.stderr').write_text(stderr)
        raise
    return subprocess.CompletedProcess(command,p.returncode,stdout,stderr)


def measure(root, spec):
    folder = root / 'windows' / spec['label']
    command = ['iperf3', '-'+str(spec['family']), '-c', spec['target'], '-p', str(spec['port']),
               '-t', str(spec['seconds']), '-O', str(spec['omit']), '-J', '--get-server-output']
    if spec['protocol'] == 'TCP':
        command += ['-P', str(spec['streams'])]
    else:
        command += ['-u', '-b', str(spec['rate_mbps'])+'M', '-l', '1200']
    if spec['direction'] == 'download':
        command += ['-R']
    started = time.time_ns()
    p = owned_run(root,folder,spec['label'],command,spec['seconds']+spec['omit']+25)
    (folder / 'iperf.json').write_text(p.stdout)
    (folder / 'iperf.stderr').write_text(p.stderr)
    data = json.loads(p.stdout)
    require(p.returncode == 0 and not data.get('error'), 'iperf window failed')
    test = data['start']['test_start']
    require(test['protocol'] == spec['protocol'] and test['num_streams'] == spec['streams'], 'unexpected iperf test')
    require(test['duration'] == spec['seconds'] and test['omit'] == spec['omit'], 'duration mismatch')
    received, sent = data['end']['sum_received'], data['end']['sum_sent']
    require(math.isfinite(received['seconds']) and math.isfinite(received['bits_per_second'])
            and received['seconds'] >= spec['seconds']*.9 and received['bits_per_second'] > 0, 'incomplete traffic')
    if spec['protocol']=='UDP':
        require(math.isfinite(received['lost_percent']) and 0<=received['lost_percent']<=100
                and math.isfinite(received['jitter_ms']) and received['jitter_ms']>=0,'invalid UDP statistics')
    require(len(data['start']['connected'])==spec['streams'],'missing iperf streams')
    require(all(s['remote_host'] == spec['target'] and s['remote_port'] == spec['port']
                for s in data['start']['connected']), 'endpoint mismatch')
    value = dict(**spec, started_ns=started, finished_ns=time.time_ns(), command=command,
                 cookie=data['start']['cookie'], mbps=received['bits_per_second']/1e6,
                 retransmits=sent.get('retransmits'), loss_percent=received.get('lost_percent'),
                 jitter_ms=received.get('jitter_ms'))
    save(folder / 'measurement.json', value)
    return value


def mixed(root, spec):
    specs=[]
    for protocol,direction,port,streams in (('TCP','download',5201,4),('UDP','upload',5202,1)):
        item=dict(spec,protocol=protocol,direction=direction,port=port,streams=streams,
                  label=spec['label']+'-'+protocol.lower())
        (root/'windows'/item['label']).mkdir()
        specs.append(item)
    with ThreadPoolExecutor(max_workers=2) as pool:
        rows=list(pool.map(lambda s:measure(root,s),specs))
    overlap=min(r['finished_ns'] for r in rows)-max(r['started_ns'] for r in rows)
    require(overlap/1e9>=spec['seconds']*.9,'mixed windows did not overlap')
    return dict(**spec,results=rows,overlap_seconds=overlap/1e9)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root')
    parser.add_argument('action', choices=['snapshot', 'halt', 'launch', 'listen', 'watch-start', 'watch', 'watch-stop', 'measure', 'measure-mixed'])
    parser.add_argument('args', nargs='*')
    opts = parser.parse_args()
    root = Path(opts.root)
    require(root.parent == Path('/opt') and root.name.startswith('qeli-release-short-'), 'unsafe raw root')
    os.umask(0o077)
    result = {}
    if opts.action == 'snapshot':
        result = snapshot(root)
    elif opts.action == 'halt':
        halt(root)
    elif opts.action == 'launch':
        role, label = opts.args
        env = dict(os.environ, STATE_DIRECTORY=str(root/'state'), QELI_CONTROL_SOCKET=str(root/'control.sock'),
                   QELI_DEVICE_ID_FILE=str(root/'state'/'device-id'))
        result = dict(pid=spawn(root, label, [str(root/('qeli-'+role)), role, '--config', str(root/(role+'.conf'))], env))
    elif opts.action == 'listen':
        label, family, target, port = opts.args
        result = dict(pid=spawn(root, label, ['iperf3', '-s', '-1', '-'+family, '-B', target, '-p', port]))
    elif opts.action == 'watch-start':
        label, iface, seconds = opts.args
        (root/'windows'/label).mkdir(exist_ok=True)
        result = dict(pid=spawn(root, 'watch-'+label, ['python3', __file__, str(root), 'watch', label, iface, seconds]))
    elif opts.action == 'watch':
        label, iface, seconds = opts.args
        observe(root, label, iface, float(seconds))
    elif opts.action == 'watch-stop':
        folder = root/'windows'/opts.args[0]
        (folder/'stop').touch()
        for _ in range(60):
            if (folder/'observations.json').exists():
                result = dict(status='complete', samples=len(json.loads((folder/'observations.json').read_text())['samples']))
                break
            time.sleep(.1)
        else:
            raise RuntimeError('observer failed: inspect retained log')
    elif opts.action == 'measure':
        result = measure(root, json.loads(opts.args[0]))
    elif opts.action == 'measure-mixed':
        result = mixed(root,json.loads(opts.args[0]))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
