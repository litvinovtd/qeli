#!/usr/bin/env python3
"""Check Linux client startup I/O with signals in private namespaces.

The driver takes CONFIG HEARTBEAT, runs client::run_client on a current-thread
Tokio runtime, increments HEARTBEAT every 100 ms, and returns 1 on client errors.
Compile audit_client_startup_shim.c with gcc -shared -fPIC -ldl. Use --version
baseline only with a pre-fix driver. Requires root in a disposable Linux lab.
"""
import argparse
import os
import sys
import json
import signal
import time
import subprocess
import hashlib
from pathlib import Path

def ns(kind):
    info = os.stat('/proc/self/ns/' + kind)
    return f'{info.st_dev}:{info.st_ino}'

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--shim', type=Path, required=True)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--version', choices=['baseline', 'fixed'], default='fixed')
    parser.add_argument('--inside', choices=['stop', 'fault', 'oversize'], help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside:
        assert os.geteuid() == 0, 'requires root in a disposable lab'
        root = args.artifacts.resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_NT_HOST_NET=ns('net'), QELI_NT_HOST_MNT=ns('mnt'))
        rows = []
        for case in ['stop', 'fault', 'oversize']:
            work = root / case
            work.mkdir(mode=0o700)
            cmd = ['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--driver', str(args.driver.resolve(strict=True)), '--shim', str(args.shim.resolve(strict=True)), '--version', args.version, '--artifacts', str(work), '--inside', case]
            with (work / 'fixture.log').open('w') as log:
                proc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=45)
            report = work / 'result.json'
            rows.append(dict(case=case, exit_code=proc.returncode, result=json.loads(report.read_text()) if report.exists() else None))
            (root / 'results.json').write_text(json.dumps(rows, indent=2))
            print(args.version, case, proc.returncode, flush=True)
        assert all((row['exit_code'] == 0 for row in rows)), rows
        return
    version, case = (args.version, args.inside)
    root = args.artifacts.resolve()
    assert ns('net') != os.environ['QELI_NT_HOST_NET'] and ns('mnt') != os.environ['QELI_NT_HOST_MNT']

    def run(*cmd):
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=10)
    run('mount', '--make-rprivate', '/')
    for path in ['/run', '/var/lib', '/var/log', '/tmp']:
        run('mount', '-t', 'tmpfs', 'tmpfs', path)
    etc = root / 'etc'
    etc.mkdir(mode=0o700)
    run('mount', '--bind', str(etc), '/etc/qeli')
    run('ip', 'link', 'set', 'lo', 'up')
    for tool in ['iptables', 'ip6tables']:
        run(tool, '-N', 'OPERATOR_SENTINEL')
        run(tool, '-A', 'OPERATOR_SENTINEL', '-j', 'RETURN')
        run(tool, '-A', 'OUTPUT', '-j', 'OPERATOR_SENTINEL')

    def snapshot():
        return [run(t, '-S') for t in ['iptables', 'ip6tables']] + [run('ip', f, 'route', 'show', 'table', 'all') for f in ['-4', '-6']] + [run('ip', '-j', 'link')]
    before = snapshot()
    (root / 'before.json').write_text(json.dumps(before))
    cfg = root / 'client.ini'
    known = root / 'known_hosts'
    device = root / 'device-id'
    beat = root / 'heartbeat'
    status = root / 'status.json'
    state = root / 'state'
    state.mkdir(mode=0o700)
    cfg.write_text(f'[qeli]\nserver = 192.0.2.1:24443\nproto = tcp\nuser = audit\npassword_command = touch {root}/credential-called; echo fixture-password\nmode = fake-tls\ndev = qnt0\nbind_static = false\ngateway = true\ndns = off\nkill_switch = true\nreconnect = false\npost_up = touch {root}/post-up\ntimeout = 1\n')
    if case == 'oversize':
        cfg.write_bytes(b'#' * 524288)
    cfg.chmod(0o600)
    driver = args.driver.resolve(strict=True)
    shim = args.shim.resolve(strict=True)
    env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_KNOWN_HOSTS=str(known), QELI_DEVICE_ID_FILE=str(device), QELI_CLIENT_STATUS=str(status), LD_PRELOAD=str(shim), QELI_STARTUP_FIXTURE=str(root), QELI_STARTUP_MODE=case)

    def ticks():
        try:
            return int(beat.read_text())
        except (ValueError, FileNotFoundError):
            return 0

    def wait(check):
        end = time.monotonic() + 10
        while not check():
            assert time.monotonic() < end, 'read hook was not entered'
            time.sleep(0.02)
    with (root / 'client.log').open('w') as log:
        p = subprocess.Popen([str(driver), str(cfg), str(beat)], env=env, stdout=log, stderr=subprocess.STDOUT)
        delta = 0
        alive = None
        try:
            if case != 'oversize':
                wait((root / 'entered').exists)
                n = ticks()
                time.sleep(0.5)
                delta = ticks() - n
                assert delta >= 3 if version == 'fixed' else delta == 0, delta
                p.send_signal(signal.SIGTERM)
                time.sleep(0.4)
                alive = p.poll() is None
                assert alive if version == 'fixed' else not alive
                (root / 'release').touch()
            code = p.wait(timeout=15)
            output = (root / 'client.log').read_text()
            if case == 'oversize':
                assert code == 1, output
                assert (root / 'entered').exists() == (version == 'baseline')
                assert 'maximum is 262144' in output if version == 'fixed' else 'Input/output error' in output, output
            elif version == 'baseline':
                assert code == -signal.SIGTERM, code
            else:
                assert code == (1 if case == 'fault' else 0), output
                if case == 'fault':
                    assert 'Input/output error' in output, output
            if version == 'fixed' and case == 'stop':
                assert json.loads(status.read_text())['state'] == 'stopped'
            after = snapshot()
            (root / 'after.json').write_text(json.dumps(after))
            assert before == after
            assert not known.exists() and (not device.exists()) and (not (root / 'post-up').exists()) and (not (root / 'credential-called').exists())
            (root / 'result.json').write_text(json.dumps(dict(version=version, case=case, exit_code=code, ticks=delta, alive_after_stop=alive, reads=(root / 'entered').read_text() if (root / 'entered').exists() else '', network_unchanged=True, no_credentials_or_identity=True, driver_sha256=sha(driver), shim_sha256=sha(shim)), indent=2))
        finally:
            (root / 'release').touch()
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)
if __name__ == '__main__':
    main()
