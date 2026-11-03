#!/usr/bin/env python3
"""Exercise real client status fsync on a current-thread runtime in private Linux namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def identity(kind):
    s = os.stat('/proc/self/ns/' + kind)
    return [s.st_dev, s.st_ino]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--driver', required=True, type=Path)
    ap.add_argument('--baseline-driver', required=True, type=Path)
    ap.add_argument('--shim', required=True, type=Path)
    ap.add_argument('--artifacts', required=True, type=Path)
    ap.add_argument('--inside', choices=['tcp-failed-none', 'tcp-failed-first', 'tcp-failed-final', 'udp-stopped-none'], help=argparse.SUPPRESS)
    ap.add_argument('--version', choices=['baseline', 'fixed'], default='fixed', help=argparse.SUPPRESS)
    args = ap.parse_args()
    root = args.artifacts.resolve()
    if not args.inside:
        assert os.geteuid() == 0, 'requires root in a disposable Linux lab'
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        rows = []
        env = dict(os.environ, QELI_STATUS_PARENT=json.dumps([identity('net'), identity('mnt')]))
        for version, case in [('baseline', 'tcp-failed-none'), ('baseline', 'udp-stopped-none'), ('fixed', 'tcp-failed-none'), ('fixed', 'tcp-failed-first'), ('fixed', 'tcp-failed-final'), ('fixed', 'udp-stopped-none')]:
            work = root / (version + '-' + case)
            work.mkdir(mode=0o700)
            target = work / 'target'
            target.mkdir(mode=0o700)
            (target / 'status.json').write_text('host sentinel')
            cmd = ['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--driver', str(args.driver.resolve()), '--baseline-driver', str(args.baseline_driver.resolve()), '--shim', str(args.shim.resolve()), '--artifacts', str(work), '--version', version, '--inside', case]
            with (work / 'fixture.log').open('w') as log:
                proc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=65)
            report = work / 'result.json'
            rows.append(dict(version=version, case=case, exit_code=proc.returncode, result=json.loads(report.read_text()) if report.exists() else None))
            assert (target / 'status.json').read_text() == 'host sentinel'
            (root / 'results.json').write_text(json.dumps(rows, indent=2))
            print(version, case, proc.returncode, flush=True)
        assert len(rows) == 6 and all(row['exit_code'] == 0 for row in rows), rows
        return
    parent = json.loads(os.environ['QELI_STATUS_PARENT'])
    assert identity('net') != parent[0] and identity('mnt') != parent[1]
    proto, terminal, fault = args.inside.split('-')
    driver = (args.baseline_driver if args.version == 'baseline' else args.driver).resolve(strict=True)
    def run(*cmd):
        return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=10)
    def wait(check, limit=15):
        deadline = time.monotonic() + limit
        while not check():
            assert time.monotonic() < deadline, 'fixture readiness timeout'
            time.sleep(.02)
    run('mount', '--make-rprivate', '/')
    view = root / 'view'
    view.mkdir(mode=0o700)
    run('mount', '--bind', str(view), str(root / 'target'))
    state = root / 'state'
    state.mkdir(mode=0o700)
    status = root / 'target/status.json'
    beat = root / 'heartbeat'
    credential = root / 'credential.sh'
    credential.write_text(f'#!/bin/sh\ntouch {root}/credential-ready\nwhile ! test -e {root}/credential-release; do sleep 0.05; done\nexit 7\n')
    credential.chmod(0o700)
    cfg = root / 'client.ini'
    cfg.write_text(f'[qeli]\nserver = 127.0.0.1:24443\nproto = {proto}\nuser = audit\npassword_command = {credential}\nmode = fake-tls\ndev = qstatus0\ngateway = false\ndns = off\nkill_switch = false\nreconnect = false\n')
    cfg.chmod(0o600)
    def network():
        return [run('ip', '-j', 'link'), run('ip', '-4', 'route', 'show', 'table', 'all'), run('ip', '-6', 'route', 'show', 'table', 'all')]
    before = network()
    env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_CLIENT_STATUS=str(status), QELI_CLIENT_PROFILE='audit-status', QELI_STATUS_FIXTURE=str(root), QELI_STATUS_FAULT=fault, LD_PRELOAD=str(args.shim.resolve(strict=True)))
    def heartbeat():
        try:
            return int(beat.read_text())
        except (FileNotFoundError, ValueError):
            return 0
    with (root / 'client.log').open('w') as log:
        client = subprocess.Popen([str(driver), str(cfg), str(beat)], env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait((root / 'first-ready').exists)
            first = heartbeat()
            time.sleep(.8)
            first_ticks = heartbeat() - first
            first_threads = sorted(p.read_text().strip() for p in Path(f'/proc/{client.pid}/task').glob('*/comm'))
            if args.version == 'fixed':
                assert first_ticks >= 5 and first_threads.count('qeli-status') == 1
                wait((root / 'credential-ready').exists)
            else:
                assert first_ticks == 0 and 'qeli-status' not in first_threads
            (root / 'first-release').touch()
            wait((root / 'credential-ready').exists)
            if fault != 'first':
                wait(status.exists)
                assert json.loads(status.read_text())['state'] == 'created'
            if terminal == 'stopped':
                client.send_signal(signal.SIGTERM)
            else:
                (root / 'credential-release').touch()
            wait((root / 'final-ready').exists)
            count = heartbeat()
            time.sleep(.8)
            final_ticks = heartbeat() - count
            assert client.poll() is None, 'returned before final write finished'
            assert final_ticks >= 5 if args.version == 'fixed' else final_ticks == 0
            (root / 'final-release').touch()
            code = client.wait(timeout=15)
            assert code == (0 if terminal == 'stopped' else 1), (root / 'client.log').read_text()
            final = json.loads(status.read_text())
            assert final['state'] == ('created' if fault == 'final' else terminal), final
            if terminal == 'failed' and fault != 'final':
                assert final['last_error'] and '7' in final['last_error'], final
            assert final['schema'] == 1 and final['profile'] == 'audit-status'
            assert status.stat().st_mode & 0o777 == 0o600
            assert not list(view.glob('.status.json.qeli-tmp-*'))
            stable = status.read_bytes()
            time.sleep(.2)
            assert status.read_bytes() == stable
            assert network() == before
            result = dict(version=args.version, case=args.inside, first_ticks=first_ticks, final_ticks=final_ticks, exit_code=code, status=final, first_threads=first_threads, network_unchanged=True, temporary_files_removed=True, private_mode='0600', sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [driver, args.shim.resolve()]})
            (root / 'result.json').write_text(json.dumps(result, indent=2))
        finally:
            for name in ['first-release', 'final-release', 'credential-release']:
                (root / name).touch(exist_ok=True)
            if client.poll() is None:
                client.terminate()
                try:
                    client.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait(timeout=5)


if __name__ == '__main__':
    main()
