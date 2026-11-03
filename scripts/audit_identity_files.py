#!/usr/bin/env python3
"""Reproduce bounded device identity and fail-closed TOFU file handling in private Linux namespaces."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import time


def ns(kind):
    info = os.stat('/proc/self/ns/' + kind)
    return f'{info.st_dev}:{info.st_ino}'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qeli', required=True, type=Path)
    ap.add_argument('--driver', required=True, type=Path)
    ap.add_argument('--baseline-driver', required=True, type=Path)
    ap.add_argument('--shim', required=True, type=Path)
    ap.add_argument('--artifacts', required=True, type=Path)
    ap.add_argument('--version', choices=['baseline', 'fixed'], default='fixed', help=argparse.SUPPRESS)
    ap.add_argument('--inside', choices=[p+'-'+s for p in ['tcp', 'udp'] for s in ['device-lock', 'corrupt', 'corrupt-optin', 'fsync']], help=argparse.SUPPRESS)
    args = ap.parse_args()
    root = args.artifacts.resolve()
    binary = args.qeli.resolve(strict=True)
    driver = (args.baseline_driver if args.version == 'baseline' else args.driver).resolve(strict=True)
    if not args.inside:
        assert os.geteuid() == 0, 'requires root in a disposable Linux lab'
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        env = dict(os.environ, QELI_NT_HOST_NET=ns('net'), QELI_NT_HOST_MNT=ns('mnt'))
        rows = []
        for version in ['baseline', 'fixed']:
            for proto in ['tcp', 'udp']:
                for stage in ['device-lock', 'corrupt', 'corrupt-optin', 'fsync']:
                    case = proto + '-' + stage
                    work = root / (version + '-' + case)
                    work.mkdir(mode=0o700)
                    cmd = ['unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL', '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--qeli', str(binary), '--driver', str(args.driver.resolve()), '--baseline-driver', str(args.baseline_driver.resolve()), '--shim', str(args.shim.resolve()), '--version', version, '--artifacts', str(work), '--inside', case]
                    with (work / 'fixture.log').open('w') as log:
                        proc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=80)
                    report = work / 'result.json'
                    rows.append(dict(version=version, case=case, exit_code=proc.returncode, result=json.loads(report.read_text()) if report.exists() else None))
                    (root / 'results.json').write_text(json.dumps(rows, indent=2))
                    print(version, case, proc.returncode, flush=True)
        assert len(rows) == 16 and all(r['exit_code'] == 0 for r in rows), rows
        return
    assert os.environ.get('QELI_NT_HOST_NET') and ns('net')!=os.environ['QELI_NT_HOST_NET'] and ns('mnt')!=os.environ['QELI_NT_HOST_MNT']
    proto,stage=args.inside.split('-',1);commands=[]
    def run(argv,input=None):
        argv=list(map(str,argv));p=subprocess.run(argv,input=input,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
        commands.append(dict(argv=argv,rc=p.returncode,output=p.stdout));(root/'commands.json').write_text(json.dumps(commands,indent=2))
        if p.returncode:raise RuntimeError(f'{argv}: {p.stdout}')
        return p.stdout
    def cli(*argv):return run(['ip','netns','exec','qnt-client',*argv])
    def wait(check,seconds=20):
        until=time.monotonic()+seconds
        while not check():
            assert time.monotonic()<until,'fixture readiness timeout'
            time.sleep(.05)
    run(['mount','--make-rprivate','/'])
    for path in ['/run','/var/lib','/var/log','/tmp']:run(['mount','-t','tmpfs','tmpfs',path])
    Path('/run/qeli-identity').mkdir(mode=0o700)
    Path('/run/netns').mkdir();etc=root/'etc';etc.mkdir(mode=0o700);run(['mount','--bind',etc,'/etc/qeli'])
    run(['ip','link','set','lo','up']);run(['ip','netns','add','qnt-client'])
    run(['ip','link','add','peer0','type','veth','peer','name','wan0']);run(['ip','link','set','wan0','netns','qnt-client'])
    run(['ip','addr','add','192.0.2.1/24','dev','peer0']);run(['ip','link','set','peer0','up'])
    cli('ip','link','set','lo','up');cli('ip','addr','add','192.0.2.2/24','dev','wan0');cli('ip','link','set','wan0','up')
    cli('ip','route','add','default','via','192.0.2.1')
    wait(lambda: 'tentative' not in cli('ip','-6','addr','show','dev','wan0'))
    for tool in ['iptables','ip6tables']:
        cli(tool,'-N','OPERATOR_SENTINEL');cli(tool,'-A','OPERATOR_SENTINEL','-j','RETURN');cli(tool,'-A','OUTPUT','-j','OPERATOR_SENTINEL')
    def snapshot(name):
        data=dict(rules=[cli(t,'-S') for t in ['iptables','ip6tables']],routes=[cli('ip',f,'route','show','table','all') for f in ['-4','-6']],links=json.loads(cli('ip','-j','link')))
        (root/(name+'.json')).write_text(json.dumps(data,indent=2));return data
    servercfg=etc/'server.ini';users=etc/'users.ini';users.write_text('')
    servercfg.write_text(f'[auth]\nusers_file = {users}\nrequire_client_key_proof = false\nbind_static_to_session = false\n[web]\nenabled = false\n[logging]\nlevel = debug\n[profile:audit]\nidentity_key = {etc}/identity.key\nbind.address = 192.0.2.1\nbind.port = 24443\nbind.transport = {proto}\ntun.name = qnt-server\ntun.address = 10.86.0.1\npool.cidr = 10.86.0.0/24\npool.exclude = 10.86.0.1\nrouting.nat.enabled = false\nrouting.ipv6.mode = off\nrouting.forward_private = true\ndns.enabled = false\nobf.mode = fake-tls\n')
    servercfg.chmod(0o600)
    run([binary,'add-client','audit','--password-stdin','--profiles','audit','--static-ip','10.86.0.2','-c',servercfg],input='fixture-password\n')
    cfg=etc/'client.ini';post_up=root/'post-up'
    cfg.write_text(f'[qeli]\nserver = 192.0.2.1:24443\nproto = {proto}\nuser = audit\npass = fixture-password\nmode = fake-tls\ndev = qnt0\nbind_static = false\ngateway = true\ndns = off\nkill_switch = true\nreconnect = false\npost_up = touch {post_up}\ntimeout = 10\n[logging]\nlevel = debug\n');cfg.chmod(0o600)
    beat = root / 'heartbeat'; status = root / 'status.json'; state = root / 'state'; state.mkdir(mode=0o700)
    known = root / 'known_hosts'; device = root / 'device-id'; lock = None
    initial = b''
    if stage.startswith('corrupt'):
        initial = b'192.0.2.1:24443 ' + b'bb' * 32 + b'\n# broken comment: \xff\n'
    elif stage == 'fsync':
        initial = b'# operator\nprior:443 ' + b'aa' * 32  # Deliberately no final newline.
    if initial:
        known.write_bytes(initial); known.chmod(0o600)
    if stage == 'device-lock':
        lock = open(str(device)+'.lock', 'w'); os.chmod(str(device)+'.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
    if stage == 'corrupt-optin':
        cfg.write_text(cfg.read_text().replace('[logging]', 'allow_unpinned_tofu = true\n[logging]'))
    env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_KNOWN_HOSTS=str(known), QELI_DEVICE_ID_FILE=str(device), QELI_CLIENT_STATUS=str(status))
    if stage == 'fsync':
        env.update(LD_PRELOAD=str(args.shim.resolve(strict=True)), QELI_IDENTITY_FIXTURE=str(root))
    with (root/'server.log').open('w') as slog, (root/'client.log').open('w') as clog:
        server = subprocess.Popen([str(binary), 'server', '-c', str(servercfg)], env=dict(os.environ, QELI_CONTROL_SOCKET='/run/qeli-identity/control.sock'), stdout=slog, stderr=subprocess.STDOUT)
        client = None
        try:
            wait(lambda: ':24443' in run(['ss', '-lnu' if proto == 'udp' else '-lnt']))
            before = snapshot('before')
            client = subprocess.Popen([shutil.which('ip'), 'netns', 'exec', 'qnt-client', str(driver), str(cfg), str(beat)], env=env, stdout=clog, stderr=subprocess.STDOUT)
            def running():
                assert client.poll() is None, (root/'client.log').read_text()
                try: return json.loads(status.read_text())['state'] == 'running'
                except (ValueError, FileNotFoundError): return False
            ticks = None
            if stage == 'device-lock':
                # /proc/locks exposes the real contended flock, not a timing assumption.
                inode = os.stat(str(device)+'.lock').st_ino
                def contended():
                    text = Path('/proc/locks').read_text()
                    return any(str(inode) in line and 'FLOCK' in line for line in text.splitlines()) and client.poll() is None and any(p.read_text().strip() == 'locks_lock_inode_wait' for p in Path(f'/proc/{client.pid}/task').glob('*/wchan'))
                if args.version == 'baseline': wait(contended, 15)
                else:
                    # Fixed uses bounded nonblocking flock retries on its worker.
                    wait(lambda: any(p.read_text().strip() == 'qeli-network-pl' for p in Path(f'/proc/{client.pid}/task').glob('*/comm')), 15)
                def heartbeat():
                    try: return int(beat.read_text())
                    except (ValueError, FileNotFoundError): return 0
                count = heartbeat(); time.sleep(.8); ticks = heartbeat() - count
                assert ticks >= 5 if args.version == 'fixed' else ticks == 0
                client.send_signal(signal.SIGTERM)
                time.sleep(.15)
                assert client.poll() is None and not device.exists()
                fcntl.flock(lock, fcntl.LOCK_UN); lock.close(); lock = None
                code = client.wait(timeout=20)
                assert code == 0, (root/'client.log').read_text()
                assert device.exists() and device.stat().st_size == 16
                assert device.read_bytes() != bytes(16)
                if args.version == 'fixed': assert not post_up.exists() and not known.exists()
            elif stage.startswith('corrupt') and args.version == 'baseline':
                wait(running, 30)
                wait(post_up.exists)
                assert post_up.exists() and known.read_bytes().startswith(initial)
                assert len(known.read_bytes()) > len(initial), 'baseline must demonstrate a new pin despite corrupt old store'
                client.send_signal(signal.SIGTERM); code = client.wait(timeout=20); assert code == 0
            else:
                code = client.wait(timeout=30)
                assert code == 1 and not post_up.exists(), (root/'client.log').read_text()
                if stage == 'fsync':
                    assert (root/'tofu-fsync-failed').exists()
                    assert (known.read_bytes() == initial) == (args.version == 'fixed')
                else:
                    assert known.read_bytes() == initial
                    assert 'UTF-8' in (root/'client.log').read_text()
            after = snapshot('after')
            assert before['rules'] == after['rules'] and before['routes'] == after['routes']
            assert not any(link['ifname'] == 'qnt0' for link in after['links'])
            assert not list(root.glob('.known_hosts.qeli-tmp-*'))
            final = json.loads(status.read_text())
            assert final['state'] == ('stopped' if code == 0 else 'failed')
            known_bytes = known.read_bytes() if known.exists() else None
            result = dict(version=args.version, case=args.inside, exit_code=code, status=final, ticks=ticks, post_up=post_up.exists(), known_unchanged=(known_bytes == initial) if initial else None, network_restored=True, worker_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(), shim_sha256=hashlib.sha256(args.shim.read_bytes()).hexdigest())
            (root/'result.json').write_text(json.dumps(result, indent=2))
        finally:
            if lock is not None: fcntl.flock(lock, fcntl.LOCK_UN); lock.close()
            for process in [client, server]:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=20)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


if __name__ == '__main__':
    main()
