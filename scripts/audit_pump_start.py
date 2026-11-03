#!/usr/bin/env python3
"""Audit joined startup/rollback of failed TUN pumps on a current-thread runtime in private Linux namespaces."""
import argparse
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
    info=os.stat('/proc/self/ns/'+kind)
    return f'{info.st_dev}:{info.st_ino}'


def run_competitor(root,driver,cfg,env,real):
    other=dict(env,QELI_CLIENT_STATUS=str(root/'competitor-status.json'))
    p=subprocess.run([real,'netns','exec','qnt-client',str(driver),str(cfg),str(root/'competitor-beat')],env=other,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=5)
    (root/'competitor.log').write_text(p.stdout)
    assert p.returncode==1 and 'cannot reserve TUN' in p.stdout,p.stdout
    return dict(exit_code=p.returncode,error=p.stdout)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qeli',required=True,type=Path)
    ap.add_argument('--driver',required=True,type=Path)
    ap.add_argument('--shim',required=True,type=Path)
    ap.add_argument('--baseline-driver',required=True,type=Path)
    ap.add_argument('--version',choices=['baseline','fixed'],default='fixed',help=argparse.SUPPRESS)
    ap.add_argument('--artifacts',required=True,type=Path)
    ap.add_argument('--inside',choices=[p+'-'+f+'-'+s for p in ['tcp','udp'] for f in ['fcntl','writer'] for s in ['clean','fault']],help=argparse.SUPPRESS)
    args=ap.parse_args();root=args.artifacts.resolve();binary=args.qeli.resolve(strict=True);driver=(args.baseline_driver if args.version=='baseline' else args.driver).resolve(strict=True)
    if not args.inside:
        if os.geteuid()!=0:raise RuntimeError('requires root in a disposable Linux lab')
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        env=dict(os.environ,QELI_NT_HOST_NET=ns('net'),QELI_NT_HOST_MNT=ns('mnt'))
        rows=[]
        for version,case in [(v,p+'-'+f+'-'+s) for v in ['baseline','fixed'] for p in ['tcp','udp'] for f in ['fcntl','writer'] for s in (['clean'] if v=='baseline' else ['clean','fault'])]:
            work=root/(version+'-'+case);work.mkdir(mode=0o700)
            cmd=['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),'--qeli',str(binary),'--driver',str(args.driver.resolve()),'--shim',str(args.shim.resolve()),'--baseline-driver',str(args.baseline_driver.resolve()),'--version',version,'--artifacts',str(work),'--inside',case]
            with (work/'fixture.log').open('w') as log:proc=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=100)
            report=work/'result.json';rows.append(dict(case=case,version=version,exit_code=proc.returncode,result=json.loads(report.read_text()) if report.exists() else None))
            (root/'results.json').write_text(json.dumps(rows,indent=2));print(case,proc.returncode,flush=True)
        assert len(rows)==12 and all(r['exit_code']==0 for r in rows),rows
        return
    assert os.environ.get('QELI_NT_HOST_NET') and ns('net')!=os.environ['QELI_NT_HOST_NET'] and ns('mnt')!=os.environ['QELI_NT_HOST_MNT']
    proto,failure,stage=args.inside.split('-');commands=[]
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
        data=dict(rules=[cli(t,'-S') for t in ['iptables','ip6tables']],routes=[cli('ip',f,'route','show','table','all') for f in ['-4','-6']],links=json.loads(cli('ip','-j','link')),journals={p.name:p.read_text() for p in Path('/var/lib/qeli').glob('*.state') if p.is_file()})
        (root/(name+'.json')).write_text(json.dumps(data,indent=2));return data
    servercfg=etc/'server.ini';users=etc/'users.ini';users.write_text('')
    servercfg.write_text(f'[auth]\nusers_file = {users}\nrequire_client_key_proof = false\nbind_static_to_session = false\n[web]\nenabled = false\n[logging]\nlevel = debug\n[profile:audit]\nidentity_key = {etc}/identity.key\nbind.address = 192.0.2.1\nbind.port = 24443\nbind.transport = {proto}\ntun.name = qnt-server\ntun.address = 10.86.0.1\npool.cidr = 10.86.0.0/24\npool.exclude = 10.86.0.1\nrouting.nat.enabled = false\nrouting.ipv6.mode = off\nrouting.forward_private = true\ndns.enabled = false\nobf.mode = fake-tls\n')
    servercfg.chmod(0o600)
    run([binary,'add-client','audit','--password-stdin','--profiles','audit','--static-ip','10.86.0.2','-c',servercfg],input='fixture-password\n')
    cfg=etc/'client.ini';post_up=root/'post-up'
    cfg.write_text(f'[qeli]\nserver = 192.0.2.1:24443\nproto = {proto}\nuser = audit\npass = fixture-password\nmode = fake-tls\ndev = qnt0\nbind_static = false\ngateway = true\ndns = off\nkill_switch = true\nreconnect = false\npost_up = touch {post_up}\ntimeout = 10\n[logging]\nlevel = debug\n');cfg.chmod(0o600)
    ready=root/'ready';release=root/'release';beat=root/'heartbeat';status=root/'status.json';state=root/'state';state.mkdir(mode=0o700)
    env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_KNOWN_HOSTS=str(root/'known-hosts'),QELI_DEVICE_ID_FILE=str(root/'device-id'),QELI_CLIENT_STATUS=str(status))
    (root/'fault-enabled').touch()
    env.update(LD_PRELOAD=str(args.shim.resolve(strict=True)),QELI_PUMP_FIXTURE=str(root),QELI_PUMP_FAILURE=failure)
    wrappers=root/'wrappers';wrappers.mkdir();wrapper=wrappers/'ip';real=shutil.which('ip')
    wrapper.write_text('#!/usr/bin/python3\nimport os,sys,time\nfrom pathlib import Path\n'
        +'a=sys.argv[1:]\n'
        +f'if "route" in a and "del" in a and not Path({str(ready)!r}).exists():\n'
        +f' Path({str(ready)!r}).write_text(" ".join(a))\n until=time.monotonic()+60\n'
        +f' while not Path({str(release)!r}).exists():\n  assert time.monotonic()<until\n  time.sleep(.05)\n'
        +(' sys.stderr.write("injected route cleanup failure\\n")\n sys.exit(2)\n' if stage=='fault' else '')
        +f'os.execv({real!r},[{real!r},*a])\n')
    wrapper.chmod(0o700);env['PATH']=str(wrappers)+os.pathsep+env['PATH']
    with (root/'server.log').open('w') as slog,(root/'client.log').open('w') as clog:
        server=subprocess.Popen([str(binary),'server','-c',str(servercfg)],env=dict(os.environ,QELI_CONTROL_SOCKET=str(root/'control.sock')),stdout=slog,stderr=subprocess.STDOUT)
        client=None
        try:
            wait(lambda: ':24443' in run(['ss','-lnu' if proto=='udp' else '-lnt']))
            before=snapshot('before')
            client=subprocess.Popen([shutil.which('ip'),'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=clog,stderr=subprocess.STDOUT)
            def running():
                assert client.poll() is None,(root/'client.log').read_text()
                try:return json.loads(status.read_text())['state']=='running'
                except (ValueError,FileNotFoundError):return False
            wait((root/'pump-ready').exists,30);wait(post_up.exists);assert not ready.exists()
            active=snapshot('active');assert any(p['ifname']=='qnt0' for p in active['links'])
            def heartbeat():
                try:return int(beat.read_text())
                except (ValueError,FileNotFoundError):return 0
            def threads():
                return sorted(p.read_text().strip() for p in Path(f'/proc/{client.pid}/task').glob('*/comm'))
            count=heartbeat();time.sleep(.8);startup_ticks=heartbeat()-count
            held_threads=threads()
            assert ('qeli-tun-reader' in held_threads)==(failure=='writer'),held_threads
            assert 'qeli-tun-writer' not in held_threads,held_threads
            (root/'pump-release').touch()
            wait(ready.exists,15);assert client.poll() is None
            rollback_threads=threads()
            assert not any(t in ['qeli-tun-reader','qeli-tun-writer'] for t in rollback_threads),rollback_threads
            if stage=='fault':client.send_signal(signal.SIGTERM)
            count=heartbeat();time.sleep(.8);stop_ticks=heartbeat()-count
            if args.version=='baseline':assert startup_ticks<=1 and stop_ticks<=1,(startup_ticks,stop_ticks)
            else:assert startup_ticks>=5 and stop_ticks>=5,(startup_ticks,stop_ticks)
            # Rollback must retain the original TUN and cooperative network lease.
            competitor=run_competitor(root,driver,cfg,env,real)
            held=snapshot('held');assert any(p['ifname']=='qnt0' for p in held['links'])
            assert all('QELI_KS' in rules and '-j DROP' in rules for rules in held['rules'])
            release.touch();started=time.monotonic();rc=client.wait(timeout=20);elapsed=time.monotonic()-started
            assert rc==1, (root/'client.log').read_text()
            after=snapshot('after');final=json.loads(status.read_text());log=(root/'client.log').read_text()
            assert not any(p['ifname']=='qnt0' for p in after['links'])
            if stage=='clean':assert before['routes']==after['routes']
            else:
                for original,current,owned in zip(before['routes'],after['routes'],active['routes']):
                    assert set(original.splitlines()) <= set(current.splitlines()) <= set(owned.splitlines())
            clean=after['rules']==before['rules'] and not list(state.rglob('*.state'))
            assert final['state']=='failed',final
            assert ('Input/output error' if failure=='fcntl' else 'Resource temporarily unavailable') in final['last_error'],final
            assert ('Input/output error' if failure=='fcntl' else 'Resource temporarily unavailable') in log,log
            recovery=None
            if stage=='fault':
                assert rc==1 and not clean and all('QELI_KS' in rules for rules in after['rules'])
                assert 'injected route cleanup failure' in log and 'kill-switch retained' in log
                (root/'fault-enabled').unlink()
                # A new explicit start recovers journals and firewall left after the fault.
                with (root/'recovery.log').open('w') as recovery_log:
                    client=subprocess.Popen([real,'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=recovery_log,stderr=subprocess.STDOUT)
                    wait(running,30);client.send_signal(signal.SIGTERM);recovery_rc=client.wait(timeout=20)
                recovered=snapshot('recovered')
                recovery=dict(exit_code=recovery_rc,clean=recovered['rules']==before['rules'] and recovered['routes']==before['routes'] and not any(p['ifname']=='qnt0' for p in recovered['links']) and not list(state.rglob('*.state')))
                assert recovery_rc==0 and recovery['clean'],recovery
            else:assert rc==1 and clean and final['state']=='failed'
            result=dict(case=args.inside,version=args.version,exit_code=rc,clean=clean,startup_ticks=startup_ticks,stop_ticks=stop_ticks,held_threads=held_threads,rollback_threads=rollback_threads,competitor=competitor,seconds_after_release=elapsed,post_up=post_up.exists(),final_state=final['state'],recovery=recovery,worker_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest(),shim_sha256=hashlib.sha256(args.shim.read_bytes()).hexdigest())
            (root/'result.json').write_text(json.dumps(result,indent=2))
        finally:
            release.touch(exist_ok=True)
            (root/'pump-release').touch(exist_ok=True)
            for process in [client,server]:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=20)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=='__main__':main()
