#!/usr/bin/env python3
"""Verify composed setup and cleanup command deadlines in private Linux namespaces."""
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


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qeli',required=True,type=Path)
    ap.add_argument('--driver',required=True,type=Path)
    ap.add_argument('--baseline-driver',required=True,type=Path)
    ap.add_argument('--version',choices=['baseline','fixed'],default='fixed',help=argparse.SUPPRESS)
    ap.add_argument('--artifacts',required=True,type=Path)
    ap.add_argument('--inside',choices=['tcp-setup','udp-setup','tcp-cleanup','udp-cleanup'],help=argparse.SUPPRESS)
    args=ap.parse_args();root=args.artifacts.resolve();binary=args.qeli.resolve(strict=True);driver=(args.baseline_driver if args.version=='baseline' else args.driver).resolve(strict=True)
    if not args.inside:
        if os.geteuid()!=0:raise RuntimeError('requires root in a disposable Linux lab')
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        env=dict(os.environ,QELI_NT_HOST_NET=ns('net'),QELI_NT_HOST_MNT=ns('mnt'))
        rows=[]
        for version,case in [(v,p+'-'+s) for v in ['baseline','fixed'] for p in ['tcp','udp'] for s in ['setup','cleanup']]:
            work=root/(version+'-'+case);work.mkdir(mode=0o700)
            cmd=['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),'--qeli',str(binary),'--driver',str(args.driver.resolve()),'--baseline-driver',str(args.baseline_driver.resolve()),'--version',version,'--artifacts',str(work),'--inside',case]
            with (work/'fixture.log').open('w') as log:proc=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=100)
            report=work/'result.json';rows.append(dict(case=case,version=version,exit_code=proc.returncode,result=json.loads(report.read_text()) if report.exists() else None))
            (root/'results.json').write_text(json.dumps(rows,indent=2));print(case,proc.returncode,flush=True)
        assert len(rows)==8 and all(r['exit_code']==0 for r in rows),rows
        return
    assert os.environ.get('QELI_NT_HOST_NET') and ns('net')!=os.environ['QELI_NT_HOST_NET'] and ns('mnt')!=os.environ['QELI_NT_HOST_MNT']
    proto,stage=args.inside.split('-');commands=[]
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
        data=dict(rules=[cli(t,'-S') for t in ['iptables','ip6tables']],routes=[cli('ip',f,'route','show','table','all') for f in ['-4','-6']],links=json.loads(cli('ip','-j','link')))
        (root/(name+'.json')).write_text(json.dumps(data,indent=2));return data
    servercfg=etc/'server.ini';users=etc/'users.ini';users.write_text('')
    servercfg.write_text(f'[auth]\nusers_file = {users}\nrequire_client_key_proof = false\nbind_static_to_session = false\n[web]\nenabled = false\n[logging]\nlevel = debug\n[profile:audit]\nidentity_key = {etc}/identity.key\nbind.address = 192.0.2.1\nbind.port = 24443\nbind.transport = {proto}\ntun.name = qnt-server\ntun.address = 10.86.0.1\npool.cidr = 10.86.0.0/24\npool.exclude = 10.86.0.1\nrouting.nat.enabled = false\nrouting.ipv6.mode = off\nrouting.forward_private = true\ndns.enabled = false\nobf.mode = fake-tls\n')
    servercfg.chmod(0o600)
    run([binary,'add-client','audit','--password-stdin','--profiles','audit','--static-ip','10.86.0.2','-c',servercfg],input='fixture-password\n')
    cfg=etc/'client.ini';post_up=root/'post-up'
    cfg.write_text(f'[qeli]\nserver = 192.0.2.1:24443\nproto = {proto}\nuser = audit\npass = fixture-password\nmode = fake-tls\ndev = qnt0\nbind_static = false\ngateway = true\ngateway_nat = true\nlan_subnet = 192.0.2.0/24\ndns = off\nkill_switch = true\nreconnect = false\npost_up = touch {post_up}\ntimeout = 60\n[logging]\nlevel = debug\n');cfg.chmod(0o600)
    beat=root/'heartbeat';status=root/'status.json';state=root/'state';state.mkdir(mode=0o700)
    env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_KNOWN_HOSTS=str(root/'known-hosts'),QELI_DEVICE_ID_FILE=str(root/'device-id'),QELI_CLIENT_STATUS=str(status))
    wrappers=root/'wrappers';wrappers.mkdir(mode=0o700)
    real=shutil.which('ip')
    # Delay after the real mutation. Timeout must retain uncertain ownership and
    # rollback must not assume that a killed command left the kernel unchanged.
    for tool in ['ip','iptables','ip6tables']:
        target=shutil.which(tool)
        wrapper=wrappers/tool
        script=f'#!/usr/bin/python3\nimport os,sys,time,subprocess,json\nfrom pathlib import Path\nr=Path({str(root)!r});a=sys.argv[1:];key=None\n'
        if tool=='ip':
            if stage=='setup':
                script+='if a[:2]==["addr","add"] and "qnt0" in a:key="first"\nelif a[:2]==["link","set"] and "qnt0" in a and "up" in a:key="second"\n'
            else:
                script+='if "route" in a and "del" in a:key="first"\n'
        elif stage=='cleanup':
            script+='if "-D" in a and "qeli-gw-nat" in a:key="second"\n'
        script+=f'if key and not (r/key).exists():\n p=subprocess.run([{target!r},*a])\n (r/key).write_text(json.dumps(dict(start=time.monotonic(),argv=a,rc=p.returncode)))\n time.sleep(9)\n (r/(key+"-finished")).touch()\n sys.exit(p.returncode)\nos.execv({target!r},[{target!r},*a])\n'
        wrapper.write_text(script);wrapper.chmod(0o700)
    env['PATH']=str(wrappers)+os.pathsep+env['PATH'];env['QELI_IPT_DIR']=str(wrappers)
    with (root/'server.log').open('w') as slog,(root/'client.log').open('w') as clog:
        server=subprocess.Popen([str(binary),'server','-c',str(servercfg)],env=dict(os.environ,QELI_CONTROL_SOCKET=str(root/'control.sock')),stdout=slog,stderr=subprocess.STDOUT)
        client=None
        try:
            wait(lambda: ':24443' in run(['ss','-lnu' if proto=='udp' else '-lnt']))
            before=snapshot('before')
            client=subprocess.Popen([real,'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=clog,stderr=subprocess.STDOUT)
            def running():
                assert client.poll() is None,(root/'client.log').read_text()
                try:return json.loads(status.read_text())['state']=='running'
                except (ValueError,FileNotFoundError):return False
            def heartbeat():
                try:return int(beat.read_text())
                except (ValueError,FileNotFoundError):return 0
            if stage=='cleanup':
                wait(running,30);wait(post_up.exists)
                client.send_signal(signal.SIGTERM)
            wait((root/'first').exists,30)
            start=json.loads((root/'first').read_text())['start']
            n=heartbeat();time.sleep(.6);ticks=heartbeat()-n;assert ticks>=3,ticks
            wait((root/'second').exists,15)
            if stage=='setup' and args.version=='baseline':
                wait(running,30);wait(post_up.exists)
                elapsed=time.monotonic()-start
                client.send_signal(signal.SIGTERM);code=client.wait(timeout=20)
            else:
                code=client.wait(timeout=30);elapsed=time.monotonic()-start
            after=snapshot('after');final=json.loads(status.read_text());log=(root/'client.log').read_text()
            assert not any(p['ifname']=='qnt0' for p in after['links'])
            assert before['routes']==after['routes'],(before['routes'],after['routes'])
            for rules in after['rules']:assert '-A OUTPUT -j OPERATOR_SENTINEL' in rules
            clean=after['rules']==before['rules']
            if args.version=='baseline':
                assert code==0 and clean and final['state']=='stopped',log
                assert elapsed>=17,elapsed
                assert (root/'second-finished').exists()
            else:
                assert code==1 and final['state']=='failed',log
                assert 12<elapsed<18,elapsed
                assert not (root/'second-finished').exists(),'late command survived its deadline'
                if stage=='setup':
                    assert clean and not post_up.exists(),log
                else:
                    assert not clean and all('QELI_KS' in rules and '-j DROP' in rules for rules in after['rules']),log
                    assert 'kill-switch retained' in log,log
            recovery=None
            if args.version=='fixed' and stage=='cleanup':
                # Existing markers disarm both delays. Lost per-interface sysctl
                # witnesses must still refuse automatic replay (D02 contract).
                journal=state/'sysctls.state'
                initial_journal=json.loads(journal.read_text())
                (root/'sysctls-before-restart.json').write_text(json.dumps(initial_journal,indent=2))
                initial_records=[entry for group in initial_journal['namespaces'].values() for path,entry in group['entries'].items() if path=='/proc/sys/net/ipv4/conf/qnt0/rp_filter']
                assert len(initial_records)==1
                with (root/'recovery.log').open('w') as recovery_log:
                    client=subprocess.Popen([real,'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=recovery_log,stderr=subprocess.STDOUT)
                    wait(running,30);client.send_signal(signal.SIGTERM);recovery_code=client.wait(timeout=20)
                recovered=snapshot('recovered')
                recovery=dict(exit_code=recovery_code,clean=recovered['rules']==before['rules'] and recovered['routes']==before['routes'] and not any(p['ifname']=='qnt0' for p in recovered['links']))
                restart_log=(root/'recovery.log').read_text()
                assert recovery_code==1 and not recovery['clean'],recovery
                assert 'lost live per-interface sysctl evidence' in restart_log and 'kill-switch retained' in restart_log
                assert all('QELI_KS' in rules and '-j DROP' in rules for rules in recovered['rules'])
                assert recovered['routes']==before['routes'] and not any(p['ifname']=='qnt0' for p in recovered['links'])
                final_journal=json.loads(journal.read_text())
                (root/'sysctls-after-restart.json').write_text(json.dumps(final_journal,indent=2))
                retained=[(path,entry) for group in final_journal['namespaces'].values() for path,entry in group['entries'].items()]
                assert len(retained)==1 and retained[0][0]=='/proc/sys/net/ipv4/conf/qnt0/rp_filter'
                assert not retained[0][1]['owners']
                for key in ['original','managed','target']:assert retained[0][1][key]==initial_records[0][key]
                recovery['manual_sysctl_recovery_required']=True
                recovery['original_witness_record_preserved']=True
            result=dict(recovery=recovery,case=args.inside,version=args.version,exit_code=code,seconds=elapsed,ticks=ticks,clean=clean,post_up=post_up.exists(),final_state=final['state'],network_routes_restored=True,operator_firewall_preserved=True,worker_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest())
            (root/'result.json').write_text(json.dumps(result,indent=2))
        finally:
            for process in [client,server]:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=20)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=='__main__':main()
