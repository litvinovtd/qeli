#!/usr/bin/env python3
"""Audit cancellation and retained firewall barriers on a current-thread runtime in private Linux namespaces."""
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


WRAPPER = r"""#!/usr/bin/python3
import os,sys,subprocess,time
from pathlib import Path
root=Path(os.environ['QELI_FW_ROOT']);stage=os.environ['QELI_FW_STAGE'];tool=Path(sys.argv[0]).name;a=sys.argv[1:];chain='QELI_KS_qnt0'
ready=root/'ready';release=root/'release';enabled=(root/'fault-enabled').exists()
setup=tool=='ip6tables' and a==['-C','OUTPUT','-j',chain] and (root/'v6-hooked').exists()
refresh=tool=='iptables' and a==['-C',chain,'-d','192.0.2.3','-j','ACCEPT'] and (root/'new-allowed').exists()
cleanup=tool=='iptables' and a==['-D','OUTPUT','-j',chain]
trigger=dict(setup=setup,refresh=refresh,cleanup=cleanup)[stage]
first=trigger and not ready.exists()
if first:
 ready.write_text(tool+' '+' '.join(a));until=time.monotonic()+60
 while not release.exists():
  assert time.monotonic()<until
  time.sleep(.05)
if trigger and enabled and (first or stage=='cleanup'):
 sys.stderr.write('injected firewall '+stage+' failure\n');sys.exit(2)
p=subprocess.run([str(root/'real'/tool),*a],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
if p.returncode==0 and tool=='ip6tables' and a==['-I','OUTPUT','1','-j',chain]:
 (root/'v6-hooked').touch()
 if stage=='refresh':(root/'hosts').write_text('127.0.0.1 localhost\n::1 localhost\n192.0.2.3 qeli-firewall.test\n')
if p.returncode==0 and tool=='iptables' and a==['-I',chain,'1','-d','192.0.2.3','-j','ACCEPT']:(root/'new-allowed').touch()
sys.stdout.buffer.write(p.stdout);sys.stderr.buffer.write(p.stderr);sys.exit(p.returncode)
"""
PROBE = r"""
import socket,json
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(.15)
r=dict(replies=0,errors=[])
for i in range(3):
 try:
  sock.sendto(b'probe',('192.0.2.9',33333));reply=sock.recvfrom(100)[0];r['replies']+=int(reply==b'probe')
 except OSError as error:r['errors'].append(str(error))
print(json.dumps(r))
"""
ECHO = r"""
import socket,sys
from pathlib import Path
root=Path(sys.argv[1]);sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('192.0.2.9',33333))
(root/'received').write_text('');(root/'echo-ready').touch()
with (root/'received').open('a',buffering=1) as log:
 while True:
  packet,peer=sock.recvfrom(100);log.write('received\n');sock.sendto(packet,peer)
"""

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
    ap.add_argument('--inside',choices=[p+'-'+s+'-'+f for p in ['tcp','udp'] for s in ['setup','refresh','cleanup'] for f in ['clean','fault']],help=argparse.SUPPRESS)
    args=ap.parse_args();root=args.artifacts.resolve();binary=args.qeli.resolve(strict=True);driver=(args.baseline_driver if args.version=='baseline' else args.driver).resolve(strict=True)
    if not args.inside:
        if os.geteuid()!=0:raise RuntimeError('requires root in a disposable Linux lab')
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        env=dict(os.environ,QELI_NT_HOST_NET=ns('net'),QELI_NT_HOST_MNT=ns('mnt'))
        rows=[]
        for version,case in [(v,p+'-'+s+'-'+f) for v in ['baseline','fixed'] for p in ['tcp','udp'] for s in ['setup','refresh','cleanup'] for f in (['clean','fault'] if v=='fixed' or s=='cleanup' else ['clean'])]:
            work=root/(version+'-'+case);work.mkdir(mode=0o700)
            cmd=['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),'--qeli',str(binary),'--driver',str(args.driver.resolve()),'--baseline-driver',str(args.baseline_driver.resolve()),'--version',version,'--artifacts',str(work),'--inside',case]
            with (work/'fixture.log').open('w') as log:proc=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=100)
            report=work/'result.json';rows.append(dict(case=case,version=version,exit_code=proc.returncode,result=json.loads(report.read_text()) if report.exists() else None))
            (root/'results.json').write_text(json.dumps(rows,indent=2));print(case,proc.returncode,flush=True)
        assert len(rows)==20 and all(r['exit_code']==0 for r in rows),rows
        return
    assert os.environ.get('QELI_NT_HOST_NET') and ns('net')!=os.environ['QELI_NT_HOST_NET'] and ns('mnt')!=os.environ['QELI_NT_HOST_MNT']
    proto,stage,outcome=args.inside.split('-');fault=outcome=='fault';commands=[]
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
    run(['ip','addr','add','192.0.2.1/24','dev','peer0']);run(['ip','addr','add','192.0.2.3/24','dev','peer0']);run(['ip','addr','add','192.0.2.9/24','dev','peer0']);run(['ip','link','set','peer0','up'])
    cli('ip','link','set','lo','up');cli('ip','addr','add','192.0.2.2/24','dev','wan0');cli('ip','link','set','wan0','up')
    cli('ip','route','add','default','via','192.0.2.1')
    cli('ip','-6','addr','add','fd42::2/64','dev','wan0','nodad')
    hosts=root/'hosts';hosts.write_text('127.0.0.1 localhost\n::1 localhost\n192.0.2.1 qeli-firewall.test\n');run(['mount','--bind',hosts,'/etc/hosts'])
    wait(lambda: 'tentative' not in cli('ip','-6','addr','show','dev','wan0'))
    for tool in ['iptables','ip6tables']:
        cli(tool,'-N','OPERATOR_SENTINEL');cli(tool,'-A','OPERATOR_SENTINEL','-j','RETURN');cli(tool,'-A','OUTPUT','-j','OPERATOR_SENTINEL')
    def snapshot(name):
        data=dict(rules=[cli(t,'-S') for t in ['iptables','ip6tables']],routes=[cli('ip',f,'route','show','table','all') for f in ['-4','-6']],links=json.loads(cli('ip','-j','link')))
        (root/(name+'.json')).write_text(json.dumps(data,indent=2));return data
    servercfg=etc/'server.ini';users=etc/'users.ini';users.write_text('')
    # Pin the reply source: a wildcard UDP socket may reply from the primary
    # address (.1), which a client connected to the rotated address (.3) drops.
    server_address='192.0.2.3' if stage=='refresh' else '192.0.2.1'
    servercfg.write_text(f'[auth]\nusers_file = {users}\nrequire_client_key_proof = false\nbind_static_to_session = false\n[web]\nenabled = false\n[logging]\nlevel = debug\n[profile:audit]\nidentity_key = {etc}/identity.key\nbind.address = {server_address}\nbind.port = 24443\nbind.transport = {proto}\ntun.name = qnt-server\ntun.address = 10.86.0.1\npool.cidr = 10.86.0.0/24\npool.exclude = 10.86.0.1\nrouting.nat.enabled = false\nrouting.ipv6.mode = off\nrouting.forward_private = true\ndns.enabled = false\nobf.mode = fake-tls\n')
    servercfg.chmod(0o600)
    run([binary,'add-client','audit','--password-stdin','--profiles','audit','--static-ip','10.86.0.2','-c',servercfg],input='fixture-password\n')
    cfg=etc/'client.ini';post_up=root/'post-up'
    cfg.write_text(f'[qeli]\nserver = qeli-firewall.test:24443\nproto = {proto}\nuser = audit\npass = fixture-password\nmode = fake-tls\ndev = qnt0\nbind_static = false\ngateway = true\ndns = off\nkill_switch = true\npost_up = touch {post_up}\ntimeout = 10\n[logging]\nlevel = debug\n');cfg.chmod(0o600)
    ready=root/'ready';release=root/'release';beat=root/'heartbeat';status=root/'status.json';state=root/'state';state.mkdir(mode=0o700)
    env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_KNOWN_HOSTS=str(root/'known-hosts'),QELI_DEVICE_ID_FILE=str(root/'device-id'),QELI_CLIENT_STATUS=str(status))
    wrappers=root/'wrappers';wrappers.mkdir();real=root/'real';real.mkdir()
    enabled=root/'fault-enabled'
    if fault:enabled.touch()
    env.update(QELI_IPT_DIR=str(wrappers),QELI_FW_ROOT=str(root),QELI_FW_STAGE=stage)
    for tool in ['iptables','ip6tables']:
        shutil.copy2(Path(shutil.which(tool)).resolve(),real/tool)
        wrapper=wrappers/tool;wrapper.write_text(WRAPPER);wrapper.chmod(0o700)
    def probe(name,blocked):
        before_count=len((root/'received').read_text().splitlines()) if (root/'received').exists() else 0
        counters=cli('iptables','-nvx','-L','QELI_KS_qnt0') if blocked else ''
        drop_before=sum(int(line.split()[0]) for line in counters.splitlines() if len(line.split())>2 and line.split()[2]=='DROP')
        report=json.loads(cli(sys.executable,'-c',PROBE));time.sleep(.05)
        received=len((root/'received').read_text().splitlines())-before_count
        counters=cli('iptables','-nvx','-L','QELI_KS_qnt0') if blocked else ''
        drop_after=sum(int(line.split()[0]) for line in counters.splitlines() if len(line.split())>2 and line.split()[2]=='DROP')
        report.update(received=received,drop_before=drop_before,drop_after=drop_after,blocked=blocked)
        (root/(name+'.json')).write_text(json.dumps(report,indent=2))
        if blocked:assert report['replies']==received==0 and drop_after-drop_before>=3,report
        else:assert report['replies']==received==3 and not report['errors'],report
        return report
    echo=subprocess.Popen([sys.executable,'-u','-c',ECHO,str(root)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    wait(lambda:(root/'echo-ready').exists())
    with (root/'server.log').open('w') as slog,(root/'client.log').open('w') as clog:
        server=subprocess.Popen([str(binary),'server','-c',str(servercfg)],env=dict(os.environ,QELI_CONTROL_SOCKET=str(root/'control.sock')),stdout=slog,stderr=subprocess.STDOUT)
        client=None
        try:
            wait(lambda: ':24443' in run(['ss','-lnu' if proto=='udp' else '-lnt']))
            preflight=probe('preflight',False)
            before=snapshot('before')
            client=subprocess.Popen([shutil.which('ip'),'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=clog,stderr=subprocess.STDOUT)
            def running():
                assert client.poll() is None,(root/'client.log').read_text()
                try:return json.loads(status.read_text())['state']=='running'
                except (ValueError,FileNotFoundError):return False
            if stage=='cleanup':
                wait(running,30);wait(post_up.exists);assert not ready.exists()
                client.send_signal(signal.SIGTERM)
            wait(ready.exists,30);assert client.poll() is None
            def heartbeat():
                try:return int(beat.read_text())
                except (ValueError,FileNotFoundError):return 0
            count=heartbeat();time.sleep(.8);work_ticks=heartbeat()-count
            if stage!='cleanup':client.send_signal(signal.SIGTERM)
            count=heartbeat();time.sleep(.8);stop_ticks=heartbeat()-count
            if args.version=='baseline':assert work_ticks<=1 and stop_ticks<=1,(work_ticks,stop_ticks)
            else:assert work_ticks>=3 and stop_ticks>=3,(work_ticks,stop_ticks)
            held=snapshot('held');assert not any(p['ifname']=='qnt0' for p in held['links'])
            assert all('-j QELI_KS_qnt0' in rules and '-j DROP' in rules for rules in held['rules'])
            held_probe=probe('held-probe',True)
            competing=subprocess.run([shutil.which('ip'),'netns','exec','qnt-client',str(binary),'client','-c',str(cfg)],env=dict(env,QELI_CLIENT_STATUS=str(root/'competing-status.json')),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=10)
            (root/'competing.log').write_text(competing.stdout)
            assert competing.returncode!=0 and 'cannot reserve TUN' in competing.stdout,competing.stdout
            release.touch();started=time.monotonic();rc=client.wait(timeout=25);elapsed=time.monotonic()-started
            after=snapshot('after');final=json.loads(status.read_text());log=(root/'client.log').read_text()
            had_post_up=post_up.exists();assert had_post_up==(stage=='cleanup')
            assert not any(p['ifname']=='qnt0' for p in after['links']) and before['routes']==after['routes']
            clean=after['rules']==before['rules'] and not list(state.rglob('*.state'))
            recovery=None;after_probe=None
            if fault:
                assert rc==1 and final['state']=='failed',(rc,final,log)
                if stage=='setup':assert clean
                else:
                    assert not clean
                    after_probe=probe('after-probe',args.version=='fixed' or stage=='refresh')
                    if stage=='refresh':assert all('-j DROP' in rules for rules in after['rules'])
                    if stage=='cleanup' and args.version=='fixed':assert '-A QELI_KS_qnt0 -j DROP' in after['rules'][0]
                    enabled.unlink()
                    with (root/'recovery.log').open('w') as recovery_log:
                        client=subprocess.Popen([shutil.which('ip'),'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=recovery_log,stderr=subprocess.STDOUT)
                        wait(running,30);client.send_signal(signal.SIGTERM);recovery_rc=client.wait(timeout=25)
                    recovered=snapshot('recovered')
                    recovery=dict(exit_code=recovery_rc,clean=recovered['rules']==before['rules'] and recovered['routes']==before['routes'] and not any(p['ifname']=='qnt0' for p in recovered['links']) and not list(state.rglob('*.state')))
                    assert recovery_rc==0 and recovery['clean'],recovery
            else:assert rc==0 and clean and final['state']=='stopped',(rc,clean,final,log)
            result=dict(case=args.inside,version=args.version,exit_code=rc,clean=clean,work_ticks=work_ticks,stop_ticks=stop_ticks,seconds_after_release=elapsed,post_up=had_post_up,final_state=final['state'],held_probe=held_probe,after_probe=after_probe,recovery=recovery,competing_exit=competing.returncode,worker_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest())
            (root/'result.json').write_text(json.dumps(result,indent=2))
        finally:
            release.touch(exist_ok=True)
            for process in [client,server,echo]:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=20)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=='__main__':main()
