#!/usr/bin/env python3
"""Stop real NetworkPlan application on a current-thread runtime in private Linux namespaces."""
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

SHIM = r"""
#define _GNU_SOURCE
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdatomic.h>
static atomic_int delayed;
int ioctl(int fd, unsigned long request, ...) {
    va_list ap; va_start(ap,request); void *arg=va_arg(ap,void *); va_end(ap);
    int (*real)(int,unsigned long,...)=dlsym(RTLD_NEXT,"ioctl");
    int rc=real(fd,request,arg);
    if (rc<0 || (request!=TUNSETIFF && request!=SIOCSIFFLAGS)) return rc;
    struct ifreq *ifr=arg;
    if (strcmp(ifr->ifr_name,"qnt0")) return rc;
    const char *stage=getenv("QELI_NT_STAGE");
    if ((request==TUNSETIFF && strcmp(stage,"create")) || (request==SIOCSIFFLAGS && strcmp(stage,"up"))) return rc;
    if (!atomic_exchange(&delayed,1)) {
        int marker=open(getenv("QELI_NT_READY"),O_WRONLY|O_CREAT|O_EXCL,0600);
        if (marker<0) _exit(112); close(marker);
        for (unsigned i=0;i<600 && access(getenv("QELI_NT_RELEASE"),F_OK);++i) usleep(100000);
        if (access(getenv("QELI_NT_RELEASE"),F_OK)) _exit(113);
    }
    return rc;
}
"""


def ns(kind):
    info=os.stat('/proc/self/ns/'+kind)
    return f'{info.st_dev}:{info.st_ino}'


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qeli',required=True,type=Path)
    ap.add_argument('--driver',required=True,type=Path)
    ap.add_argument('--artifacts',required=True,type=Path)
    ap.add_argument('--inside',choices=['tcp-create','tcp-up','udp-create','udp-up'],help=argparse.SUPPRESS)
    args=ap.parse_args();root=args.artifacts.resolve();binary=args.qeli.resolve(strict=True);driver=args.driver.resolve(strict=True)
    if not args.inside:
        if os.geteuid()!=0:raise RuntimeError('requires root in a disposable Linux lab')
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        env=dict(os.environ,QELI_NT_HOST_NET=ns('net'),QELI_NT_HOST_MNT=ns('mnt'))
        rows=[]
        for case in ['tcp-create','tcp-up','udp-create','udp-up']:
            work=root/case;work.mkdir(mode=0o700)
            cmd=['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),'--qeli',str(binary),'--driver',str(driver),'--artifacts',str(work),'--inside',case]
            with (work/'fixture.log').open('w') as log:proc=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=100)
            report=work/'result.json';rows.append(dict(case=case,exit_code=proc.returncode,result=json.loads(report.read_text()) if report.exists() else None))
            (root/'results.json').write_text(json.dumps(rows,indent=2));print(case,proc.returncode,flush=True)
        assert len(rows)==4 and all(r['exit_code']==0 for r in rows),rows
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
    cfg.write_text(f'[qeli]\nserver = 192.0.2.1:24443\nproto = {proto}\nuser = audit\npass = fixture-password\nmode = fake-tls\ndev = qnt0\nbind_static = false\ngateway = true\ndns = off\nkill_switch = true\npost_up = touch {post_up}\ntimeout = 10\n[logging]\nlevel = debug\n');cfg.chmod(0o600)
    source=root/'delay.c';source.write_text(SHIM);shim=root/'delay.so'
    run(['cc','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fPIC','-shared',source,'-o',shim,'-ldl'])
    ready=root/'ready';release=root/'release';beat=root/'heartbeat';status=root/'status.json';state=root/'state';state.mkdir(mode=0o700)
    env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_KNOWN_HOSTS=str(root/'known-hosts'),QELI_DEVICE_ID_FILE=str(root/'device-id'),QELI_CLIENT_STATUS=str(status),LD_PRELOAD=str(shim),QELI_NT_STAGE=stage,QELI_NT_READY=str(ready),QELI_NT_RELEASE=str(release))
    if stage=='up':
        wrappers=root/'wrappers';wrappers.mkdir();wrapper=wrappers/'ip'
        real=shutil.which('ip')
        wrapper.write_text('#!/usr/bin/python3\nimport os,sys,subprocess,time\nfrom pathlib import Path\n'
            +f'rc=subprocess.run([{real!r},*sys.argv[1:]]).returncode\n'
            +'if rc==0 and sys.argv[1:6]==["link","set","dev","qnt0","up"]:\n'
            +f' Path({str(ready)!r}).touch()\n until=time.monotonic()+60\n'
            +f' while not Path({str(release)!r}).exists():\n  assert time.monotonic()<until\n  time.sleep(.05)\n'
            +'sys.exit(rc)\n')
        wrapper.chmod(0o700);env['PATH']=str(wrappers)+os.pathsep+env['PATH']
    with (root/'server.log').open('w') as slog,(root/'client.log').open('w') as clog:
        server=subprocess.Popen([str(binary),'server','-c',str(servercfg)],env=dict(os.environ,QELI_CONTROL_SOCKET=str(root/'control.sock')),stdout=slog,stderr=subprocess.STDOUT)
        client=None
        try:
            wait(lambda: ':24443' in run(['ss','-lnu' if proto=='udp' else '-lnt']))
            before=snapshot('before')
            client=subprocess.Popen([shutil.which('ip'),'netns','exec','qnt-client',str(driver),str(cfg),str(beat)],env=env,stdout=clog,stderr=subprocess.STDOUT)
            wait(ready.exists,30);assert client.poll() is None
            active=snapshot('active');assert any(p['ifname']=='qnt0' for p in active['links'])
            def heartbeat():
                try:return int(beat.read_text())
                except (ValueError,FileNotFoundError):return 0
            count=heartbeat();time.sleep(.8);setup_ticks=heartbeat()-count
            assert setup_ticks>=3,setup_ticks
            initial=json.loads(status.read_text());assert initial['state']=='awaiting_network',initial
            client.send_signal(signal.SIGTERM);count=heartbeat();time.sleep(.8);stop_ticks=heartbeat()-count
            assert stop_ticks>=3 and client.poll() is None,(stop_ticks,client.poll())
            held=snapshot('held');assert any(p['ifname']=='qnt0' for p in held['links'])
            release.touch();started=time.monotonic();rc=client.wait(timeout=20);elapsed=time.monotonic()-started
            after=snapshot('after');final=json.loads(status.read_text())
            clean=after['rules']==before['rules'] and after['routes']==before['routes'] and not any(p['ifname']=='qnt0' for p in after['links']) and not list(state.rglob('*.state'))
            result=dict(case=args.inside,exit_code=rc,clean=clean,setup_ticks=setup_ticks,stop_ticks=stop_ticks,seconds_after_release=elapsed,post_up=post_up.exists(),final_state=final['state'],worker_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),driver_sha256=hashlib.sha256(driver.read_bytes()).hexdigest())
            (root/'result.json').write_text(json.dumps(result,indent=2))
            assert rc==0 and clean and not post_up.exists() and final['state']=='stopped',result
        finally:
            release.touch(exist_ok=True)
            for process in [client,server]:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=20)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=='__main__':main()
