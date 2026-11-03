#!/usr/bin/env python3
"""Resolver-file admission and real DNS allowance regression in private Linux namespaces."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

CASES = ['fifo', 'slow', 'oversized', 'glued', 'comments', 'drift', 'scoped']
CHAIN = 'QELI_KS_qeli-file0'
ADDRESSES = ['192.0.2.53', 'fd42::53', 'fd42::54']
SHIM = r'''
#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdatomic.h>
static atomic_int delayed;
ssize_t read(int fd, void *buf, size_t count) {
    ssize_t (*real)(int,void *,size_t) = dlsym(RTLD_NEXT,"read");
    char link[80], path[4096];
    snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
    ssize_t length=readlink(link,path,sizeof(path)-1);
    if (length>0) {
        path[length]=0;
        if (!strcmp(path,"/etc/resolv.conf") && !atomic_exchange(&delayed,1)) {
            int marker=open(getenv("QELI_FILE_READY"),O_WRONLY|O_CREAT|O_EXCL,0600);
            if (marker<0) _exit(113);
            close(marker);
            for (unsigned i=0;i<450;++i) usleep(100000);
        }
    }
    return real(fd,buf,count);
}
'''
PROBE = r'''
import socket,sys,json
address=sys.argv[1];s=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'wan0\0');s.settimeout(.15)
sent=received=0;errors=[]
for i in range(4):
 data=('qeli-file-'+str(i)).encode()
 try:
  s.sendto(data,(address,53));sent+=1
  if s.recv(100)==data:received+=1
 except OSError as e:errors.append(str(e))
print(json.dumps(dict(address=address,attempts=4,sent=sent,replies=received,errors=errors)))
'''


def ns(kind):
    info=os.stat('/proc/self/ns/'+kind)
    return f'{info.st_dev}:{info.st_ino}'


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qeli',required=True,type=Path)
    ap.add_argument('--baseline',required=True,type=Path)
    ap.add_argument('--artifacts',required=True,type=Path)
    ap.add_argument('--inside',choices=CASES,help=argparse.SUPPRESS)
    ap.add_argument('--version',choices=['baseline','fixed'],help=argparse.SUPPRESS)
    args=ap.parse_args();root=args.artifacts.resolve()
    binaries=dict(fixed=args.qeli.resolve(strict=True),baseline=args.baseline.resolve(strict=True))
    if not args.inside:
        if os.geteuid()!=0:raise RuntimeError('requires root in a disposable Linux lab')
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        env=dict(os.environ,QELI_FILES_HOST_NET=ns('net'),QELI_FILES_HOST_MNT=ns('mnt'))
        rows=[]
        for case in CASES:
            for version in ['baseline','fixed']:
                work=root/(case+'-'+version);work.mkdir(mode=0o700)
                cmd=['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),
                     '--qeli',str(binaries['fixed']),'--baseline',str(binaries['baseline']),'--artifacts',str(work),'--inside',case,'--version',version]
                with (work/'fixture.log').open('w') as log:p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=75)
                report=work/'result.json';rows.append(dict(case=case,version=version,exit_code=p.returncode,result=json.loads(report.read_text()) if report.exists() else None))
                (root/'results.json').write_text(json.dumps(rows,indent=2));print(case,version,p.returncode,flush=True)
        assert len(rows)==len(CASES)*2 and all(r['exit_code']==0 for r in rows),rows
        return 0
    if not os.environ.get('QELI_FILES_HOST_NET') or ns('net')==os.environ['QELI_FILES_HOST_NET'] or ns('mnt')==os.environ.get('QELI_FILES_HOST_MNT'):
        raise RuntimeError('private NET/mount/PID context is mandatory')
    commands=[]
    def run(argv):
        argv=list(map(str,argv));p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
        commands.append(dict(argv=argv,rc=p.returncode,output=p.stdout));(root/'commands.json').write_text(json.dumps(commands,indent=2))
        if p.returncode:raise RuntimeError(f'{argv}: {p.stdout}')
        return p.stdout
    def cli(*argv):return run(['ip','netns','exec','qfilec',*argv])
    run(['mount','--make-rprivate','/'])
    for target in ['/run','/var/lib','/var/log','/tmp']:run(['mount','-t','tmpfs','tmpfs',target])
    Path('/run/netns').mkdir();etc=root/'etc';etc.mkdir(mode=0o700);run(['mount','--bind',etc,'/etc/qeli'])
    run(['ip','link','set','lo','up']);run(['ip','netns','add','qfilec'])
    run(['ip','link','add','peer0','type','veth','peer','name','wan0'])
    run(['ip','link','set','wan0','netns','qfilec']);run(['ip','link','set','peer0','up'])
    cli('ip','link','set','lo','up');cli('ip','link','set','wan0','up')
    run(['ip','addr','add','192.0.2.1/24','dev','peer0']);cli('ip','addr','add','192.0.2.10/24','dev','wan0')
    run(['ip','-6','addr','add','fd42::1/64','dev','peer0','nodad']);cli('ip','-6','addr','add','fd42::10/64','dev','wan0','nodad')
    cli('ip','route','add','default','via','192.0.2.1');cli('ip','-6','route','add','default','via','fd42::1')
    mac=json.loads(run(['ip','-j','link','show','peer0']))[0]['address']
    client_mac=json.loads(cli('ip','-j','link','show','wan0'))[0]['address']
    # Neighbor discovery must not become a hidden prerequisite for the DNS probe.
    # Freeze both return neighbors before testing application UDP through the firewall.
    for family,address in [('-4','192.0.2.10'),('-6','fd42::10')]:
        run(['ip',family,'neigh','replace',address,'lladdr',client_mac,'nud','permanent','dev','peer0'])
    for address in ADDRESSES:
        family='-6' if ':' in address else '-4';prefix='/128' if family=='-6' else '/32'
        run(['ip',family,'addr','add',address+prefix,'dev','peer0']+(['nodad'] if family=='-6' else []))
        cli('ip',family,'neigh','replace',address,'lladdr',mac,'nud','permanent','dev','wan0')
    dad_deadline=time.monotonic()+5
    while ('tentative' in cli('ip','-6','addr','show','dev','wan0')
           or 'tentative' in run(['ip','-6','addr','show','dev','peer0'])):
        assert time.monotonic()<dad_deadline, 'fixture IPv6 DAD did not finish before snapshot'
        time.sleep(.05)
    for tool in ['iptables','ip6tables']:
        cli(tool,'-N','OPERATOR_SENTINEL');cli(tool,'-A','OPERATOR_SENTINEL','-j','RETURN');cli(tool,'-A','OUTPUT','-j','OPERATOR_SENTINEL')
    def snapshot(name):
        data=dict(rules=[cli(tool,'-S') for tool in ['iptables','ip6tables']],routes=[cli('ip',family,'route','show','table','all') for family in ['-4','-6']],links=json.loads(cli('ip','-j','link')))
        (root/(name+'.json')).write_text(json.dumps(data,indent=2));return data
    resolver=root/'resolver.conf'
    regular='nameserver 192.0.2.53\nnameserver fd42::53\n'
    contents=dict(slow=regular,oversized='#'+('x'*65536)+'\n'+regular,glued='nameserver192.0.2.53\nnameserverfd42::53\n',
                  comments='nameserver 192.0.2.53 # upstream\nnameserver fd42::53 ; upstream\n',drift=regular,scoped='nameserver 192.0.2.53\nnameserver fe80::53%wan0\nnameserver fd42::53%wan0\n')
    if args.inside=='fifo':os.mkfifo(resolver,0o600)
    else:resolver.write_text(contents[args.inside])
    run(['mount','--bind',resolver,'/etc/resolv.conf'])
    state=root/'state';state.mkdir(mode=0o700)
    env=dict(os.environ,STATE_DIRECTORY=str(state))
    if args.inside=='slow':
        source=root/'slow-read.c';source.write_text(SHIM);shim=root/'slow-read.so'
        run(['cc','-Wall','-Wextra','-Werror','-fPIC','-shared',source,'-o',shim,'-ldl'])
        env.update(LD_PRELOAD=str(shim),QELI_FILE_READY=str(root/'read.ready'))
    if args.inside=='drift':
        wrappers=root/'wrappers';wrappers.mkdir()
        for tool in ['iptables','ip6tables']:
            real=root/(tool+'-real');shutil.copy2(Path(shutil.which(tool)).resolve(strict=True),real)
            wrapper=wrappers/tool
            wrapper.write_text('#!/usr/bin/python3\nimport os,sys\nfrom pathlib import Path\n'
              +f'if {tool!r}=="ip6tables" and sys.argv[1:]==["-N",{CHAIN!r}]:\n'
              +f' Path({str(resolver)!r}).write_text("nameserver 192.0.2.53\\nnameserver fd42::54\\n")\n'
              +f' Path({str(root/"changed.ready")!r}).touch()\n'
              +f'os.execv({str(real)!r},[{tool!r},*sys.argv[1:]])\n')
            wrapper.chmod(0o700)
        env['QELI_IPT_DIR']=str(wrappers)
    cfg=etc/'client.ini';cfg.write_text('[qeli]\nserver = 192.0.2.2:24443\nproto = tcp\nuser = audit\npass = audit-fixture-pass\nmode = fake-tls\ndev = qeli-file0\nbind_static = false\ngateway = true\ndns = off\nkill_switch = true\ntimeout = 20\n[logging]\nlevel = debug\n');cfg.chmod(0o600)
    selected=selectors.DefaultSelector();received=[];stop=threading.Event()
    for address in ADDRESSES:
        sock=socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,socket.SOCK_DGRAM);sock.bind((address,53));selected.register(sock,selectors.EVENT_READ,address)
    def echo():
        while not stop.is_set():
            for key,_ in selected.select(.1):
                data,peer=key.fileobj.recvfrom(1024);received.append(key.data);key.fileobj.sendto(data,peer)
    thread=threading.Thread(target=echo);thread.start()
    preflight=[]
    for address in ADDRESSES:
        probe=json.loads(cli(sys.executable,'-c',PROBE,address));preflight.append(probe)
        assert probe['sent']==probe['replies']==4 and not probe['errors'],probe
    (root/'preflight.json').write_text(json.dumps(preflight,indent=2))
    before=snapshot('before');binary=binaries[args.version];probes=[];forced=False
    with (root/'client.log').open('w') as log:
        client=subprocess.Popen(['ip','netns','exec','qfilec',str(binary),'client','-c',str(cfg)],env=env,stdout=log,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+25
            while True:
                assert client.poll() is None,(root/'client.log').read_text()
                rules=[cli(tool,'-S') for tool in ['iptables','ip6tables']]
                if args.inside=='slow':ready=(root/'read.ready').exists()
                elif args.inside=='fifo' and args.version=='baseline':ready=any(CHAIN in r for r in rules)
                else:ready=all(f'-A {CHAIN} -j DROP' in r and f'-A OUTPUT -j {CHAIN}' in r for r in rules)
                if ready:break
                assert time.monotonic()<deadline,'client readiness timeout';time.sleep(.03)
            active=snapshot('active')
            if args.inside=='slow':assert any(CHAIN in r for r in active['rules'])==(args.version=='baseline')
            if args.inside=='drift':assert (root/'changed.ready').exists()
            if args.inside!='slow' and not (args.inside=='fifo' and args.version=='baseline'):
                for address in ADDRESSES:
                    n=len(received);probe=json.loads(cli(sys.executable,'-c',PROBE,address));probe['received']=received[n:].count(address)
                    if args.inside in ['fifo','oversized','glued']:allowed=args.version=='baseline' and address in ADDRESSES[:2]
                    elif args.inside=='scoped':allowed=address==ADDRESSES[0]
                    elif args.inside=='comments':allowed=args.version=='fixed' and address in ADDRESSES[:2]
                    else:allowed=address in (ADDRESSES[:2] if args.version=='fixed' else [ADDRESSES[0],ADDRESSES[2]])
                    probe['expected_allowed']=allowed;probes.append(probe)
                    if allowed:assert probe['sent']==probe['replies']==probe['received']==4 and not probe['errors'],probe
                    else:assert probe['replies']==probe['received']==0 and len(probe['errors'])==4 and all(e.startswith('[Errno 1]') for e in probe['errors']),probe
            started=time.monotonic();client.send_signal(signal.SIGTERM)
            try:rc=client.wait(timeout=3)
            except subprocess.TimeoutExpired:forced=True;client.kill();rc=client.wait(timeout=5)
            elapsed=time.monotonic()-started
        finally:
            if client.poll() is None:client.kill();client.wait(timeout=5)
            stop.set();thread.join(timeout=2)
            for key in list(selected.get_map().values()):key.fileobj.close()
            selected.close()
    after=snapshot('after');clean=after['rules']==before['rules'] and after['routes']==before['routes'] and not list(state.rglob('*.state')) and all(p['ifname']!='qeli-file0' for p in after['links'])
    result=dict(case=args.inside,version=args.version,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),exit_code=rc,forced_kill=forced,stop_seconds=elapsed,clean=clean,probes=probes)
    (root/'result.json').write_text(json.dumps(result,indent=2))
    if args.version=='baseline' and args.inside in ['fifo','slow']:assert forced,result
    else:assert rc==0 and not forced and clean,result
    return 0


if __name__=='__main__':sys.exit(main())
