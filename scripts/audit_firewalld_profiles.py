#!/usr/bin/env python3
"""Real private firewalld fixture for the four-profile IPv6 lifecycle audit.

Used only after audit_release_matrix_lab.ISOLATED; package files are read-only.
The nft/legacy wrappers execute real copied multicall binaries, never mock rules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time


def normalize(value):
    if isinstance(value, dict):
        return {k:normalize(v) for k,v in value.items() if k not in ('handle','packets','bytes')}
    if isinstance(value,list):
        return [normalize(v) for v in value]
    return value


class MixedFirewall:
    def __init__(self, root, package, ipv4, ipv6, run, record):
        self.root, self.package, self.run, self.record = root, Path(package).resolve(strict=True), run, record
        self.backends = [ipv4,ipv6]
        self.processes=[]
        self.real={}
        self.ready=False
        for backend in ('nft','legacy'):
            source=Path(shutil.which('iptables-'+backend)).resolve(strict=True)
            self.real[backend]=root/('xtables-real-'+backend)
            shutil.copy2(source,self.real[backend])
        (root/'backend-inputs.json').write_text(json.dumps(dict(backends=self.backends,binaries={k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in self.real.items()}),indent=2))
        wrapper=root/'xtables-mixed-wrapper'
        wrapper.write_text('#!/usr/bin/python3\nimport os,sys\n'
                           +f'root={str(root)!r}\nbackends={self.backends!r}\n'
                           +'name=os.path.basename(sys.argv[0])\nbackend=backends[int(name.startswith("ip6"))]\n'
                           +'os.execv(root+"/xtables-real-"+backend,[name,*sys.argv[1:]])\n')
        wrapper.chmod(0o700)
        for target in {Path(shutil.which(tool)).resolve(strict=True) for tool in ('iptables','ip6tables')}:
            run(['mount','--bind',str(wrapper),str(target)])
        for family,tool in enumerate(('iptables','ip6tables')):
            version=run([tool,'--version']).stdout
            record('actual '+tool+' '+self.backends[family]+' backend', ('nf_tables' if self.backends[family]=='nft' else 'legacy') in version)

    def real_run(self, backend, argv):
        return self.run(argv,executable=str(self.real[backend]))

    def launch(self, argv, label, env=None):
        with (self.root/(label+'.log')).open('w') as log:
            child=subprocess.Popen(argv,env=env,stdout=log,stderr=subprocess.STDOUT)
        self.processes.append(child)
        return child

    def wait(self, predicate):
        end=time.monotonic()+25
        while not predicate():
            assert time.monotonic()<end and all(p.poll() is None for p in self.processes), 'private firewalld fixture not ready; inspect logs'
            time.sleep(.1)

    def command(self, *args):
        return self.run(self.fwcmd+list(args),env=self.env)

    def prepare(self):
        run=self.run;root=self.root;p=self.package
        run(['ip','netns','add','qfw-peer'])
        run(['ip','link','add','probe0','type','veth','peer','name','peer0'])
        run(['ip','link','set','peer0','netns','qfw-peer'])
        for cmd in (['ip','link','set','probe0','up'],['ip','addr','add','198.18.0.1/24','dev','probe0'],['ip','-6','addr','add','2001:db8:ee::1/64','dev','probe0','nodad']):run(cmd)
        for cmd in (['ip','link','set','lo','up'],['ip','link','set','peer0','up'],['ip','addr','add','198.18.0.2/24','dev','peer0'],['ip','-6','addr','add','2001:db8:ee::2/64','dev','peer0','nodad']):run(['ip','netns','exec','qfw-peer',*cmd])
        self.launch([sys.executable,str(Path(__file__).resolve()),'echo','--root',str(root)],'packet-echo')
        self.wait(lambda:(root/'echo.ready').exists())
        for backend in ('nft','legacy'):
            for tool in ('iptables','ip6tables'):
                for table in ('nat','mangle'):
                    self.real_run(backend,[tool,'-t',table,'-N','audit-prime']);self.real_run(backend,[tool,'-t',table,'-X','audit-prime'])
                    # iptables-save can print synthetic builtin headers before nft
                    # hooks actually exist. Prime every hook Qeli uses, then retain
                    # a strict native nft comparison including empty base chains.
                    for chain in (('FORWARD',) if table=='mangle' else ('PREROUTING','POSTROUTING')):
                        spec=[tool,'-t',table,'-A',chain,'-m','comment','--comment','audit-prime-builtin','-j','RETURN']
                        self.real_run(backend,spec)
                        spec[3]='-D';self.real_run(backend,spec)
                self.real_run(backend,[tool,'-I','INPUT','1','-i','probe0','-p','udp','--dport','49000:49001','-m','comment','--comment','audit-operator-probe','-j','ACCEPT'])
                if tool == 'ip6tables':
                    self.real_run(backend,[tool,'-I','INPUT','1','-i','probe0','-p','ipv6-icmp','-m','comment','--comment','audit-operator-ndp','-j','ACCEPT'])
                self.real_run(backend,[tool,'-A','FORWARD','-m','comment','--comment','audit-opposite-kept','-j','DROP'])
        run(['nft','add','table','inet','audit_operator'])
        run(['nft','add','chain','inet','audit_operator','forward','{ type filter hook forward priority 20; policy accept; }'])
        run(['nft','add','rule','inet','audit_operator','forward','counter','accept','comment','"audit-native-kept"'])
        self.env=dict(os.environ,PYTHONPATH=str(p/'usr/lib/python3/dist-packages'),GI_TYPELIB_PATH=str(p/'usr/lib/x86_64-linux-gnu/girepository-1.0'),LD_LIBRARY_PATH=str(p/'usr/lib/x86_64-linux-gnu'),DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/qeli-four-profile-bus')
        busconf=root/'dbus.conf';busconf.write_text('<busconfig><type>system</type><listen>unix:path=/run/qeli-four-profile-bus</listen><auth>EXTERNAL</auth><policy context="default"><allow user="root"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>')
        self.launch(['dbus-daemon','--config-file='+str(busconf),'--nofork','--nopidfile'],'dbus')
        self.wait(lambda:Path('/run/qeli-four-profile-bus').exists())
        config=root/'firewalld-config';config.mkdir(mode=0o700)
        (config/'firewalld.conf').write_text('DefaultZone=public\nFirewallBackend=nftables\nCleanupOnExit=yes\n')
        self.launch([sys.executable,str(p/'usr/sbin/firewalld'),'--nofork','--nopid','--system-config',str(config),'--default-config',str(p/'usr/lib/firewalld'),'--log-target','console'],'firewalld',self.env)
        self.fwcmd=[sys.executable,str(p/'usr/bin/firewall-cmd')]
        self.wait(lambda:run(self.fwcmd+['--state'],False,env=self.env).returncode==0)
        self.record('real private firewalld public zone starts',True,self.command('--version').stdout.strip())
        self.command('--permanent','--zone=public','--add-interface=probe0')
        self.command('--permanent','--zone=public','--add-port=49000-49001/udp')
        self.command('--permanent','--new-policy=auditIngress')
        self.command('--permanent','--policy=auditIngress','--add-ingress-zone=public')
        self.command('--permanent','--policy=auditIngress','--add-egress-zone=HOST')
        self.command('--permanent','--policy=auditIngress','--set-priority=-500')
        self.rich='rule port port="49001" protocol="udp" drop'
        self.command('--permanent','--policy=auditIngress','--add-rich-rule='+self.rich)
        self.command('--reload')
        self.ready=True
        self.probe('before-worker',False)
        self.command('--reload')
        # Wait for original auto link-local addresses before strict route snapshots.
        self.wait(lambda:'scope link' in run(['ip','-6','addr','show','dev','probe0']).stdout and 'tentative' not in run(['ip','-6','addr','show','dev','probe0']).stdout)

    def snapshot(self):
        native=json.loads(self.run(['nft','-j','list','ruleset']).stdout)['nftables']
        native=[normalize(o) for o in native if 'metainfo' not in o]
        def group(obj):
            kind,body=next(iter(obj.items()))
            return (body.get('family',''),body.get('table',body.get('name','')),kind,body.get('chain',body.get('name','')))
        # Stable grouping preserves order of rules inside each chain.
        native.sort(key=group)
        other={}
        import re
        for backend in ('nft','legacy'):
            for tool in ('iptables-save','ip6tables-save'):
                output=self.real_run(backend,[tool]).stdout
                other[backend+':'+tool]=re.sub(r'\[\d+:\d+\]','[COUNTERS]','\n'.join(x for x in output.splitlines() if not x.startswith('#')))
        return dict(native=native,all_backends=other)

    def probe(self, label, both):
        for family,address in ((4,'198.18.0.1'),(6,'2001:db8:ee::1')):
            for port in (49000,49001):
                expect=both or port==49000
                output=self.root/f'probe-{label}-v{family}-{port}.json'
                self.run(['ip','netns','exec','qfw-peer',sys.executable,str(Path(__file__).resolve()),'query','--address',address,'--port',str(port),'--expect','yes' if expect else 'no','--output',str(output)])
                data=json.loads(output.read_text())
                self.record(f'{label} IPv{family} public-policy UDP {port}',data['sent']==3 and data['replies']==(3 if expect else 0),data)

    def reload(self, expected, label):
        self.command('--reload')
        self.record(label+' keeps exact Qeli and foreign firewall',self.snapshot()==expected)
        self.probe(label,False)

    def policy_transition(self, expected):
        self.command('--permanent','--policy=auditIngress','--remove-rich-rule='+self.rich)
        self.command('--reload')
        changed=self.snapshot()
        def without_firewalld(value):
            return dict(all_backends=value['all_backends'],native=[o for o in value['native'] if next(iter(o.values())).get('table',next(iter(o.values())).get('name'))!='firewalld'])
        self.record('policy change only replaces firewalld table',without_firewalld(changed)==without_firewalld(expected))
        self.probe('policy-open',True)
        self.command('--permanent','--policy=auditIngress','--add-rich-rule='+self.rich)
        self.command('--reload')
        self.record('policy restore keeps original exact firewall',self.snapshot()==expected)
        self.probe('policy-restored',False)

    def restart_equivalent(self, before, after):
        # A new generation may schedule independent profile installers in a
        # different order. Preserve order inside each profile/table/chain and
        # independently require all protective DROP rules before any permits.
        import re
        def specs(value):
            out={}
            for family,save in value['all_backends'].items():
                table=''
                for line in save.splitlines():
                    if line.startswith('*'):table=line
                    tag=re.search(r'qeli-nat:([^\s"]+)',line)
                    key=(family,table,line.split()[1] if line.startswith('-A ') else '',tag.group(1) if tag else 'foreign')
                    out.setdefault(key,[]).append(line)
                forward=[x for x in save.splitlines() if x.startswith('-A FORWARD')]
                first=next((i for i,x in enumerate(forward) if '-j ACCEPT' in x),len(forward))
                assert all(i<first for i,x in enumerate(forward) if 'qeli-nat:' in x and '-j DROP' in x)
            return out
        def external(value):
            return [o for o in value['native'] if next(iter(o.values())).get('table',next(iter(o.values())).get('name')) in ('audit_operator','firewalld')]
        return specs(before)==specs(after) and external(before)==external(after)

    def close(self):
        for child in reversed(self.processes):
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:child.wait(timeout=15)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        self.run(['ip','netns','del','qfw-peer'],False)


def echo(root):
    selector=selectors.DefaultSelector()
    for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
        for port in (49000,49001):
            sock=socket.socket(family,socket.SOCK_DGRAM)
            if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((address,port));selector.register(sock,selectors.EVENT_READ)
    (Path(root)/'echo.ready').touch()
    while True:
        for key,_ in selector.select():
            data,peer=key.fileobj.recvfrom(65535);key.fileobj.sendto(data,peer)


def query(args):
    family=socket.AF_INET6 if ':' in args.address else socket.AF_INET
    sent,replies=0,0
    for i in range(3):
        with socket.socket(family,socket.SOCK_DGRAM) as sock:
            sock.settimeout(.25 if args.expect=='no' else 2)
            token=f'{args.address}-{args.port}-{i}'.encode();sock.sendto(token,(args.address,args.port));sent+=1
            try:
                data,peer=sock.recvfrom(4096)
                assert data==token and peer[0]==args.address and peer[1]==args.port
                replies+=1
            except TimeoutError:pass
    result=dict(address=args.address,port=args.port,sent=sent,replies=replies,expected=args.expect)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    assert replies==(3 if args.expect=='yes' else 0),result


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='cmd',required=True)
    ep=sub.add_parser('echo');ep.add_argument('--root',required=True)
    qp=sub.add_parser('query')
    for name in ('address','expect','output'):qp.add_argument('--'+name,required=True)
    qp.add_argument('--port',type=int,required=True)
    args=ap.parse_args()
    if args.cmd=='echo':echo(args.root)
    else:query(args)
