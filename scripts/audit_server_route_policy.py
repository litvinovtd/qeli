#!/usr/bin/env python3
"""Real authenticated NAT44/NAT66 and IPv6 route packets during route changes.
Run only through audit_release_matrix_lab.ISOLATED. All peers are private netns.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import re
import signal
import socket
import subprocess
import sys
import time
from audit_firewalld_profiles import MixedFirewall


def echo(args):
    selector = selectors.DefaultSelector()
    for address in args.addresses.split(','):
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6: sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, 45000)); selector.register(sock, selectors.EVENT_READ)
    Path(args.ready).touch()
    while True:
        for key, _ in selector.select():
            data, peer = key.fileobj.recvfrom(4096)
            reply = json.dumps(dict(token=data.decode(), source=peer[0], peer=args.peer)).encode()
            key.fileobj.sendto(reply, peer)


def query(args):
    family = socket.AF_INET6 if ':' in args.address else socket.AF_INET
    replies = []
    for i in range(3):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            if args.bind: sock.bind((args.bind, 0))
            sock.settimeout(.35 if args.expect == 'no' else 3)
            token = f'{args.label}-{i}-{time.monotonic_ns()}'
            sock.sendto(token.encode(), (args.address, 45000))
            try:
                data, peer = sock.recvfrom(4096); reply = json.loads(data)
                assert peer[0] == args.address and peer[1] == 45000 and reply['token'] == token
                assert reply['source'] == args.source and reply['peer'] == args.peer, reply
                replies.append(reply)
            except TimeoutError: pass
    result = dict(label=args.label, address=args.address, bind=args.bind, sent=3, replies=replies,
                  expected=args.expect, expected_source=args.source, expected_peer=args.peer)
    Path(args.output).write_text(json.dumps(result, indent=2)+'\n')
    assert len(replies) == (3 if args.expect == 'yes' else 0), result


def main(args):
    for kind in ('net', 'mnt', 'pid'):
        assert os.readlink('/proc/self/ns/'+kind) != getattr(args, 'parent_'+kind)
    binary = Path(args.qeli).resolve(strict=True)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256
    root = Path(args.artifacts); root.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks, commands, children, namespaces = [], [], [], []
    completed = False

    def run(argv, check=True, input=None, env=None, executable=None):
        p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=30, env=env, executable=executable)
        commands.append(dict(argv=argv, executable=executable, exit_code=p.returncode, output=p.stdout+p.stderr))
        (root/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        if check: assert p.returncode == 0, (argv, p.stdout, p.stderr)
        return p

    def ns(name, argv, **kwargs):
        return run(['ip', 'netns', 'exec', name, *argv], **kwargs)

    def record(name, ok, detail=None):
        checks.append(dict(name=name, passed=bool(ok), detail=detail))
        (root/'checks.json').write_text(json.dumps(checks, indent=2)+'\n')
        assert ok, (name, detail)
        print('PASS', name, flush=True)

    def until(predicate):
        end = time.monotonic()+35
        while not predicate():
            assert time.monotonic()<end and all(p.poll() is None for p in children), 'fixture readiness failed; inspect logs'
            time.sleep(.1)

    def spawn(name, argv, label):
        with (root/(label+'.log')).open('w') as log:
            child = subprocess.Popen((['ip','netns','exec',name] if name else [])+argv, stdout=log, stderr=subprocess.STDOUT)
        children.append(child); return child

    def stop(child):
        child.send_signal(signal.SIGTERM); rc=child.wait(timeout=45); children.remove(child); return rc

    def packet(label, namespace, address, source, peer, expect=True, bind=None):
        output=root/('packet-'+label+'.json')
        argv=[sys.executable,str(Path(__file__).resolve()),'query','--label',label,'--address',address,
              '--source',source,'--peer',peer,'--expect','yes' if expect else 'no','--output',str(output)]
        if bind: argv+=['--bind',bind]
        (ns(namespace,argv) if namespace else run(argv))
        data=json.loads(output.read_text())
        record(label,len(data['replies'])==(3 if expect else 0), data)

    try:
        mixed=MixedFirewall(root,args.package,args.ipv4,args.ipv6,run,record)
        run(['ip','link','set','lo','up'])
        for backend in ('nft','legacy'):
            for tool in ('iptables','ip6tables'):
                for table in ('filter','nat','mangle'):
                    mixed.real_run(backend,[tool,'-t',table,'-N','audit-prime']);mixed.real_run(backend,[tool,'-t',table,'-X','audit-prime'])
                    for chain in (('FORWARD',) if table!='nat' else ('PREROUTING','POSTROUTING')):
                        spec=[tool,'-t',table,'-A',chain,'-m','comment','--comment','audit-prime-builtin','-j','RETURN']
                        mixed.real_run(backend,spec);spec[3]='-D';mixed.real_run(backend,spec)
                mixed.real_run(backend,[tool,'-A','FORWARD','-m','comment','--comment','audit-foreign-kept','-j','RETURN'])
        links=[('qwn','ctrl0','cn0','10.46.1.1','10.46.1.2','fd60:1::1','fd60:1::2'),
               ('qwr','ctrl1','cr0','10.46.2.1','10.46.2.2','fd60:2::1','fd60:2::2'),
               ('qwa','wan0','a0','198.18.60.2','198.18.60.1','fd60:a::2','fd60:a::1'),
               ('qwb','wan1','b0','198.18.61.2','198.18.61.1','fd60:b::2','fd60:b::1'),
               ('qwl','lan0','l0','10.50.0.2','10.50.0.1','fd60:c::2','fd60:c::1')]
        for name,host,guest,h4,p4,h6,p6 in links:
            run(['ip','netns','add',name]);namespaces.append(name)
            run(['ip','link','add',host,'type','veth','peer','name',guest]);run(['ip','link','set',guest,'netns',name])
            run(['ip','link','set',host,'up']);ns(name,['ip','link','set','lo','up']);ns(name,['ip','link','set',guest,'up'])
            for addr,flag in ((h4+'/24',[]),(h6+'/64',['-6'])):run(['ip',*flag,'addr','add',addr,'dev',host,*(['nodad'] if flag else [])])
            for addr,flag in ((p4+'/24',[]),(p6+'/64',['-6'])):ns(name,['ip',*flag,'addr','add',addr,'dev',guest,*(['nodad'] if flag else [])])
            for iface in ('all',host):Path('/proc/sys/net/ipv4/conf/'+iface+'/rp_filter').write_text('0\n')
            ns(name,[sys.executable,'-c',"from pathlib import Path;[p.write_text('0\\n') for p in Path('/proc/sys/net/ipv4/conf').glob('*/rp_filter')]"])
            if name in ('qwn','qwr'):
                ns(name,['ip','route','add','default','via',h4]);ns(name,['ip','-6','route','add','default','via',h6])
            else:
                ns(name,['ip','route','add','10.86.0.0/24','via',h4])
                if args.ipv4_gateway:ns(name,['ip','route','add','10.87.0.0/24','via',h4])
                for prefix in ('fd86::/64','fd87::/64'):ns(name,['ip','-6','route','add',prefix,'via',h6])
        for name in ('qwa','qwb'):
            ns(name,['ip','addr','add','203.0.113.99/32','dev','lo']);ns(name,['ip','-6','addr','add','fd60:d::99/128','dev','lo'])
        for address in ('172.16.0.1','192.168.50.1','100.64.0.1','192.0.2.1'):
            ns('qwl',['ip','addr','add',address+'/32','dev','lo']);run(['ip','route','add',address+'/32','via','10.50.0.1','dev','lan0'])
        gateway_before = None
        def gateway_network():
            return dict(forwarding=ns('qwn',['cat','/proc/sys/net/ipv4/ip_forward']).stdout,
                        firewall={tool: ns('qwn',[tool]).stdout for tool in ('iptables-save','iptables-legacy-save')},
                        routes=ns('qwn',['ip','-4','route','show','table','all']).stdout,
                        rp_filter=ns('qwn',[sys.executable,'-c',"from pathlib import Path;import json;print(json.dumps({str(p):p.read_text() for p in Path('/proc/sys/net/ipv4/conf').glob('*/rp_filter')},sort_keys=True))"]).stdout)
        if args.ipv4_gateway:
            run(['ip','netns','add','qwg']);namespaces.append('qwg')
            ns('qwn',['ip','link','add','lan0','type','veth','peer','name','gl0'])
            ns('qwn',['ip','link','set','gl0','netns','qwg'])
            ns('qwn',['ip','addr','add','192.168.77.1/24','dev','lan0'])
            ns('qwn',['ip','link','set','lan0','up'])
            ns('qwg',['ip','link','set','lo','up']);ns('qwg',['ip','link','set','gl0','up'])
            ns('qwg',['ip','addr','add','192.168.77.2/24','dev','gl0'])
            ns('qwg',['ip','route','add','default','via','192.168.77.1'])
            for table,chain in (('filter','FORWARD'),('nat','POSTROUTING'),('mangle','FORWARD')):
                spec=['iptables','-t',table,'-A',chain,'-m','comment','--comment','audit-prime','-j','RETURN']
                ns('qwn',spec);spec[3]='-D';ns('qwn',spec)
            ns('qwn',['iptables','-P','FORWARD','DROP'])
            ns('qwn',['iptables','-A','FORWARD','-m','comment','--comment','qeli-gw-nat-foreign','-j','RETURN'])
            gateway_before=gateway_network()
            (root/'gateway-before.json').write_text(json.dumps(gateway_before,indent=2))
        for name, addresses in [('qwa','203.0.113.99,fd60:d::99'),('qwb','203.0.113.99,fd60:d::99'),('qwl','10.50.0.1,172.16.0.1,192.168.50.1,100.64.0.1,192.0.2.1,fd60:c::1')]:
            ready=root/(name+'.ready')
            spawn(name,[sys.executable,str(Path(__file__).resolve()),'echo','--peer',name,'--ready',str(ready),'--addresses',addresses],'echo-'+name)
            until(ready.exists)
        run(['ip','route','add','default','via','198.18.60.1','dev','wan0'])
        run(['ip','-6','route','add','default','via','fd60:a::1','dev','wan0'])
        until(lambda:'tentative' not in run(['ip','-6','addr']).stdout and 'scope link' in run(['ip','-6','addr','show','dev','wan0']).stdout)

        def network():
            return dict(firewall=mixed.snapshot(),rules4=run(['ip','-4','rule','show']).stdout,rules6=run(['ip','-6','rule','show']).stdout,routes4=run(['ip','-4','route','show','table','all']).stdout,
                        routes6=run(['ip','-6','route','show','table','all']).stdout,links=json.loads(run(['ip','-j','link']).stdout),
                        sysctls={n:Path('/proc/sys/net/'+n).read_text() for n in ('ipv4/ip_forward','ipv6/conf/all/forwarding','ipv6/conf/default/forwarding','ipv6/conf/wan0/accept_ra')})
        before=network();(root/'network-before.json').write_text(json.dumps(before,indent=2))
        packet('direct-v4-positive',None,'203.0.113.99','198.18.60.2','qwa')
        packet('direct-v6-positive',None,'fd60:d::99','fd60:a::2','qwa')
        state=root/'state';state.mkdir(mode=0o700);cfg=root/'server.conf';users=root/'users.conf';users.write_text('');users.chmod(0o600)
        common=f'''[auth]
users_file = {users}
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
'''
        text=common
        for mode,idx,transport,pool in [('nat66',0,'tcp','fd86'),('route',1,'udp','fd87')]:
            text+=f'''[profile:{mode}]
identity_key = {root}/{mode}.key
bind.address = 10.46.{idx+1}.1
bind.port = {27443+idx}
bind.transport = {transport}
tun.name = vpns{idx}
tun.ip_mode = {'dual' if idx==0 or args.ipv4_gateway else 'ipv6'}
tun.address = 10.{86+idx}.0.1
tun.ipv6_address = {pool}::1
tun.queues = 1
pool.cidr = 10.{86+idx}.0.0/24
pool.ipv6.cidr = {pool}::/64
routing.nat.enabled = {'true' if idx==0 else 'false'}
routing.nat.interface =
routing.forward_private = {'true' if args.ipv4_gateway and idx==1 else 'false'}
routing.ipv6.mode = {mode}
routing.ipv6.interface =
routing.ipv6.ndp_proxy = off
routing.post_up = printf up >> {root}/up-{mode}
dns.enabled = false
roaming.enabled = false
obf.mode = fake-tls
'''
        cfg.write_text(text);cfg.chmod(0o600)
        for mode,idx,pool in [('nat66',0,'fd86'),('route',1,'fd87')]:
            argv=[str(binary),'add-client',mode+'-user','--password-stdin','--profiles',mode,'--static-ipv6',pool+'::2','-c',str(cfg)]
            if idx==0 or args.ipv4_gateway:argv+=['--static-ip',f'10.{86+idx}.0.2']
            run(argv,input='route-fixture-pass\n')
        run([str(binary),'check-config','-c',str(cfg)])
        worker=spawn(None,['env','STATE_DIRECTORY='+str(state),'QELI_CONTROL_SOCKET='+str(root/'control.sock'),str(binary),'_worker','-c',str(cfg)],'worker')
        until(lambda:all((root/('up-'+m)).exists() for m in ('nat66','route')))
        record('two real NAT44/NAT66 TCP and route UDP profiles ready',worker.poll() is None)
        clients=[]
        include='203.0.113.99/32,fd60:d::99/128,10.50.0.1/32,172.16.0.1/32,192.168.50.1/32,100.64.0.1/32,192.0.2.1/32,fd60:c::1/128'
        for mode,idx,name,transport,pool in [('nat66',0,'qwn','tcp','fd86'),('route',1,'qwr','udp','fd87')]:
            client_include=include if idx==0 or args.ipv4_gateway else 'fd60:d::99/128,fd60:c::1/128'
            gateway_options='gateway_nat = true\nlan_subnet = 192.168.77.0/24\n' if args.ipv4_gateway and idx==0 else ''
            c=root/('client-'+mode+'.conf');c.write_text(f'''[qeli]
server = 10.46.{idx+1}.1:{27443+idx}
proto = {transport}
roaming = off
user = {mode}-user
pass = route-fixture-pass
mode = fake-tls
dev = vpnc
bind_static = false
gateway = false
{gateway_options}include = {client_include}
ipv6 = required
dns = off
kill_switch = false
timeout = 8
[logging]
level = info
''');c.chmod(0o600)
            cs=root/('client-state-'+mode);cs.mkdir(mode=0o700)
            client=spawn(name,['env','STATE_DIRECTORY='+str(cs),'QELI_KNOWN_HOSTS='+str(root/('known-'+mode)),'QELI_DEVICE_ID_FILE='+str(root/('device-'+mode)),str(binary),'client','-c',str(c)],'client-'+mode);clients.append(client)
            until(lambda:pool+'::2/128' in ns(name,['ip','-6','addr','show','dev','vpnc'],check=False).stdout and 'dev vpnc' in ns(name,['ip','-6','route','get','fd60:d::99'],check=False).stdout)
            record(mode+' authenticated exact IPv6 address',True)
        active=network();(root/'network-active.json').write_text(json.dumps(active,indent=2))
        record('NAT pool MASQUERADE and route source-preservation rules installed','MASQUERADE' in run(['ip6tables-save']).stdout and 'qeli-nat:route' in run(['ip6tables-save']).stdout)

        def guard_packets(ipv6):
            text=run(['ip6tables' if ipv6 else 'iptables','-n','-v','-x','-L','FORWARD']).stdout
            rows=[line.split() for line in text.splitlines() if 'qeli-nat:nat66' in line and 'vpns0' in line and '!wan0' in line and 'DROP' in line]
            assert len(rows)==1, text
            return int(rows[0][0])
        def nat(label,ipv6,source,peer,expect=True,address=None):
            guarded = not expect and label != 'administrator-drop-denies-rfc1918-lan'
            previous=guard_packets(ipv6) if guarded else None
            packet(label,'qwn',address or ('fd60:d::99' if ipv6 else '203.0.113.99'),source,peer,expect,'fd86::2' if ipv6 else '10.86.0.2')
            if guarded:
                delta=guard_packets(ipv6)-previous
                record(label+' hits managed DROP',delta>=3,dict(counter_delta=delta))
        def route(label,peer,address='fd60:d::99'):
            packet(label,'qwr',address,'fd87::2',peer,True,'fd87::2')
        nat('selected-wan-nat44',False,'198.18.60.2','qwa');nat('selected-wan-nat66',True,'fd60:a::2','qwa');route('selected-wan-route','qwa')
        for address in ('10.50.0.1','172.16.0.1','192.168.50.1'):nat('lan-source-'+address,False,'10.86.0.2','qwl',True,address)
        for address in ('100.64.0.1','192.0.2.1'):packet('lan-public-positive-'+address,None,address,'10.50.0.2','qwl')
        for address in ('100.64.0.1','192.0.2.1'):nat('non-rfc1918-block-'+address,False,'10.86.0.2','qwl',False,address)
        nat('nat66-lan-off-wan-block',True,'fd86::2','qwl',False,'fd60:c::1');route('route-lan-source','qwl','fd60:c::1')
        if args.ipv4_gateway:
            gw_rules=ns('qwn',['iptables-save']).stdout
            record('gateway exact LAN MASQUERADE with explicit permits and MSS',all(x in gw_rules for x in ('192.168.77.0/24','-o vpnc','MASQUERADE','TCPMSS','qeli-gw-nat')))
            record('gateway enables actual IPv4 forwarding',ns('qwn',['cat','/proc/sys/net/ipv4/ip_forward']).stdout.strip()=='1')
            packet('gateway-lan-double-nat-wan','qwg','203.0.113.99','198.18.60.2','qwa',True,'192.168.77.2')
            packet('gateway-lan-nat-private-server-network','qwg','10.50.0.1','10.86.0.2','qwl',True,'192.168.77.2')
            packet('forward-private-preserves-v4-source','qwr','10.50.0.1','10.87.0.2','qwl',True,'10.87.0.2')
        run(['iptables','-P','FORWARD','DROP'])
        if args.ipv4_gateway:
            packet('forward-private-explicit-permit-over-drop-policy','qwr','10.50.0.1','10.87.0.2','qwl',True,'10.87.0.2')
        nat('administrator-drop-denies-rfc1918-lan',False,'10.86.0.2','qwl',False,'10.50.0.1')
        nat('administrator-drop-keeps-selected-nat44',False,'198.18.60.2','qwa')
        run(['iptables','-P','FORWARD','ACCEPT'])
        record('temporary administrator policy fully restored',mixed.snapshot()==active['firewall'])
        run(['ip','route','replace','default','via','198.18.61.1','dev','wan1']);run(['ip','-6','route','replace','default','via','fd60:b::1','dev','wan1'])
        packet('second-wan-v4-positive',None,'203.0.113.99','198.18.61.2','qwb')
        packet('second-wan-v6-positive',None,'fd60:d::99','fd60:b::2','qwb')
        nat('changed-default-nat44-blocks-off-wan',False,'10.86.0.2','qwb',False)
        nat('changed-default-nat66-blocks-off-wan',True,'fd86::2','qwb',False);route('changed-default-route-follows-kernel','qwb')
        record('default change preserves selected WAN firewall generation',mixed.snapshot()==active['firewall'])
        for ipv6,prefix,via in [(False,'10.86.0.2/32','198.18.60.1'),(True,'fd86::2/128','fd60:a::1')]:
            flag=['-6'] if ipv6 else []
            run(['ip',*flag,'route','add','table','100','default','via',via,'dev','wan0'])
            run(['ip',*flag,'rule','add','priority','1000','from',prefix,'lookup','100'])
        nat('policy-selected-wan-nat44',False,'198.18.60.2','qwa');nat('policy-selected-wan-nat66',True,'fd60:a::2','qwa');route('policy-only-nat-source-route-still-wan1','qwb')
        for flag in ([],['-6']):run(['ip',*flag,'rule','del','priority','1000']);run(['ip',*flag,'route','flush','table','100'])
        run(['ip','route','replace','default','via','198.18.60.1','dev','wan0']);run(['ip','-6','route','replace','default','via','fd60:a::1','dev','wan0'])
        nat('restored-default-nat44',False,'198.18.60.2','qwa');nat('restored-default-nat66',True,'fd60:a::2','qwa');route('restored-default-route','qwa')
        for ipv6,prefix,via in [(False,'10.86.0.2/32','198.18.61.1'),(True,'fd86::2/128','fd60:b::1')]:
            flag=['-6'] if ipv6 else []
            run(['ip',*flag,'route','add','table','100','default','via',via,'dev','wan1']);run(['ip',*flag,'rule','add','priority','1000','from',prefix,'lookup','100'])
        nat('policy-off-wan-nat44-block',False,'10.86.0.2','qwb',False);nat('policy-off-wan-nat66-block',True,'fd86::2','qwb',False)
        for flag in ([],['-6']):run(['ip',*flag,'rule','del','priority','1000']);run(['ip',*flag,'route','flush','table','100'])
        record('all route and policy changes restore live generation',network()==active)
        record('both authenticated clients retain their processes',all(c.poll() is None for c in clients))
        for i,c in enumerate(clients):record('client clean stop '+str(i),stop(c)==0)
        if args.ipv4_gateway:
            gateway_after=gateway_network()
            (root/'gateway-after.json').write_text(json.dumps(gateway_after,indent=2))
            def stable_gateway(snapshot):
                return {**snapshot,'firewall':{tool:re.sub(r'\[\d+:\d+\]','[COUNTERS]', '\n'.join(line for line in value.splitlines() if not line.startswith('#'))) for tool,value in snapshot['firewall'].items()}}
            record('gateway clean stop restores foreign rules routes forwarding and rp_filter',stable_gateway(gateway_after)==stable_gateway(gateway_before))
            packet('stopped-gateway-no-longer-forwards-LAN','qwg','203.0.113.99','192.168.77.2','qwa',False,'192.168.77.2')
        record('worker clean stop',stop(worker)==0)
        after=network();(root/'network-after.json').write_text(json.dumps(after,indent=2))
        record('worker restores foreign firewall routes links and sysctl',after==before)
        record('worker retires socket and journal',not (root/'control.sock').exists() and not (state/'sysctls.state').exists())
        completed=True
    finally:
        for c in children:
            if c.poll() is None:c.kill()
            c.wait(timeout=5)
        for name in reversed(namespaces):run(['ip','netns','del',name],check=False)
        (root/'result.json').write_text(json.dumps(dict(status='PASS' if completed else 'FAIL',backends=[args.ipv4,args.ipv6],artifact_sha256=args.sha256,check_count=len(checks),checks=checks),indent=2)+'\n')


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='command',required=True)
    ep=sub.add_parser('echo')
    for n in ('peer','ready','addresses'):ep.add_argument('--'+n,required=True)
    qp=sub.add_parser('query')
    for n in ('label','address','source','peer','expect','output'):qp.add_argument('--'+n,required=True)
    qp.add_argument('--bind')
    rp=sub.add_parser('run')
    for n in ('qeli','sha256','artifacts','package','parent-net','parent-mnt','parent-pid'):rp.add_argument('--'+n,required=True)
    for n in ('ipv4','ipv6'):rp.add_argument('--'+n,choices=('nft','legacy'),required=True)
    rp.add_argument('--ipv4-gateway',action='store_true',help='Add a private LAN sender, gateway NAT cleanup, and IPv4 forward_private profile')
    args=ap.parse_args()
    if args.command=='echo':echo(args)
    elif args.command=='query':query(args)
    else:main(args)
