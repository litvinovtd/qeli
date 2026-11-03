#!/usr/bin/env python3
"""Authenticated upstream NDP lifecycle in private NET/mount/PID namespaces.

Run through audit_release_matrix_lab.ISOLATED. The probe sends Ethernet NS on
an upstream veth; it never injects a SessionMap or talks to production services.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import time

from tap_ipv6_control_probe import (ETH_P_IPV6, ethernet_ipv6, ipv6_icmp,
                                   neighbor_solicitation, options, solicited_node)


def link_mac(interface):
    link = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', interface]))[0]
    return bytes.fromhex(link['address'].replace(':', ''))


def probe(args):
    source = ipaddress.IPv6Address('fd46:2::1')
    target = ipaddress.IPv6Address(args.target)
    mac = link_mac('up0')
    dad = args.kind in ('dad', 'dad-slla', 'dad-unicast')
    if dad:
        destination, dmac = solicited_node(target)
        body = struct.pack('!BBHI16s', 135, 0, 0, 0, target.packed)
        if args.kind == 'dad-slla':
            body += bytes((1, 1)) + mac
        if args.kind == 'dad-unicast':destination=target;dmac=bytes.fromhex(args.proxy_mac.replace(':',''))
        frame = ethernet_ipv6(mac, dmac, ipaddress.IPv6Address('::'), destination, body)
    else:
        frame = neighbor_solicitation(mac, source, target)
    if args.kind == 'bad-hop':
        frame = frame[:21] + bytes((254,)) + frame[22:]
    if args.kind == 'bad-checksum':
        frame = frame[:56] + bytes((frame[56] ^ 1,)) + frame[57:]
    responses = []
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IPV6)) as packet:
        packet.bind(('up0', 0))
        # Subscribe for DAD's all-nodes reply without relying on kernel memberships.
        packet.setsockopt(263, 1, struct.pack('IHH8s', socket.if_nametoindex('up0'), 2, 0, b'\0'*8))
        end = time.monotonic() + 1.0
        next_send = 0
        sent = 0
        while time.monotonic() < end:
            now = time.monotonic()
            if sent < 3 and now >= next_send:
                packet.send(frame)
                sent += 1
                next_send = now + .2
            packet.settimeout(min(.05, max(.001, end-time.monotonic())))
            try:
                reply = packet.recv(4096)
            except socket.timeout:
                continue
            if len(reply) < 78 or reply[12:14] != b'\x86\xdd' or reply[54] != 136 or reply[62:78] != target.packed:
                continue
            src, dst, payload = ipv6_icmp(reply)
            assert src == target and payload[:2] == b'\x88\x00'
            flags = int.from_bytes(payload[4:8], 'big')
            expected_mac = bytes.fromhex(args.proxy_mac.replace(':', ''))
            assert reply[6:12] == expected_mac
            assert any(k == 2 and value[2:8] == expected_mac for k, value in options(payload, 24))
            if args.kind == 'kernel':
                assert dst == source
            else:
                assert flags == (0 if dad else 0x40000000), flags
                assert dst == (ipaddress.IPv6Address('ff02::1') if dad else source)
                assert reply[:6] == (bytes.fromhex('333300000001') if dad else mac)
            responses.append(dict(source=str(src), destination=str(dst), flags=flags, frame_hex=reply.hex()))
    output = dict(target=str(target), kind=args.kind, sent=sent, solicitation_hex=frame.hex(), responses=responses)
    Path(args.output).write_text(json.dumps(output, indent=2)+'\n')
    assert bool(responses) == (args.expect == 'yes'), output
    print(json.dumps(dict(target=str(target), kind=args.kind, responses=len(responses))))


def rate_probe(args):
    target=ipaddress.IPv6Address(args.target);mac=link_mac('up0')
    frame=neighbor_solicitation(mac,ipaddress.IPv6Address('fd46:2::1'),target)
    responses=[];sent=0
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(ETH_P_IPV6)) as packet:
        packet.bind(('up0',0));packet.setsockopt(263,1,struct.pack('IHH8s',socket.if_nametoindex('up0'),2,0,b'\0'*8));packet.setblocking(False)
        # First request after idle resets the proxy window; the bounded burst then
        # stays inside that same window. Preserve raw counts rather than throughput claims.
        time.sleep(1.1);started=time.monotonic()
        while sent<513:
            packet.send(frame);sent+=1
            try:
                while True:
                    reply=packet.recv(4096)
                    if len(reply)>=78 and reply[6:12]==bytes.fromhex(args.proxy_mac.replace(':','')) and reply[54]==136 and reply[62:78]==target.packed:responses.append(reply.hex())
            except BlockingIOError:pass
        send_duration=time.monotonic()-started
        end=started+.7
        while time.monotonic()<end:
            try:
                reply=packet.recv(4096)
                if len(reply)>=78 and reply[6:12]==bytes.fromhex(args.proxy_mac.replace(':','')) and reply[54]==136 and reply[62:78]==target.packed:responses.append(reply.hex())
            except BlockingIOError:time.sleep(.001)
    result=dict(sent=sent,responses=responses,send_duration=send_duration)
    Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    assert send_duration<.5 and 1<=len(responses)<=256,result


def main(args):
    for kind in ('net', 'mnt', 'pid'):
        assert os.readlink('/proc/self/ns/'+kind) != getattr(args, 'parent_'+kind)
    binary = Path(args.qeli).resolve(strict=True)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256
    root = Path(args.artifacts)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    results, commands, children, namespaces = [], [], [], []
    completed = False

    def run(argv, check=True, input=None):
        p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=30)
        commands.append(dict(argv=argv, exit_code=p.returncode, output=p.stdout+p.stderr))
        (root/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        if check:
            assert p.returncode == 0, (argv, p.stdout, p.stderr)
        return p

    def ns(name, argv, **kwargs):
        return run(['ip', 'netns', 'exec', name, *argv], **kwargs)

    def record(name, ok, detail=None):
        results.append(dict(name=name, passed=bool(ok), detail=detail))
        (root/'checks.json').write_text(json.dumps(results, indent=2)+'\n')
        assert ok, (name, detail)
        print('PASS', name, flush=True)

    def until(fn, seconds=30):
        end = time.monotonic()+seconds
        while not fn():
            assert time.monotonic() < end, 'readiness timeout'
            assert all(p.poll() is None for p in children), 'a test process exited; inspect logs'
            time.sleep(.1)

    def spawn(name, argv, label):
        with (root/(label+'.log')).open('w') as log:
            child = subprocess.Popen(['ip','netns','exec',name,*argv], stdout=log, stderr=subprocess.STDOUT)
        children.append(child)
        return child

    def stop(child):
        child.send_signal(signal.SIGTERM)
        rc = child.wait(timeout=45)
        children.remove(child)
        return rc

    try:
        if args.backend == 'legacy':
            target = Path('/usr/sbin/iptables').resolve(strict=True)
            assert target.name == 'xtables-nft-multi'
            wrapper = root/'xtables-wrapper'
            wrapper.write_text('#!/bin/sh\nexec /usr/sbin/xtables-legacy-multi "$(basename "$0")" "$@"\n')
            wrapper.chmod(0o700)
            run(['mount','--bind',str(wrapper),str(target)])
        record('real firewall backend selected', ('legacy' if args.backend=='legacy' else 'nf_tables') in run(['iptables','--version']).stdout)
        for name in ('qnc','qnr','qns'):
            run(['ip','netns','add',name]);namespaces.append(name)
            ns(name,['ip','link','set','lo','up'])
        for left, right, ln, rn in (('cli0','rc0','qnc','qnr'),('wan0','up0','qns','qnr')):
            run(['ip','link','add',left,'type','veth','peer','name',right])
            run(['ip','link','set',left,'netns',ln]);run(['ip','link','set',right,'netns',rn])
            ns(ln,['ip','link','set',left,'up']);ns(rn,['ip','link','set',right,'up'])
        for name, interface, v4, v6 in (('qnc','cli0','10.46.1.2','fd46:1::2'),('qnr','rc0','10.46.1.1','fd46:1::1'),('qnr','up0','10.46.2.1','fd46:2::1'),('qns','wan0','10.46.2.2','fd46:2::2')):
            ns(name,['ip','addr','add',v4+'/24','dev',interface])
            ns(name,['ip','-6','addr','add',v6+'/64','dev',interface,'nodad'])
        for name, hop, interface in (('qnc','10.46.1.1','cli0'),('qns','10.46.2.1','wan0')):
            ns(name,['ip','route','add','default','via',hop,'dev',interface])
        ns('qnc',['ip','-6','route','add','default','via','fd46:1::1','dev','cli0'])
        ns('qns',['ip','-6','route','add','default','via','fd46:2::1','dev','wan0'])
        ns('qnr',['sysctl','-qw','net.ipv4.ip_forward=1','net.ipv6.conf.all.forwarding=1'])
        ns('qnr',['ip','-6','addr','add','fd46:ffff::1/128','dev','lo','nodad'])
        for prefix in ('fd86::/64','fd87::/64'):
            ns('qnr',['ip','-6','route','add',prefix,'dev','up0'])
        ns('qnc',['ip','-6','addr','add','fd87::42/128','dev','lo','nodad'])
        ns('qns',['sysctl','-qw','net.ipv6.conf.all.forwarding='+('1' if args.mode=='manual' else '0')])
        for tool in ('iptables','ip6tables'):
            for table in ('nat','mangle'):
                ns('qns',[tool,'-t',table,'-N','audit-prime']);ns('qns',[tool,'-t',table,'-X','audit-prime'])
            ns('qns',[tool,'-A','FORWARD','-m','comment','--comment','audit-foreign','-j','DROP'])
            ns('qns',[tool,'-P','FORWARD','DROP'])
        if args.mode == 'manual':
            for chainargs in (['-i','vpns','-o','wan0'],['-i','wan0','-o','vpns']):
                ns('qns',['ip6tables','-I','FORWARD','1',*chainargs,'-m','comment','--comment','audit-admin-manual','-j','ACCEPT'])
        # Automatic link-local DAD can finish after global nodad addresses.
        # Wait for the original WAN address to become usable before baseline.
        until(lambda:'scope link' in ns('qns',['ip','-6','addr','show','dev','wan0']).stdout and 'tentative' not in ns('qns',['ip','-6','addr','show','dev','wan0']).stdout)

        def network():
            d={}
            for label, argv in (('v4',['iptables-save']),('v6',['ip6tables-save']),('routes4',['ip','-4','route','show','table','all']),('routes6',['ip','-6','route','show','table','all']),('links',['ip','-j','link'])):
                output=ns('qns',argv).stdout
                d[label]=re.sub(r'\[\d+:\d+\]','[COUNTERS]','\n'.join(x for x in output.splitlines() if not x.startswith('#'))) if label in ('v4','v6') else output
            for name in ('all/forwarding','default/forwarding','wan0/accept_ra'):
                d[name]=ns('qns',['cat','/proc/sys/net/ipv6/conf/'+name]).stdout.strip()
            return d

        before=network();(root/'network-before.json').write_text(json.dumps(before,indent=2))
        proxy_mac=json.loads(ns('qns',['ip','-j','link','show','wan0']).stdout)[0]['address']
        cfg=root/'server.conf';users=root/'users.conf';users.write_text('');users.chmod(0o600)
        cfg.write_text(f'''[auth]
users_file = {users}
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:ndp]
identity_key = {root}/identity.key
bind.address = 10.46.2.2
bind.port = 26443
bind.transport = {args.transport}
tun.name = vpns
tun.ip_mode = ipv6
tun.ipv6_address = fd86::1
tun.mtu = 1400
tun.queues = 1
pool.ipv6.cidr = fd86::/64
routing.nat.enabled = false
routing.client_to_client = {'true' if args.extended else 'false'}
routing.ipv6.mode = {args.mode}
routing.ipv6.interface = wan0
routing.ipv6.ndp_proxy = required
routing.ipv6.ndp_proxy_interface = wan0
roaming.enabled = false
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 0
perf.connection.idle_timeout_secs = 3
''');cfg.chmod(0o600)
        run([str(binary),'add-client','ndp-user','--password-stdin','--profiles','ndp','--static-ipv6','fd86::2','-c',str(cfg)],input='ndp-fixture-pass\n')
        with users.open('a') as f:f.write('\nclient_subnet = fd87::/64'+(', ::/0' if args.extended else '')+'\n')
        run([str(binary),'check-config','-c',str(cfg)])
        state=root/'state';state.mkdir(mode=0o700)
        worker=spawn('qns',['env','STATE_DIRECTORY='+str(state),'QELI_CONTROL_SOCKET='+str(root/'control.sock'),str(binary),'_worker','-c',str(cfg)],'server')
        until(lambda:"session-aware IPv6 NDP proxy active" in (root/'server.log').read_text() and ':26443' in ns('qns',['ss','-lnt' if args.transport=='tcp' else '-lnu']).stdout)
        record('required NDP responder and carrier listener ready',worker.poll() is None)

        def packet(label,target,expect,kind='normal'):
            output=root/('packet-'+label+'.json')
            ns('qnr',['python3',str(Path(__file__).resolve()),'probe','--target',target,'--expect',expect,'--kind',kind,'--proxy-mac',proxy_mac,'--output',str(output)])
            result=json.loads(output.read_text())
            record(label,result['sent']==3 and bool(result['responses'])==(expect=='yes'),dict(target=target,responses=len(result['responses'])))

        def control(request=None):
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(3);sock.connect(str(root/'control.sock'));sock.sendall((json.dumps(request or {'cmd':'list-clients'})+'\n').encode());data=b''
                while b'\n' not in data:
                    part=sock.recv(65536);assert part;data+=part
            reply=json.loads(data.split(b'\n')[0]);assert reply['ok'];return reply if request else reply['clients']

        packet('upstream kernel NDP positive control','fd46:2::2','yes','kernel')
        packet('unconnected reserved lease has no NA','fd86::2','no')
        packet('unconnected delegated prefix has no NA','fd87::42','no')
        client_cfg=root/'client.conf';client_cfg.write_text(f'''[qeli]
server = 10.46.2.2:26443
proto = {args.transport}
roaming = off
user = ndp-user
pass = ndp-fixture-pass
mode = fake-tls
dev = vpnc
bind_static = false
gateway = true
ipv6 = required
dns = off
kill_switch = false
timeout = 8
[logging]
level = info
''');client_cfg.chmod(0o600)
        def connect(label):
            child=spawn('qnc',['env','STATE_DIRECTORY='+str(state),'QELI_KNOWN_HOSTS='+str(root/'known-hosts'),'QELI_DEVICE_ID_FILE='+str(root/'device-id'),str(binary),'client','-c',str(client_cfg)],label)
            until(lambda:len(control())==1 and 'fd86::2/128' in ns('qnc',['ip','-6','addr','show','dev','vpnc'],check=False).stdout)
            record(label+' authenticated exact IPv6 lease',control()[0]['addresses']==['fd86::2'])
            return child
        client=connect('client')
        packet('active exact lease gets valid proxy NA','fd86::2','yes')
        packet('active delegated prefix gets valid proxy NA','fd87::42','yes')
        packet('free pool address has no proxy NA','fd86::99','no')
        packet('unowned external prefix has no proxy NA','fd88::42','no')
        packet('active DAD gets unsolicited all-nodes NA','fd86::2','yes','dad')
        if args.extended:
            packet('DAD unicast destination baseline-fix','fd86::2','yes' if args.baseline else 'no','dad-unicast')
            previous=(root/'server.log').read_text().count('NDP proxy rate limit reached')
            output=root/'rate-probe.json'
            ns('qnr',['python3',str(Path(__file__).resolve()),'rate','--target','fd86::2','--proxy-mac',proxy_mac,'--output',str(output)])
            rate=json.loads(output.read_text())
            record('per-MAC packet response cap enforced',1<=len(rate['responses'])<=256,dict(sent=rate['sent'],responses=len(rate['responses']),duration=rate['send_duration']))
            warnings=(root/'server.log').read_text().count('NDP proxy rate limit reached')-previous
            record('rate warnings baseline/fix',warnings>1 if args.baseline else warnings==1,dict(warnings=warnings))
            time.sleep(1.1)
            packet('NDP responds again after rate-window reset','fd86::2','yes')
        for kind in ('bad-hop','bad-checksum','dad-slla'):
            packet('malformed-'+kind+' rejected','fd86::2','no',kind)
        for target in ('fd86::2','fd87::42'):
            ping=ns('qnr',['ping','-6','-c','2','-W','2',target],check=False)
            record('on-link upstream reaches authenticated '+target,ping.returncode==0,ping.stdout)
        record('delegated kernel route installed','fd87::/64 dev vpns' in ns('qns',['ip','-6','route','show']).stdout)
        record('IPv6 is source preserving','MASQUERADE' not in ns('qns',['ip6tables-save']).stdout)
        record('client normal stop',stop(client)==0)
        # UDP has no clean close. Wait for its configured idle expiry and 30 s
        # maintenance tick; do not mislabel a retained UDP session as disconnected.
        until(lambda:len(control())==0,seconds=45)
        record('session registry retired after transport teardown',control()==[])
        packet('retired exact lease stops proxy NA','fd86::2','no')
        packet('retired delegated prefix stops proxy NA','fd87::42','no')
        record('delegated kernel route retired','fd87::/64 dev vpns' not in ns('qns',['ip','-6','route','show']).stdout)
        client=connect('client-reconnect')
        packet('reconnected exact lease resumes NA','fd86::2','yes')
        packet('reconnected delegated prefix resumes NA','fd87::42','yes')
        if args.extended and not args.baseline:
            client.send_signal(signal.SIGSTOP)
            try:
                reply=control({'cmd':'kick','username':'ndp-user'})
                record('administrator kick removes live session',reply['ok'] and control()==[])
                packet('admin-revoked lease stops NA','fd86::2','no')
                packet('admin-revoked prefix stops NA','fd87::42','no')
                record('admin revoke removes delegated route','fd87::/64 dev vpns' not in ns('qns',['ip','-6','route','show']).stdout)
            finally:
                client.kill();client.wait(timeout=5);children.remove(client)
            client=connect('client-after-kick')
            packet('new authenticated owner resumes NA','fd86::2','yes')
        record('reconnected client normal stop',stop(client)==0)
        record('worker normal stop',stop(worker)==0)
        after=network();(root/'network-after.json').write_text(json.dumps(after,indent=2))
        record('worker restores foreign firewall routes links and sysctl',after==before)
        record('worker retires socket and sysctl journal',not (root/'control.sock').exists() and not (state/'sysctls.state').exists())
        packet('stopped responder has no lease NA','fd86::2','no')
        if args.extended and not args.baseline:
            worker=spawn('qns',['env','STATE_DIRECTORY='+str(state),'QELI_CONTROL_SOCKET='+str(root/'control.sock'),str(binary),'_worker','-c',str(cfg)],'server-crash')
            until(lambda:'session-aware IPv6 NDP proxy active' in (root/'server-crash.log').read_text())
            client=connect('client-crash')
            packet('proxy responds before worker SIGKILL','fd86::2','yes')
            client.send_signal(signal.SIGSTOP)
            worker.kill();worker.wait(timeout=5);children.remove(worker)
            client.kill();client.wait(timeout=5);children.remove(client)
            packet('SIGKILL closes proxy lease responder','fd86::2','no')
            packet('SIGKILL closes proxy delegated responder','fd87::42','no')
            old_wan=next(x for x in json.loads(before['links']) if x['ifname']=='wan0')
            new_wan=json.loads(ns('qns',['ip','-j','link','show','wan0']).stdout)[0]
            record('SIGKILL releases socket multicast membership',old_wan['flags']==new_wan['flags'])
            (root/'network-crash.json').write_text(json.dumps(network(),indent=2))
            # SIGKILL firewall/sysctl recovery has separate evidence and explicit
            # lost-witness manual boundaries. Do not label this as clean restore.

        completed=True
    finally:
        for child in children:
            if child.poll() is None:child.kill()
            child.wait(timeout=5)
        for name in reversed(namespaces):
            for pid in ns(name,['ip','netns','pids',name],check=False).stdout.split():
                run(['kill','-KILL',pid],check=False)
            run(['ip','netns','del',name],check=False)
        (root/'result.json').write_text(json.dumps(dict(status='PASS' if completed else 'FAIL',backend=args.backend,mode=args.mode,transport=args.transport,artifact_sha256=args.sha256,check_count=len(results),checks=results),indent=2)+'\n')


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    sub=ap.add_subparsers(dest='command',required=True)
    pp=sub.add_parser('probe')
    for name in ('target','expect','kind','proxy-mac','output'):pp.add_argument('--'+name,required=True)
    rp=sub.add_parser('run')
    for name in ('qeli','sha256','artifacts','parent-net','parent-mnt','parent-pid'):rp.add_argument('--'+name,required=True)
    rp.add_argument('--backend',choices=('nft','legacy'),required=True)
    rp.add_argument('--mode',choices=('route','manual'),required=True)
    rp.add_argument('--transport',choices=('tcp','udp'),required=True)
    rp.add_argument('--extended',action='store_true')
    rp.add_argument('--baseline',action='store_true',help='Reproduce invalid DAD replies and repeated rate warnings')
    rate=sub.add_parser('rate')
    for name in ('target','proxy-mac','output'):rate.add_argument('--'+name,required=True)
    args=ap.parse_args()
    if args.command=='probe':probe(args)
    elif args.command=='rate':rate_probe(args)
    else:main(args)
