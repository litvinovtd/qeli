#!/usr/bin/env python3
"""Frozen DEVMAP guard packet prototype, not an integrated Qeli fix.
Run only via audit_release_matrix_lab.ISOLATED; synthetic exit-shaped rules.
"""
import argparse
import errno
from audit_wan_devmap import Guard
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from audit_firewalld_profiles import MixedFirewall

def main(args):
    for kind in ('net', 'mnt', 'pid'):
        assert os.readlink('/proc/self/ns/'+kind) != getattr(args, 'parent_'+kind)
    root = Path(args.artifacts); root.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks, commands, children, namespaces = [], [], [], []
    completed = False
    guards=[]

    def run(argv, check=True, input=None, env=None, executable=None):
        p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=30,
                           env=env, executable=executable)
        commands.append(dict(argv=argv, executable=executable, exit_code=p.returncode,
                             output=p.stdout+p.stderr))
        (root/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        if check: assert p.returncode == 0, (argv, p.stdout, p.stderr)
        return p

    def ns(name, argv, **kwargs):
        return run(['ip','netns','exec',name,*argv], **kwargs)

    def record(name, ok, detail=None):
        checks.append(dict(name=name, passed=bool(ok), detail=detail))
        (root/'checks.json').write_text(json.dumps(checks, indent=2)+'\n')
        assert ok, (name, detail)
        print('PASS', name, flush=True)

    def link(name):
        return json.loads(run(['ip','-j','link','show','dev',name]).stdout)[0]

    def group(name):
        value = link(name).get('group', 0)
        return 0 if value == 'default' else int(value)

    def route(name, peer4, peer6):
        run(['ip','route','replace','default','via',peer4,'dev',name])
        run(['ip','-6','route','replace','default','via',peer6,'dev',name])

    def pair(peer, host, guest, h4, p4, h6, p6, index=None):
        if peer not in namespaces:
            run(['ip','netns','add',peer]); namespaces.append(peer)
            ns(peer,['ip','link','set','lo','up'])
        run(['ip','link','add',host,*(['index',str(index)] if index else []),
             'type','veth','peer','name',guest])
        run(['ip','link','set',guest,'netns',peer])
        run(['ip','link','set',host,'up']); ns(peer,['ip','link','set',guest,'up'])
        for flag,a,b in [([],h4+'/24',p4+'/24'),(['-6'],h6+'/64',p6+'/64')]:
            run(['ip',*flag,'addr','add',a,'dev',host,*(['nodad'] if flag else [])])
            ns(peer,['ip',*flag,'addr','add',b,'dev',guest,*(['nodad'] if flag else [])])
        Path('/proc/sys/net/ipv4/conf/'+host+'/rp_filter').write_text('0\n')
        Path('/proc/sys/net/ipv6/conf/'+host+'/keep_addr_on_down').write_text('1\n')
        if host != 'incoming':
            for flag,pool,via in [([],'10.86.0.0/24',h4),(['-6'],'fd86::/64',h6)]:
                ns(peer,['ip',*flag,'route','replace',pool,'via',via,'dev',guest])

    def packet(label, peer, sources, expect=True, direct=False):
        for ipv6 in (False,True):
            suffix='v6' if ipv6 else 'v4'; output=root/('packet-'+label+'-'+suffix+'.json')
            argv=[sys.executable,str(Path(__file__).with_name('audit_server_route_policy.py')),
                  'query','--label',label+'-'+suffix,'--address','fd60:d::99' if ipv6 else '203.0.113.99',
                  '--source',sources[int(ipv6)],'--peer',peer,'--expect','yes' if expect else 'no',
                  '--output',str(output)]
            if not direct: argv+=['--bind','fd86::2' if ipv6 else '10.86.0.2']
            tool='ip6tables' if ipv6 else 'iptables'
            def drops():
                chain='qidB'
                rows=[x.split() for x in run([tool,'-t','mangle','-n','-v','-x','-L',chain]).stdout.splitlines() if 'DROP' in x]
                assert len(rows)==1,rows
                return int(rows[0][0])
            before=drops() if not expect else None
            run(argv) if direct else ns('qic',argv)
            result=json.loads(output.read_text())
            record(label+' '+suffix,len(result['replies'])==(3 if expect else 0),result)
            if not expect: record(label+' '+suffix+' exact DROP counter',drops()-before==3)

    def rules():
        for tool in ('iptables','ip6tables'):
            for table,chain in [('mangle','qidM'),('filter','qidF'),('nat','qidN')]:run([tool,'-t',table,'-F',chain])
            run([tool,'-t','mangle','-A','qidM','-i','incoming','-o','wan0','-j','MARK','--set-xmark','0x51/0x51'])
            run([tool,'-A','qidF','-i','incoming','-m','mark','--mark','0x51/0x51','-j','ACCEPT'])
            run([tool,'-A','qidF','-i','incoming','-j','DROP'])
            run([tool,'-t','nat','-A','qidN','-o','wan0','-m','mark','--mark','0x51/0x51','-j','MASQUERADE'])

    try:
        mixed=MixedFirewall(root,args.package,args.ipv4,args.ipv6,run,record)
        run(['ip','link','set','lo','up'])
        for backend in ('nft','legacy'):
            for tool in ('iptables','ip6tables'):
                for table,chain in [('filter','FORWARD'),('mangle','FORWARD'),('mangle','POSTROUTING'),('nat','POSTROUTING')]:
                    spec=[tool,'-t',table,'-A',chain,'-j','RETURN']
                    mixed.real_run(backend,spec);spec[3]='-D';mixed.real_run(backend,spec)
        original_firewall=mixed.snapshot()
        (root/'firewall-before.json').write_text(json.dumps(original_firewall,indent=2)+'\n')
        pair('qic','incoming','c0','10.86.0.1','10.86.0.2','fd86::1','fd86::2')
        pair('qwa','wan0','a0','198.18.60.2','198.18.60.1','fd60:a::2','fd60:a::1')
        pair('qwb','wan1','b0','198.18.61.2','198.18.61.1','fd60:b::2','fd60:b::1')
        original=link('wan0');old_index=original['ifindex'];old_mac=original['address']
        record('original group is zero',group('wan0')==0)
        for peer in ('qwa','qwb'):
            ns(peer,['ip','addr','add','203.0.113.99/32','dev','lo'])
            ns(peer,['ip','-6','addr','add','fd60:d::99/128','dev','lo','nodad'])
            ready=root/(peer+'.ready')
            with (root/(peer+'.log')).open('w') as log:
                child=subprocess.Popen(['ip','netns','exec',peer,sys.executable,
                    str(Path(__file__).with_name('audit_server_route_policy.py')),'echo',
                    '--peer',peer,'--ready',str(ready),'--addresses','203.0.113.99,fd60:d::99'],stdout=log,stderr=subprocess.STDOUT)
            children.append(child)
            until=time.monotonic()+10
            while not ready.exists():
                assert time.monotonic()<until and child.poll() is None
                time.sleep(.05)
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
        Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1\n')
        Path('/proc/sys/net/ipv4/conf/all/rp_filter').write_text('0\n')
        for flag,via in [([],'10.86.0.1'),(['-6'],'fd86::1')]:ns('qic',['ip',*flag,'route','add','default','via',via,'dev','c0'])
        for tool in ('iptables','ip6tables'):
            for table,chain,hook in [('mangle','qidM','FORWARD'),('filter','qidF','FORWARD'),('nat','qidN','POSTROUTING')]:
                run([tool,'-t',table,'-N',chain]);run([tool,'-t',table,'-A',hook,'-j',chain])
        route('wan0','198.18.60.1','fd60:a::1');rules()
        packet('baseline-selected-WAN','qwa',['198.18.60.2','fd60:a::2'])
        pins=root/'bpffs';pins.mkdir();run(['mount','-t','bpf','bpf',str(pins)])
        guard=Guard(old_index,pins/'original',root/'verifier-original.log',link('incoming')['ifindex']);guards.append(guard)
        record('original device in frozen map',guard.lookup()==old_index)
        try:guard.update(old_index)
        except OSError as error:record('live map rejects userspace rewrite',error.errno==errno.EPERM)
        else:record('live map rejects userspace rewrite',False)
        for tool in ('iptables','ip6tables'):
            run([tool,'-t','mangle','-N','qidB'])
            run([tool,'-t','mangle','-A','POSTROUTING','-j','qidB'])
            run([tool,'-t','mangle','-A','qidB','-o','wan0','-m','bpf','--object-pinned',str(guard.root/'program'),'-j','DROP'])
        pinned_rules=mixed.snapshot()
        packet('guard-original-NAT-preserved','qwa',['198.18.60.2','fd60:a::2'])
        packet('guard-local-original-unchanged','qwa',['198.18.60.2','fd60:a::2'],direct=True)
        guard.close();guard=Guard.reopen(pins/'original');guards[0]=guard
        record('pinned original survives owner FD close and reopen',guard.lookup()==old_index)
        packet('reopened-generation-NAT-preserved','qwa',['198.18.60.2','fd60:a::2'])
        # Original device remains alive under a different name; map is non-empty.
        run(['ip','link','set','wan0','down']);run(['ip','link','set','wan0','name','retired0']);run(['ip','link','set','retired0','up'])
        run(['ip','link','set','wan1','down']);run(['ip','link','set','wan1','name','wan0']);run(['ip','link','set','wan0','up'])
        route('wan0','198.18.61.1','fd60:b::1')
        record('rename keeps original map entry',guard.lookup()==old_index)
        record('new name claimant has different index',link('wan0')['ifindex']!=old_index)
        packet('local-new-name-positive-control','qwb',['198.18.61.2','fd60:b::2'],direct=True)
        packet('guard-blocks-name-reuse-while-original-alive','qwb',['10.86.0.2','fd86::2'],False)
        record('name replacement leaves pinned firewall generation unchanged',mixed.snapshot()==pinned_rules)
        run(['ip','link','del','wan0']);run(['ip','link','del','retired0'])
        record('kernel retires entry despite frozen map',guard.lookup() is None)
        pair('qwb','wan0','b0','198.18.61.2','198.18.61.1','fd60:b::2','fd60:b::1',old_index)
        run(['ip','link','set','wan0','address',old_mac]);route('wan0','198.18.61.1','fd60:b::1')
        record('replacement reuses name index and MAC',link('wan0')['ifindex']==old_index and link('wan0')['address']==old_mac)
        record('reused index does not refill frozen map',guard.lookup() is None)
        guard.close();guard=Guard.reopen(pins/'original');guards[0]=guard
        record('reopened retired generation stays empty',guard.lookup() is None)
        packet('local-index-reuse-positive-control','qwb',['198.18.61.2','fd60:b::2'],direct=True)
        packet('guard-blocks-name-index-MAC-reuse','qwb',['10.86.0.2','fd86::2'],False)
        try:guard.update(old_index)
        except OSError as error:record('retired map rejects replacement reauthorization',error.errno==errno.EPERM)
        else:record('retired map rejects replacement reauthorization',False)
        record('device group stays zero',group('wan0')==0)
        record('index reuse leaves pinned firewall generation unchanged',mixed.snapshot()==pinned_rules)
        # Fresh generation may authorize this device only after retiring old rules.
        for tool in ('iptables','ip6tables'):run([tool,'-t','mangle','-F','qidB'])
        guard.close()
        new=Guard(old_index,pins/'next',root/'verifier-next.log',link('incoming')['ifindex']);guards.append(new)
        for tool in ('iptables','ip6tables'):run([tool,'-t','mangle','-A','qidB','-o','wan0','-m','bpf','--object-pinned',str(new.root/'program'),'-j','DROP'])
        packet('fresh-generation-authorizes-current-device','qwb',['198.18.61.2','fd60:b::2'])
        for tool in ('iptables','ip6tables'):
            run([tool,'-t','mangle','-D','POSTROUTING','-j','qidB']);run([tool,'-t','mangle','-F','qidB']);run([tool,'-t','mangle','-X','qidB'])
            for table,chain,hook in [('mangle','qidM','FORWARD'),('filter','qidF','FORWARD'),('nat','qidN','POSTROUTING')]:
                run([tool,'-t',table,'-D',hook,'-j',chain]);run([tool,'-t',table,'-F',chain]);run([tool,'-t',table,'-X',chain])
        after=mixed.snapshot();(root/'firewall-after.json').write_text(json.dumps(after,indent=2)+'\n')
        record('foreign firewall restored exactly',after==original_firewall)
        for owner in guards:
            owner.close()
            for name in ('program','map'):(owner.root/name).unlink()
            owner.root.rmdir()
        run(['umount',str(pins)])
        completed=True
    finally:
        for guard in guards:guard.close()
        for child in children:
            if child.poll() is None:child.terminate()
            child.wait(timeout=5)
        for name in reversed(namespaces):run(['ip','netns','del',name],check=False)
        (root/'result.json').write_text(json.dumps(dict(status='PASS' if completed else 'FAIL',
            backends=[args.ipv4,args.ipv6],check_count=len(checks),checks=checks,
            production_fix=False),indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('artifacts','package','parent-net','parent-mnt','parent-pid'):p.add_argument('--'+n,required=True)
    for n in ('ipv4','ipv6'):p.add_argument('--'+n,choices=('nft','legacy'),required=True)
    main(p.parse_args())
