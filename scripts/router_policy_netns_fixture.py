"""Run ONLY inside unshare --mount --pid --fork --net --mount-proc.
All ISP/LAN/tunnel peers, packet captures and mutations are namespace-local.
"""
import os,sys,json,time,threading,subprocess,tempfile,signal,socket,struct
from pathlib import Path
BIN=Path(sys.argv[1]).resolve(); BASE=Path(sys.argv[2]).resolve()
BACKEND=os.environ.get('QELI_ROUTER_TEST_BACKEND','nft')
assert BACKEND in ('nft','iptables')
assert os.getpid()==1, 'requires private PID namespace'
assert len(sys.argv)==5, 'pass parent network and mount namespace identities'
assert os.readlink('/proc/self/ns/net')!=sys.argv[3], 'network namespace was not isolated'
assert os.readlink('/proc/self/ns/mnt')!=sys.argv[4], 'mount namespace was not isolated'
def cmd(*args,check=True,input=None):
    p=subprocess.run([str(a) for a in args],input=input,capture_output=True,text=True,timeout=15)
    if check and p.returncode:raise AssertionError((args,p.returncode,p.stdout,p.stderr))
    return p
def ip(*args,**kw):return cmd('ip',*args,**kw)
def cli(*args,**kw):return cmd(BIN,'router',*args,**kw)
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temp=path.with_suffix('.new');temp.write_text(json.dumps(value) if not isinstance(value,str) else value);temp.chmod(0o600);temp.replace(path)
def wait(test,seconds=18):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        try:
            if test():return
        except (FileNotFoundError,json.JSONDecodeError):pass
        time.sleep(.1)
    raise AssertionError('condition timeout')
cmd('mount','--make-rprivate','/')
cmd('mount','-t','tmpfs','tmpfs','/run')
cmd('mount','-t','sysfs','sysfs','/sys')
ip('link','set','lo','up');cmd('sysctl','-q','-w','net.ipv4.ip_forward=1')
children=[];report={'backend':BACKEND,'passed':[]}
def passed(name):report['passed'].append(name);print('PASS',name,flush=True)
for name,local,remote,subnet in [('ispA','uplinkA','a0','10.71.1'),('ispB','uplinkB','b0','10.71.2'),('exit','qeli-test','t0','10.71.3'),('lan','clientnet','l0','10.71.4')]:
    ip('netns','add',name);ip('link','add',local,'type','veth','peer','name',remote)
    ip('link','set',remote,'netns',name);ip('addr','add',subnet+'.1/24','dev',local);ip('link','set',local,'up')
    ip('-n',name,'link','set','lo','up');ip('-n',name,'addr','add',subnet+'.2/24','dev',remote);ip('-n',name,'link','set',remote,'up')
    if name!='lan':
        for vip in ['1.1.1.1','1.0.0.1','9.9.9.9']:ip('-n',name,'addr','add',vip+'/32','dev','lo')
        ip('-n',name,'route','add','10.71.4.0/24','via',subnet+'.1')
    else:ip('-n',name,'route','add','default','via',subnet+'.1')
# Explicit connected and routed local exceptions must survive the terminal prohibit.
ip('netns','exec','lan','ip','addr','add','192.168.88.8/32','dev','lo')
ip('route','add','192.168.88.0/24','via','10.71.4.2','dev','clientnet')
ip('-6','addr','add','fd71:4::1/64','dev','clientnet','nodad')
ip('-n','lan','-6','addr','add','fd71:4::2/64','dev','l0','nodad')
ip('-n','lan','-6','addr','add','fd88::8/128','dev','lo','nodad')
ip('-6','route','add','fd88::/64','via','fd71:4::2','dev','clientnet')
ip('route','add','default','via','10.71.1.2','dev','uplinkA','metric','10')
ip('route','add','default','via','10.71.2.2','dev','uplinkB','metric','20')
# Keep namespace peer replies from reverse-path filtering a policy-selected link.
for d in ['all','default','uplinkA','uplinkB','qeli-test','clientnet']:cmd('sysctl','-q','-w',f'net.ipv4.conf.{d}.rp_filter=0')
folder=Path(tempfile.mkdtemp(prefix='fixture-',dir=BASE));folder.chmod(0o700)
status_dir=folder/'runtime';status_dir.mkdir(mode=0o700,exist_ok=True)
state=folder/'state';state.mkdir(mode=0o700,exist_ok=True)
conf=folder/'client.conf';save(conf,'[qeli]\nserver=192.0.2.1:444\nmode=plain\nbind_static=false\ngateway=false\npull_routes=false\nuser=fixture\npass=fixture-only-secret\ndev=qeli-test\ndns=off\n')
policy_file=folder/'router.json';pidfile=folder/'vpn.pid';statusfile=status_dir/'status.json'
holder=subprocess.Popen(['sleep','900']);children.append(holder)
def ticks(pid):return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
save(pidfile,f'{holder.pid} {ticks(holder.pid)}\n')
boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();vpn={'state':'connected'};stop_refresh=False
def refresh():
    while not stop_refresh:
        index=int(Path('/sys/class/net/qeli-test/ifindex').read_text())
        save(statusfile,{'schema':1,'runtime':{'pid':holder.pid,'boot_id':boot,'start_ticks':ticks(holder.pid),'run_id':f'{boot}:{holder.pid}:{ticks(holder.pid)}','updated_boottime_ms':int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)},'tunnel':{'state':vpn['state'],'device':'qeli-test','ifindex':index,'addresses':['10.71.3.1']}})
        time.sleep(.2)
threading.Thread(target=refresh,daemon=True).start()
p=json.loads(cli('example').stdout)
p['backend']=BACKEND
p.update(components={'routing':'client','firewall':'client'},device='qeli-test',client_config=str(conf),status_file=str(statusfile),pid_file=str(pidfile),state_directory=str(state),offload_disabled=True,persistent_guard=True,
    uplinks=[{'device':'uplinkA','probes':['1.1.1.1']},{'device':'uplinkB','probes':['1.1.1.1']}],
    networks=[{'device':'clientnet','subnets':['10.71.4.0/24'],'policy':'vpn_only'}],server_addresses=['192.0.2.1'],health={'interval_secs':1,'timeout_secs':1,'up':1,'down':1,'tunnel_probes':['1.0.0.1']})
p['local_subnets']=['10.71.4.0/24','192.168.88.0/24','fd71:4::/64','fd88::/64']
save(policy_file,p)
baseline_rules=ip('-4','rule','show').stdout
baseline_routes=ip('-4','route','show','table','main').stdout
def start_worker():
    log=(folder/f'worker-{len(children)}.log').open('w')
    worker=subprocess.Popen([str(BIN),'router','run','--policy',str(policy_file)],stdout=log,stderr=subprocess.STDOUT);children.append(worker);return worker
def health():return json.loads((state/'health.json').read_text())
def ping():return ip('netns','exec','lan','ping','-n','-c','1','-W','1','9.9.9.9',check=False).returncode==0
server_code=r'''
import socket,threading,sys
tag=sys.argv[1].encode()
def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('9.9.9.9',8081));s.listen(10)
 def peer(c):
  with c:
   while c.recv(64):c.sendall(tag)
 while True:
  c,_=s.accept();threading.Thread(target=peer,args=(c,),daemon=True).start()
threading.Thread(target=tcp,daemon=True).start()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('9.9.9.9',9091))
while True:
 data,addr=u.recvfrom(64);u.sendto(tag,addr)
'''
client_code=r'''
import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if sys.argv[1]=='udp' else socket.SOCK_STREAM);s.settimeout(4)
s.connect(('9.9.9.9',9091 if sys.argv[1]=='udp' else 8081))
for line in sys.stdin:
 s.send(b'fixture');print(s.recv(64).decode(),flush=True)
'''
def session(proto):
    child=subprocess.Popen(['ip','netns','exec','lan','python3','-u','-c',client_code,proto],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(child);return child
def request(child):
    child.stdin.write('next\n');child.stdin.flush();return child.stdout.readline().strip()
reply_server="""import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',18081));s.listen(10)
def peer(c):
 with c:
  if c.recv(64):c.sendall(b'reply-ok')
while True:
 c,_=s.accept();threading.Thread(target=peer,args=(c,),daemon=True).start()
"""
def inbound(ns,dest,port=18081):
    code="import socket,sys;s=socket.socket();s.settimeout(3);s.bind(('1.1.1.1',0));s.connect((sys.argv[1],int(sys.argv[2])));s.sendall(b'test');assert s.recv(64)==b'reply-ok'"
    return ip('netns','exec',ns,'python3','-c',code,dest,str(port),check=False).returncode==0
try:
    children.append(subprocess.Popen(['python3','-c',reply_server]))
    children.append(subprocess.Popen(['ip','netns','exec','lan','python3','-c',reply_server]))
    for ns,tag in [('ispA','A'),('ispB','B'),('exit','VPN')]:
        child=subprocess.Popen(['ip','netns','exec',ns,'python3','-u','-c',server_code,tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(child)
    time.sleep(.3)
    assert json.loads(cli('check','--policy',policy_file).stdout)['valid'];passed('managed preflight')
    cli('guard','--policy',policy_file)
    assert not ping()
    assert ip('netns','exec','lan','ping','-n','-c','1','-W','1','10.71.4.1',check=False).returncode==0
    passed('early guard blocks VPN-only before VPN or policy worker starts; router remains reachable')
    worker=start_worker()
    wait(lambda: (state/'health.json').exists() or worker.poll() is not None)
    if worker.poll() is not None:raise AssertionError('worker failed: '+'\n'.join(f.read_text() for f in folder.glob('worker-*.log')))
    wait(lambda:health()['vpn'] and all(u['internet'] for u in health()['uplinks']))
    assert ping();passed('VPN-only delivers with live verified tunnel')
    receipt=json.loads((state/'receipt.json').read_text())
    mark=str((len(p['uplinks'])+1)<<receipt['allocation']['shift'])
    for family,address in [('-4','10.71.4.2'),('-4','192.168.88.8'),('-6','fd71:4::2'),('-6','fd88::8')]:
        found=ip(family,'route','get',address,'mark',mark).stdout
        assert 'dev clientnet' in found,(address,found)
    passed('connected and routed IPv4/IPv6 local exceptions bypass terminal prohibit')
    ip('route','del','192.168.88.0/24','via','10.71.4.2','dev','clientnet')
    wait(lambda:ip('-4','route','get','192.168.88.8','mark',mark,check=False).returncode!=0)
    ip('route','add','192.168.88.0/24','via','10.71.4.2','dev','clientnet')
    wait(lambda:ip('-4','route','get','192.168.88.8','mark',mark,check=False).returncode==0)
    passed('missing local route cannot inherit a WAN default and returns after renewal')
    assert inbound('ispA','10.71.1.1') and inbound('ispB','10.71.2.1') and inbound('exit','10.71.3.1')
    passed('router service replies symmetrically through both WANs and TUN')
    cmd('nft','-f','-',input='table ip fixture_dnat {\n chain incoming {\n type nat hook prerouting priority -100;\n tcp dport 18083 dnat to 10.71.4.2:18081\n }\n}\n')
    assert inbound('ispA','10.71.1.1',18083) and inbound('ispB','10.71.2.1',18083)
    passed('platform-admitted DNAT replies from VPN-only LAN retain incoming WAN')
    cmd('nft','delete','table','ip','fixture_dnat')
    cmd('nft','-f','-',input='table inet fixture_probe_drop {\n chain output {\n type filter hook output priority 0;\n oifname "qeli-test" ip daddr 1.0.0.1 icmp type echo-request drop\n }\n}\n')
    wait(lambda:not health()['vpn'])
    assert health()['native']['state']=='connected' and inbound('exit','10.71.3.1')
    passed('TUN administrative return route survives failed TUN Internet probe')
    cmd('nft','delete','table','inet','fixture_probe_drop');wait(lambda:health()['vpn'])
    pending=json.loads((state/'pending.json').read_text());remaining=pending['deadline_ms']-int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)
    assert 90000<remaining<=120000;cli('confirm','--policy',policy_file);passed('independent 120-second watchdog and explicit confirmation')
    assert json.loads(cli('status','--file',statusfile,'--pid-file',pidfile,'--device','qeli-test').stdout)['state']=='connected'
    save(pidfile,f'{holder.pid} 1\n');assert not json.loads(cli('status','--file',statusfile,'--pid-file',pidfile,'--device','qeli-test').stdout)['available'];save(pidfile,f'{holder.pid} {ticks(holder.pid)}\n');passed('PID reuse/stale generation cannot report connected')
    ip('address','del','10.71.3.1/24','dev','qeli-test')
    assert not json.loads(cli('status','--file',statusfile,'--pid-file',pidfile,'--device','qeli-test').stdout)['available']
    wait(lambda:not health()['vpn']);assert not ping()
    ip('address','add','10.71.3.1/24','dev','qeli-test');wait(lambda:health()['vpn']);wait(ping)
    passed('authenticated process without assigned TUN address is not connected (OpkgTun attach gate)')
    other=dict(p,state_directory=str(folder/'second-state'));save(folder/'second.json',other)
    result=cli('run','--policy',folder/'second.json',check=False)
    assert result.returncode!=0 and 'network namespace' in result.stderr
    passed('second controller cannot acquire namespace through a different runtime directory')
    vpn['state']='reconnecting';wait(lambda:not health()['vpn']);assert not ping();passed('VPN-only blocks while process and TUN survive')
    p['networks'][0]['policy']='vpn_fallback';save(policy_file,p);worker.wait(timeout=8);worker=start_worker();wait(lambda: health()['vpn']==False and worker.poll() is None)
    wait(ping);cli('confirm','--policy',policy_file);passed('VPN fallback with unchanged VPN PID')
    ip('link','set','uplinkA','down');wait(lambda:not health()['uplinks'][0]['internet'] and health()['uplinks'][1]['internet']);assert ping();passed('WAN1 failure uses WAN2')
    tcp=session('tcp');udp=session('udp');assert request(tcp)=='B';assert request(udp)=='B'
    ip('link','set','uplinkA','up')
    # Linux removes the static default at link-down; model netifd/NDM DHCP renewal.
    ip('route','replace','default','via','10.71.1.2','dev','uplinkA','metric','10')
    wait(lambda:health()['uplinks'][0]['internet']);wait(ping,8);passed('WAN1 failback after gateway renewal')
    assert request(tcp)=='B';assert request(udp)=='B'
    assert request(session('tcp'))=='A';assert request(session('udp'))=='A';passed('healthy TCP and UDP sessions stay on WAN2; new sessions prefer WAN1')
    assert holder.poll() is None;assert ticks(holder.pid)==pidfile.read_text().split()[1];passed('VPN process not restarted')
    # Expiry fixture exercises the same watchdog with a short, explicitly-created
    # private journal. Production admission above was verified to use 120 seconds.
    previous=dict(p);previous['components']={'routing':'external','firewall':'external'}
    save(state/'pending.json',{'boot':boot,'token':'expiry-fixture','deadline_ms':int(time.clock_gettime(time.CLOCK_BOOTTIME)*1000)+1000,'policy':str(policy_file),'state':str(state),'previous':list(json.dumps(previous).encode()),'candidate':list(policy_file.read_bytes())})
    watchdog=subprocess.Popen([str(BIN),'router','watchdog','--pending',str(state/'pending.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(watchdog)
    out,err=watchdog.communicate(timeout=25);assert watchdog.returncode==0,(out,err)
    wait(lambda:not (state/'receipt.json').exists());worker.wait(timeout=8)
    assert 'qeli_router' not in cmd('nft','list','ruleset').stdout
    if BACKEND=='iptables':
        for tool in ['iptables-save','ip6tables-save']:
            rules=cmd(tool).stdout
            assert 'QELI_R_' not in rules and 'QELI_G_' not in rules
    assert ip('-4','rule','show').stdout==baseline_rules
    assert ip('-4','route','show','table','main').stdout==baseline_routes
    passed('watchdog restores external policy and deletes only owned network resources')
    # A stale supervisor/UCI reload may not silently re-apply a rejected manifest.
    assert (policy_file.with_suffix('.rejected.json')).exists()
    secret_dir=folder/'retained';runtime=folder/'restored';runtime.mkdir(mode=0o700)
    cli('store-secret','--directory',secret_dir,'--name','pass',input='private-fixture-password\n')
    assert (secret_dir/'password').stat().st_mode&0o777==0o600
    cli('restore-secrets','--persistent',secret_dir,'--runtime',runtime)
    assert (runtime/'password').read_text()=='private-fixture-password'
    victim=folder/'victim';save(victim,'unchanged');(secret_dir/'obfs-key').symlink_to(victim)
    assert cli('store-secret','--directory',secret_dir,'--name','obfs-key',input='new-secret\n',check=False).returncode!=0
    assert victim.read_text()=='unchanged';passed('retained secrets: 0600, restore, symlink rejection')
finally:
    if sys.exc_info()[0]:
        report['error']=str(sys.exc_info()[1])
        for name,argv in [('rules',['ip','-N','-j','-4','rule','show']),('routes',['ip','-N','-j','-4','route','show','table','all']),('firewall',['nft','list','ruleset'])]:
            (folder/(name+'-at-failure.txt')).write_text(cmd(*argv,check=False).stdout)
    stop_refresh=True
    for child in reversed(children):
        if child.poll() is None:child.terminate()
    for child in children:
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:child.kill();child.wait()
    (BASE/'integration-result.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report),flush=True)
