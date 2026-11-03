# Q16 authenticated ACL and route ownership checks in fresh NET/mount/PID namespaces.
import argparse,json,os,select,signal,socket,struct,subprocess,time,threading,concurrent.futures
from pathlib import Path
from audit_udp_handshake_contracts import hashed,control,stop,wait_for

def checksum(data):
    if len(data)%2:data+=b'\0'
    value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value>65535:value=(value&65535)+(value>>16)
    return (~value)&65535

def packet(src,dst):
    v=6 if ':' in src else 4;family=socket.AF_INET6 if v==6 else socket.AF_INET
    a=socket.inet_pton(family,src);b=socket.inet_pton(family,dst)
    udp=struct.pack('!HHHH',35000,25816,14,0)+b'Q16UP!'
    if v==4:
        ip=bytearray(struct.pack('!BBHHHBBH',0x45,0,34,0,0,64,17,0)+a+b);ip[10:12]=struct.pack('!H',checksum(ip));return bytes(ip)+udp
    pseudo=a+b+struct.pack('!I3xB',len(udp),17);udp=udp[:6]+struct.pack('!H',checksum(pseudo+udp) or 65535)+udp[8:]
    return struct.pack('!IHBB',0x60000000,len(udp),17,64)+a+b+udp

def ns(k):return os.readlink('/proc/self/ns/'+k)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--qeli',required=True);ap.add_argument('--peer',required=True);ap.add_argument('--root',type=Path,required=True);ap.add_argument('--inside',action='store_true');ap.add_argument('--baseline',action='store_true');a=ap.parse_args()
    root=a.root.resolve();binary=str(Path(a.qeli).resolve(strict=True));peer=str(Path(a.peer).resolve(strict=True))
    if not a.inside:
        assert os.geteuid()==0;root.mkdir(mode=0o700)
        env=dict(os.environ,**{'Q16_PARENT_'+k.upper():ns(k) for k in ('net','mnt','pid')})
        return subprocess.run(['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',os.sys.executable,__file__,'--qeli',binary,'--peer',peer,'--root',str(root),'--inside',*(['--baseline'] if a.baseline else [])],env=env,timeout=420).returncode
    assert all(ns(k)!=os.environ['Q16_PARENT_'+k.upper()] for k in ('net','mnt','pid'))
    def cmd(*args):
        p=subprocess.run(args,capture_output=True,text=True);assert p.returncode==0,(args,p.stdout,p.stderr);return p.stdout
    cmd('mount','--make-rprivate','/');cmd('ip','link','set','lo','up')
    for path in ('/run','/var/lib','/var/log'):cmd('mount','-t','tmpfs','tmpfs',path)
    Path('/var/lib/qeli').mkdir();Path('/var/log/qeli').mkdir();etc=root/'etc';etc.mkdir(mode=0o700);cmd('mount','--bind',str(etc),'/etc/qeli')
    cmd('sysctl','-w','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.default.rp_filter=0','net.ipv6.conf.all.forwarding=1')
    def net():return {k:cmd(*v) for k,v in {'addresses':['ip','-br','addr'],'v4':['ip','-4','route','show','table','all'],'v6':['ip','-6','route','show','table','all']}.items()}
    baseline=net();results={'status':'RUNNING','cases':[]};password=hashed()
    try:
        for transport in ('tcp','udp','quic'):
            for ctc in ([False] if a.baseline else [False,True]):
                case=root/(transport+'-'+str(ctc));case.mkdir(mode=0o700);(case/'state').mkdir(mode=0o700);checks=[];peers=[];sinks=[];server=None;log=None;peer_lock=threading.Lock()
                def check(name,value):
                    checks.append({'name':name,'passed':bool(value)});(case/'checks.json').write_text(json.dumps(checks,indent=2));assert value,name
                def clients():return control(case,'list-clients')['clients']
                users={'A':'client_subnet = 198.18.16.0/24, fd76:16::/64\n','B':'client_subnet = 198.18.16.0/24, fd76:16::/64\n','C':'','D':'client_subnet = 198.18.16.128/25, fd76:16::8000/113\n','E':'static_ip = 10.76.0.6\nstatic_ipv6 = fd76::6\nclient_subnet = 0.0.0.0/0, ::/0\n','G':'group = staff\n','U':'group = staff\nallowed_networks = fd76::1/128, 198.18.99.0/24, fd76:99::/64\nroute = 198.51.100.0/24\nroute = 2001:db8:4::/48\n','X':'profiles = other-profile\n','F':'client_subnet = 198.18.17.0/24\n','R1':'client_subnet = 198.18.18.0/24, fd76:18::/64\n','R2':'client_subnet = 198.18.18.0/24, fd76:18::/64\n'}
                text='[group:staff]\nallowed_networks = 10.76.0.1/32\n'+''.join('[user:'+name+']\npassword_hash = '+password+'\nenabled = true\nmax_sessions = 0\n'+fields for name,fields in users.items());(case/'users.ini').write_text(text)
                cfg=f'''[auth]
users_file = {case}/users.ini
require_client_key_proof = true
bind_static_to_session = false
[web]
enabled = false
[logging]
level = debug
[profile:acl]
identity_key = {case}/identity.key
bind.address = 127.0.0.1
bind.port = 24943
bind.transport = {'tcp' if transport=='tcp' else 'udp'}
tun.name = q16srv
tun.address = 10.76.0.1
tun.queues = 1
tun.ip_mode = dual
tun.ipv6_address = fd76::1
pool.cidr = 10.76.0.0/24
pool.ipv6.cidr = fd76::/120
routing.nat.enabled = false
routing.client_to_client = {str(ctc).lower()}
routing.ipv6.mode = manual
route = 203.0.113.0/24
route = 2001:db8:3::/48
route = 0.0.0.0/0 gateway=10.76.0.6
route = ::/0 gateway=fd76::6
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = false
obf.traffic_shaping.enabled = false
perf.connection.idle_timeout_secs = 120
perf.connection.max_clients = 32
perf.connection.handshake_timeout_secs = 6
perf.connection.new_session_rate_max = 1000
'''
                (case/'server.ini').write_text(cfg);env=dict(os.environ,STATE_DIRECTORY=str(case/'state'),QELI_CONTROL_SOCKET=str(case/'control.sock'))
                def response(p,seconds=8):
                    assert select.select([p.stdout],[],[],seconds)[0],'peer response deadline';line=p.stdout.readline();assert line,(p.poll(),'peer ended');return json.loads(line)
                def connect(user,device=1):
                    with peer_lock:
                        number=len(peers);err=(case/f'peer-{number}.log').open('w');p=subprocess.Popen([peer,transport,'127.0.0.1:24943',str(case/'identity.key'),user,str(device),'command'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,start_new_session=True);peers.append((p,err))
                    info=response(p,10);assert info['server_proof_verified'];(case/f'peer-{number}.json').write_text(json.dumps(info));return p,info
                def request(p,line):p.stdin.write(line+'\n');p.stdin.flush();return response(p)
                def address(info,v):return next(x['address'] for x in info['addresses'] if x['family']==('ipv4' if v==4 else 'ipv6'))
                def inject(p,src,dst):value=packet(src,dst);assert request(p,'SEND '+value.hex())['sent']==len(value);return value
                def actual(p,src,v,allowed,label):
                    sink=sinks[0 if v==4 else 1]
                    while select.select([sink],[],[],0)[0]:sink.recvfrom(2048)
                    inject(p,src,'10.76.0.1' if v==4 else 'fd76::1')
                    ready=bool(select.select([sink],[],[],2 if allowed else .8)[0])
                    if allowed is not None:check(label,ready==allowed)
                    if ready:
                        data,source=sink.recvfrom(2048);check(label+' source and payload',data==b'Q16UP!' and source[0]==src)
                    return ready
                try:
                    cmd(binary,'check-config','-c',str(case/'server.ini'));log=(case/'server.log').open('w');server=subprocess.Popen([binary,'server','-c',str(case/'server.ini')],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                    wait_for(lambda:(case/'control.sock').exists() and ':24943' in cmd('ss','-lnt' if transport=='tcp' else '-lnu'),15)
                    cmd('sysctl','-w','net.ipv4.conf.q16srv.rp_filter=0')
                    for v,dst in ((4,'10.76.0.1'),(6,'fd76::1')):
                        sink=socket.socket(socket.AF_INET if v==4 else socket.AF_INET6,socket.SOCK_DGRAM);sink.setblocking(False);sink.bind((dst,25816));sinks.append(sink)
                    A,ai=connect('A');B,bi=connect('B');C,ci=connect('C');check('three dual sessions admitted',all(x['accepted'] for x in (ai,bi,ci)) and len(clients())==3)
                    for v,src in ((4,'198.18.16.9'),(6,'fd76:16::9')):
                        actual(A,src,v,True,f'v{v} first iroute owner can send')
                        actual(B,src,v,a.baseline,f'v{v} conflicting iroute source '+('reproduced' if a.baseline else 'refused'))
                        actual(B,address(bi,v),v,True,f'v{v} second session own source unaffected')
                    control(case,'kick',username='A');wait_for(lambda:all(c['username']!='A' for c in clients()))
                    for v,src in ((4,'198.18.16.9'),(6,'fd76:16::9')):actual(B,src,v,a.baseline,f'v{v} unregistered source after owner kick '+('reproduced' if a.baseline else 'refused'))
                    B,bi=connect('B');check('reconnect claims now free routes',bi['accepted'] and len(clients())==2)
                    for v,src in ((4,'198.18.16.9'),(6,'fd76:16::9')):actual(B,src,v,True,f'v{v} newly registered route allowed')
                    if not a.baseline:
                        for v in (4,6):
                            value=inject(B,address(bi,v),address(ci,v));got=request(C,'RECV')['packet'];check(f'v{v} client isolation {ctc}',(got==value.hex()) if ctc else got is None)
                            src='198.18.16.9' if v==4 else 'fd76:16::9';value=inject(B,src,address(ci,v));got=request(C,'RECV')['packet'];check(f'v{v} routed source isolation {ctc}',(got==value.hex()) if ctc else got is None)
                        D,di=connect('D');check('more specific owner admitted',di['accepted'])
                        for v,src in ((4,'198.18.16.130'),(6,'fd76:16::8009')):
                            actual(B,src,v,False,f'v{v} broader route cannot impersonate specific owner');actual(D,src,v,True,f'v{v} longest prefix owner can send')
                        control(case,'kick',username='D');wait_for(lambda:all(c['username']!='D' for c in clients()))
                        for v,src in ((4,'198.18.16.130'),(6,'fd76:16::8009')):actual(B,src,v,True,f'v{v} broader ownership resumes after specific kick')
                        E,ei=connect('E');G,gi=connect('G');U,ui=connect('U');check('exit and ACL users admitted',all(x['accepted'] for x in (ei,gi,ui)))
                        check('profile routes pushed without internal defaults',{r['cidr'] for r in gi['routes']}=={'203.0.113.0/24','2001:db8:3::/48'})
                        check('user routes override profile',{r['cidr'] for r in ui['routes']}=={'198.51.100.0/24','2001:db8:4::/48'})
                        X,xi=connect('X');check('profile access restriction rejects auth',not xi['accepted'])
                        for v,src in ((4,'198.18.99.9'),(6,'fd76:99::9')):
                            actual(E,src,v,True,f'v{v} exit permits external return source');actual(E,address(ci,v),v,False,f'v{v} default cannot impersonate exact lease');actual(E,'10.76.0.1' if v==4 else 'fd76::1',v,False,f'v{v} exit cannot claim reserved server source');actual(E,'198.18.16.9' if v==4 else 'fd76:16::9',v,False,f'v{v} default cannot impersonate specific route')
                        actual(G,address(gi,4),4,True,'group IPv4 destination allowed');actual(G,address(gi,6),6,False,'group IPv6 destination refused')
                        actual(U,address(ui,4),4,False,'user override IPv4 refused');actual(U,address(ui,6),6,True,'user override IPv6 allowed')
                        for v in (4,6):
                            dst='198.18.99.9' if v==4 else 'fd76:99::9';value=inject(C,address(ci,v),dst);got=request(E,'RECV')['packet'];check(f'v{v} profile-authorized exit {ctc}',got==value.hex() if ctc else got is None)
                            inject(U,address(ui,v),dst);check(f'v{v} user override cannot use ungranted exit',request(E,'RECV')['packet'] is None)
                        cmd('ip','route','add','198.18.17.0/24','dev','lo');before={c['ip'] for c in clients()};F,fi=connect('F');check('host route conflict refuses entire admission',not fi['accepted'] and {c['ip'] for c in clients()}==before);check('foreign kernel route preserved','dev lo' in cmd('ip','route','show','198.18.17.0/24'));cmd('ip','route','del','198.18.17.0/24','dev','lo')
                        content=(case/'users.ini').read_text();assert 'allowed_networks = 10.76.0.1/32' in content;(case/'users.ini').write_text(content.replace('allowed_networks = 10.76.0.1/32','allowed_networks = fd76::1/128'))
                        control(case,'enable-user',username='G');wait_for(lambda:all(c['username']!='G' for c in clients()),15);check('changed group ACL revokes old compiled policy',all(c['username']!='G' for c in clients()))
                        G,gi=connect('G',2);check('reconnect uses new group policy',gi['accepted']);actual(G,address(gi,4),4,False,'new group IPv4 denied');actual(G,address(gi,6),6,True,'new group IPv6 allowed')
                        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:racers=list(ex.map(connect,('R1','R2')))
                        check('concurrent overlapping admissions accepted with unique leases',all(info['accepted'] for _,info in racers) and len({ip for c in clients() for ip in c['addresses']})==sum(len(c['addresses']) for c in clients()))
                        owners=[]
                        for v,src in ((4,'198.18.18.9'),(6,'fd76:18::9')):
                            seen=[actual(p,src,v,None,f'v{v} concurrent owner probe') for p,_ in racers];check(f'v{v} exactly one concurrent route owner',sum(seen)==1);owners.append(seen.index(True))
                        check('both families share one concurrent owner',owners[0]==owners[1]);winner=owners[0];loser=1-winner;control(case,'kick',username=('R1','R2')[winner]);wait_for(lambda:all(c['username']!=('R1','R2')[winner] for c in clients()))
                        for v,src in ((4,'198.18.18.9'),(6,'fd76:18::9')):actual(racers[loser][0],src,v,False,f'v{v} losing concurrent auth cannot inherit departed route')
                        fresh,info=connect(('R1','R2')[loser]);check('fresh admission claims concurrent route',info['accepted'])
                        for v,src in ((4,'198.18.18.9'),(6,'fd76:18::9')):actual(fresh,src,v,True,f'v{v} fresh concurrent-route owner allowed')
                    for name in {c['username'] for c in clients()}:control(case,'kick',username=name)
                    check('all owners released',not clients());check('nondefault kernel iroutes gone','198.18.16.0/24' not in cmd('ip','route') and 'fd76:16::/64' not in cmd('ip','-6','route'))
                    server.send_signal(signal.SIGTERM);check('clean server exit',server.wait(timeout=20)==0);check('network restored',net()==baseline)
                    results['cases'].append({'transport':transport,'client_to_client':ctc,'status':'PASS','checks':checks});(root/'results.json').write_text(json.dumps(results,indent=2));print('PASS',transport,ctc,len(checks),flush=True)
                finally:
                    for p,e in peers:stop(p);e.close();p.stdin.close();p.stdout.close()
                    for s in sinks:s.close()
                    stop(server)
                    if log:log.close()
        results['status']='REPRODUCED' if a.baseline else 'PASS';results['checks_passed']=sum(len(x['checks']) for x in results['cases']);return 0
    except BaseException:results['status']='FAIL';raise
    finally:(root/'results.json').write_text(json.dumps(results,indent=2))
if __name__=='__main__':raise SystemExit(main())
