"""Q15 private session fixture; fresh NET/mount/PID only."""
import argparse, concurrent.futures, json, os, select, signal, subprocess, sys, time, threading, socket
from pathlib import Path
from audit_udp_handshake_contracts import hashed, control, stop, wait_for

def ns(k): return os.readlink('/proc/self/ns/'+k)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--qeli',required=True);ap.add_argument('--peer',required=True);ap.add_argument('--root',type=Path,required=True);ap.add_argument('--inside',action='store_true');a=ap.parse_args()
    root=a.root.resolve();binary=str(Path(a.qeli).resolve(strict=True));peer=str(Path(a.peer).resolve(strict=True))
    if not a.inside:
        assert os.geteuid()==0;root.mkdir(mode=0o700)
        env=dict(os.environ,**{'Q15_PARENT_'+k.upper():ns(k) for k in ('net','mnt','pid')})
        return subprocess.run(['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,__file__,'--qeli',binary,'--peer',peer,'--root',str(root),'--inside'],env=env,timeout=420).returncode
    assert all(ns(k)!=os.environ['Q15_PARENT_'+k.upper()] for k in ('net','mnt','pid'))
    def cmd(*args):
        p=subprocess.run(args,capture_output=True,text=True)
        if p.returncode:raise RuntimeError((args,p.stdout,p.stderr))
        return p.stdout
    cmd('mount','--make-rprivate','/');cmd('ip','link','set','lo','up')
    for path in ('/run','/var/lib','/var/log'):cmd('mount','-t','tmpfs','tmpfs',path)
    Path('/var/lib/qeli').mkdir();Path('/var/log/qeli').mkdir();etc=root/'etc';etc.mkdir(mode=0o700);cmd('mount','--bind',str(etc),'/etc/qeli')
    def net():return {k:cmd(*v) for k,v in {'links':['ip','-br','addr'],'routes4':['ip','-4','route','show','table','all'],'routes6':['ip','-6','route','show','table','all']}.items()}
    baseline=net();results={'status':'RUNNING','cases':[]};password_hash=hashed()
    try:
        for transport in ('tcp','udp','quic'):
            for kind in ['quota']:
                case=root/(transport+'-'+kind);case.mkdir(mode=0o700);(case/'state').mkdir();checks=[];processes=[];counter=0;number_lock=threading.Lock()
                def check(name,value):
                    checks.append({'name':name,'passed':bool(value)});(case/'checks.json').write_text(json.dumps(checks,indent=2));assert value,name
                users={name:dict(max_sessions=0) for name in ('fixture','u1','u2','u3','u4')};users['fixture']['max_sessions']=2 if kind=='caps' else 0
                text=''.join('[user:'+name+']\npassword_hash = '+password_hash+'\nenabled = true\n'+''.join(k+' = '+str(v)+'\n' for k,v in fields.items()) for name,fields in users.items());(case/'users.ini').write_text(text)
                dual='tun.ip_mode = dual\ntun.ipv6_address = fd75::1\npool.ipv6.cidr = fd75::/126\n' if kind=='dual-pool' else ''
                pool='/30' if kind=='reap' else '/29';extra='pool.exclude = 10.75.0.5\npool.reservation.u4 = 10.75.0.6\n' if kind=='caps' else ''
                cfg=f'''[auth]
users_file = {case}/users.ini
require_client_key_proof = true
bind_static_to_session = false
[web]
enabled = false
[logging]
level = debug
[profile:sessions]
identity_key = {case}/identity.key
bind.address = 127.0.0.1
bind.port = 24943
bind.transport = {'tcp' if transport=='tcp' else 'udp'}
tun.name = q15srv
tun.address = 10.75.0.1
tun.queues = 1
pool.cidr = 10.75.0.0{pool}
{dual}{extra}routing.nat.enabled = false
routing.ipv6.mode = {'manual' if dual else 'off'}
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 5000
obf.heartbeat.jitter_ms = 100
obf.traffic_shaping.enabled = false
perf.connection.idle_timeout_secs = 0
perf.connection.max_clients = {2 if kind=='caps' else 16}
perf.connection.handshake_timeout_secs = 6
perf.connection.new_session_rate_max = 1000
'''
                (case/'server.ini').write_text(cfg);(case/'server.ini').chmod(0o600)
                usage={'fixture':{'used_down':1_000_000_000,'used_up':0,'used_bytes':1_000_000_000,'last_seen':int(time.time()),'sessions':1}} if kind=='quota' else {}
                (etc/'usage.json').write_text(json.dumps(usage));env=dict(os.environ,STATE_DIRECTORY=str(case/'state'),QELI_CONTROL_SOCKET=str(case/'control.sock'))
                cmd(binary,'check-config','-c',str(case/'server.ini'))
                log=(case/'server.log').open('w');server=subprocess.Popen([binary,'server','-c',str(case/'server.ini')],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                def clients():return control(case,'list-clients')['clients']
                def connect(user='fixture',device=1,live=True):
                    nonlocal counter
                    with number_lock: number=counter;counter+=1
                    err=(case/f'peer-{number}.log').open('w');p=subprocess.Popen([peer,transport,'127.0.0.1:24943',str(case/'identity.key'),user,str(device),'data' if live else 'quiet'],stdout=subprocess.PIPE,stderr=err,text=True,start_new_session=True);processes.append((p,err))
                    if not select.select([p.stdout],[],[],10)[0]:raise AssertionError('peer readiness timeout')
                    line=p.stdout.readline();assert line,(number,p.poll());data=json.loads(line);assert data['server_proof_verified'];(case/f'peer-{number}.json').write_text(json.dumps(data));return data
                def empty():
                    for name in {c['username'] for c in clients()}:control(case,'kick',username=name)
                    wait_for(lambda:not clients())
                try:
                    wait_for(lambda:(case/'control.sock').exists() and ':24943' in cmd('ss','-lnt' if transport=='tcp' else '-lnu'),15)
                    if kind=='caps':
                        check('first device accepted',connect(device=1)['accepted']);first=clients()[0]['peer']
                        check('second device coexists',connect(device=2)['accepted'] and len(clients())==2)
                        check('third replaces oldest at cap',connect(device=3)['accepted'] and len(clients())==2 and first not in {c['peer'] for c in clients()})
                        before={c['peer']:c['ip'] for c in clients()};check('same device reconnect accepted',connect(device=3)['accepted']);after=clients()
                        check('reconnect retains cap and unrelated owner',len(after)==2 and len(set(before)&{c['peer'] for c in after})==1 and set(before.values())=={c['ip'] for c in after})
                        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:burst=list(ex.map(lambda d:connect(device=d),range(10,16)))
                        check('concurrent auth bounded by per-user cap',all(x['accepted'] for x in burst) and len(clients())==2)
                        check('concurrent owners have unique nonexcluded IPs',len({c['ip'] for c in clients()})==2 and all(c['ip'] not in ('10.75.0.1','10.75.0.5','10.75.0.6') for c in clients()))
                        empty();check('kick removes all owners',not clients())
                        check('fresh user reuses released capacity',connect('u1',20)['accepted']);check('global cap accepts second',connect('u2',21)['accepted'] and len(clients())==2)
                        check('global cap rejects third preserving owners',not connect('u3',22)['accepted'] and len(clients())==2)
                        empty();check('reservation honored after churn',connect('u4',23)['accepted'] and clients()[0]['ip']=='10.75.0.6');empty()
                    elif kind=='dual-pool':
                        check('first dual admitted',connect('u1',1)['accepted']);check('second dual admitted',connect('u2',2)['accepted'])
                        check('two families unique',len(clients())==2 and all(len(c['addresses'])==2 for c in clients()) and len({ip for c in clients() for ip in c['addresses']})==4)
                        old={c['peer'] for c in clients()};check('IPv6 exhaustion rejects whole dual set',not connect('u3',3)['accepted'] and {c['peer'] for c in clients()}==old)
                        control(case,'kick',username='u1');check('kick releases both families',connect('u3',3)['accepted'] and len(clients())==2)
                        for d in range(4,8):check('same-device dual reconnect '+str(d),connect('u3',3)['accepted'] and len(clients())==2)
                        empty();check('dual owners removed',not clients());check('dual lease reusable after failures',connect('u4',4)['accepted']);empty()
                    elif kind=='quota':
                        sink=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sink.bind(('10.75.0.1',25801));sink.setblocking(False)
                        def received(seconds):
                            if select.select([sink],[],[],seconds)[0]:
                                value,addr=sink.recvfrom(1024);assert value==b'Q15UP!';return True
                            return False
                        def cutoff(name):
                            time.sleep(.5)
                            while received(0):pass
                            check(name,not received(2.5))
                        check('unlimited account with persisted usage admitted',connect()['accepted'])
                        check('authenticated data traverses actual TUN',received(5))
                        control(case,'set-limit',username='fixture',data_limit_gb=1);wait_for(lambda:not clients(),15);check('quota sweep removes live owner',not clients());cutoff('quota stops actual uplink');check('overquota new auth refused',not connect(device=2)['accepted'])
                        control(case,'reset-usage',username='fixture');check('reset admits account',connect(device=3)['accepted'])
                        control(case,'set-limit',username='fixture',data_limit_gb=1,expire_at=int(time.time())-1);wait_for(lambda:not clients(),15);check('expiry sweep removes live owner',not clients());cutoff('expiry stops actual uplink');check('expired new auth refused',not connect(device=4)['accepted'])
                        control(case,'set-limit',username='fixture',data_limit_gb=0);check('removing expiry restores admission',connect(device=5)['accepted'])
                        control(case,'disable-user',username='fixture');wait_for(lambda:not clients());check('disable revokes owner',not clients());cutoff('disable stops actual uplink');check('disabled auth refused',not connect(device=6)['accepted'])
                        control(case,'enable-user',username='fixture');check('reenable restores admission',connect(device=7)['accepted']);check('reenable restores actual TUN uplink',received(5));empty();sink.close()
                    else:
                        check('quiet UDP peer admitted',connect(live=False)['accepted']);old=clients()[0]['ip'];stop(processes[-1][0])
                        check('one-address pool rejects second',not connect('u1',2)['accepted']);started=time.monotonic();wait_for(lambda:not clients(),70);check('dead UDP peer reaped with idle_timeout zero',not clients());check('reaped lease reusable',connect('u1',3)['accepted'] and clients()[0]['ip']==old);empty();checks.append({'name':'reap seconds','passed':True,'seconds':time.monotonic()-started})
                    server.send_signal(signal.SIGTERM);check('server stop succeeds',server.wait(timeout=20)==0);check('TUN removed','q15srv' not in cmd('ip','-br','link'));check('network restored',net()==baseline)
                    results['cases'].append({'transport':transport,'kind':kind,'status':'PASS','checks':checks});(root/'results.json').write_text(json.dumps(results,indent=2));print('PASS',transport,kind,len(checks),flush=True)
                finally:
                    for p,e in processes:stop(p);e.close();p.stdout.close()
                    stop(server);log.close()
        results['status']='PASS';results['checks_passed']=sum(len(c['checks']) for c in results['cases']);return 0
    except BaseException:results['status']='FAIL';raise
    finally:(root/'results.json').write_text(json.dumps(results,indent=2))
if __name__=='__main__':raise SystemExit(main())
