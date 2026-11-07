"""Real fake-TLS client/server + ordinary TUN and simulated OpkgTun address owner.
Run ONLY inside private mount/PID/network namespaces, with PID=1.
Arguments: client server output-directory parent-netns parent-mountns.
"""
import json,os,subprocess,sys,tempfile,time
from pathlib import Path
assert os.getpid()==1 and len(sys.argv)==6,'requires private PID namespace and explicit fixture arguments'
assert os.readlink('/proc/self/ns/net')!=sys.argv[4]
assert os.readlink('/proc/self/ns/mnt')!=sys.argv[5]
CLIENT,SERVER=map(lambda p:Path(p).resolve(),sys.argv[1:3])
BASE=Path(sys.argv[3]).resolve()
def run(*args,input=None):
    p=subprocess.run(list(map(str,args)),input=input,text=True,capture_output=True,timeout=15)
    if p.returncode:raise RuntimeError(f'{args[0]} failed: {p.stderr[:1000]}')
    return p.stdout
def cip(*args):return run('ip','netns','exec','status-client',*args)
def wait(test,label,timeout=30):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        try:
            if test():return
        except (FileNotFoundError,json.JSONDecodeError):pass
        time.sleep(.1)
    raise RuntimeError('timeout: '+label)
def write(p,s):p.write_text(s);p.chmod(0o600)
run('mount','--make-rprivate','/')
run('mount','-t','tmpfs','tmpfs','/run');run('mount','-t','sysfs','sysfs','/sys')
work=Path(tempfile.mkdtemp(prefix='native-status-',dir=BASE));work.chmod(0o700)
run('ip','link','set','lo','up');run('ip','netns','add','status-client')
run('ip','link','add','server-wan','type','veth','peer','name','client-wan')
run('ip','link','set','client-wan','netns','status-client')
run('ip','addr','add','192.0.2.1/24','dev','server-wan');run('ip','link','set','server-wan','up')
cip('ip','link','set','lo','up');cip('ip','addr','add','192.0.2.2/24','dev','client-wan');cip('ip','link','set','client-wan','up')
users=work/'users.ini';write(users,'')
cfg=work/'server.ini';write(cfg,f'''[auth]
users_file = {users}
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:audit]
identity_key = {work}/identity.key
bind.address = 192.0.2.1
bind.port = 24443
bind.transport = tcp
tun.name = status-server
tun.address = 10.86.0.1
pool.cidr = 10.86.0.0/24
pool.exclude = 10.86.0.1
routing.nat.enabled = false
routing.ipv6.mode = off
routing.forward_private = true
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = true
obf.heartbeat.interval_ms = 1000
obf.heartbeat.jitter_ms = 0
''')
env=dict(os.environ,STATE_DIRECTORY=str(work),QELI_KNOWN_HOSTS=str(work/'known-hosts'),QELI_DEVICE_ID_FILE=str(work/'device-id'),QELI_CLIENT_STATUS_FORMAT='router')
run(SERVER,'add-client','audit','--password-stdin','--profiles','audit','--static-ip','10.86.0.2','-c',cfg,input='fixture-password\n')
children=[];logs=[];report={'passed':[]}
def start(argv,log,environment=None):
    f=log.open('w');logs.append(f);p=subprocess.Popen(list(map(str,argv)),env=environment,stdout=f,stderr=subprocess.STDOUT);children.append(p);return p
def passed(label):report['passed'].append(label);print('PASS',label,flush=True)
try:
    server=start([SERVER,'server','-c',cfg],work/'server.log',env)
    for attach,device in [(False,'qeli-normal'),(True,'qeli-attached')]:
        runtime=work/device;runtime.mkdir(mode=0o700)
        status=runtime/'status.json';pid=runtime/'pid';conf=runtime/'client.ini'
        if attach:
            cip('ip','tuntap','add','dev',device,'mode','tun');cip('ip','link','set',device,'up')
        write(conf,f'''[qeli]
server = 192.0.2.1:24443
proto = tcp
user = audit
pass = fixture-password
mode = fake-tls
dev = {device}
dev_attach = {str(attach).lower()}
bind_static = false
gateway = false
pull_routes = false
dns = off
kill_switch = false
timeout = 2
''')
        client=start(['ip','netns','exec','status-client',CLIENT,'--config',conf],runtime/'client.log',dict(env,QELI_CLIENT_STATUS=str(status)))
        generation=Path(f'/proc/{client.pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
        write(pid,f'{client.pid} {generation}\n')
        def body():return json.loads(status.read_text())
        def native():return json.loads(cip(CLIENT,'router','status','--file',status,'--pid-file',pid,'--device',device))
        if attach:
            wait(lambda:body()['tunnel'].get('last_error_code')=='network_not_ready','authenticated attach waits for NDM address')
            assert body()['tunnel']['state']=='connecting' and body()['tunnel']['addresses']==['10.86.0.2']
            assert native()['state']=='connecting';passed('real authenticated dev_attach waits for external address assignment')
            cip('ip','address','add','10.86.0.2/32','dev',device)
        wait(lambda:body()['tunnel']['state']=='connected','connected '+device)
        assert native()['state']=='connected';time.sleep(3);assert native()['state']=='connected'
        passed(('OpkgTun-like attach' if attach else 'ordinary TUN')+' publishes Connected and retains idle session')
        if attach:
            cip('ip','address','del','10.86.0.2/32','dev',device)
            wait(lambda:body()['tunnel']['state']=='connecting','withdrawn assigned address')
            assert client.poll() is None;passed('external address withdrawal clears Connected without killing transport')
            cip('ip','address','add','10.86.0.2/32','dev',device)
            wait(lambda:body()['tunnel']['state']=='connected','address restored')
        client.terminate();client.wait(timeout=10)
        assert not native()['available'];passed(device+' dead process cannot keep stale Connected')
    assert server.poll() is None
finally:
    if sys.exc_info()[0]:report['error']=str(sys.exc_info()[1])
    for child in reversed(children):
        if child.poll() is None:child.terminate()
    for child in children:
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:child.kill();child.wait()
    for log in logs:log.close()
    (BASE/'native-status-result.json').write_text(json.dumps(report,indent=2))
