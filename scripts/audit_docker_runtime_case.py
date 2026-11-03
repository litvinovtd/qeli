#!/usr/bin/env python3
"""Qualify an existing audit-owned Docker image in private container networks.

Linux root only. Argument: /var/tmp/qeli-q33-docker-<digits> containing its static
Docker tools, private socket/config, image.json and empty volume directory.
Does not install/start Docker or publish images; it never uses the ambient socket.
The owning controller must enforce resource limits, record/restore host state,
archive evidence and stop the owned daemon. All credentials here are synthetic.
"""
from pathlib import Path
import sys,subprocess,json,time,hashlib,stat,os,re,traceback
# Requires an audit-owned daemon/socket, extracted source/image record, and fresh volumes.
r=Path(sys.argv[1]);assert r.resolve()==r and r.parent==Path('/var/tmp') and re.fullmatch(r'qeli-q33-docker-[0-9]+',r.name)
assert len(sys.argv)==2 and not (r/'volumes').exists()
env=os.environ.copy();env['PATH']=str(r/'docker')+':'+env['PATH'];env['DOCKER_CONFIG']=str(r/'cli');env['DOCKER_HOST']='unix://'+str(r/'docker.sock')
d=[str(r/'docker/docker')];image=json.loads((r/'image.json').read_text())[0]['Id'];prefix=r.name;network=prefix+'-net';network_created=False;results={'status':'RUNNING','image':image,'checks':[],'commands':[]}
def save(): (r/'runtime-results.json').write_text(json.dumps(results,indent=2))
def run(args,label,required=True,timeout=45):
 p=subprocess.run(d+args,env=env,capture_output=True,text=True,timeout=timeout);i=len(results['commands']);(r/('runtime-%03d.log'%i)).write_text(p.stdout+p.stderr);results['commands'].append({'argv':args,'rc':p.returncode,'log':'runtime-%03d.log'%i,'label':label});save()
 if required and p.returncode:raise RuntimeError(label+': '+(p.stdout+p.stderr)[-2000:])
 return p.returncode,p.stdout.strip()
def check(label,condition):
 results['checks'].append({'label':label,'pass':bool(condition)});save();print(label+': '+str(bool(condition)),flush=True)
 if not condition:raise AssertionError(label)
def volumes(role):
 for kind in ['etc','lib']:(r/'volumes'/role/kind).mkdir(parents=True,exist_ok=True);(r/'volumes'/role/kind).chmod(0o700)
 return ['-v',str(r/'volumes'/role/'etc')+':/etc/qeli','-v',str(r/'volumes'/role/'lib')+':/var/lib/qeli']
def create(role,extra=None,command=None,img=None):
 return run(['run','-d','--name',prefix+'-'+role,'--label','qeli.audit.root='+str(r),'--network',network,'--ip',('10.93.0.2' if role=='server' else '10.93.0.3'),'--memory','256m','--cpus','0.7','--cap-add','NET_ADMIN','--cap-add','NET_RAW','--device','/dev/net/tun',*volumes(role),*(extra or []),img or image,*(command or [role])],role+' create')[1]
def ex(role,args,required=True):return run(['exec',prefix+'-'+role,*args],role+' '+args[0],required)
def state(role):
 # usage.json is intentionally updated when traffic counters are flushed; identity/config/users must stay exact.
 return {str(p.relative_to(r/'volumes'/role)):{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode),'uid':p.stat().st_uid} for p in sorted((r/'volumes'/role).rglob('*')) if p.is_file() and not (role=='server' and p.relative_to(r/'volumes'/role).as_posix()=='etc/usage.json')}
def traffic(stage):
 deadline=time.monotonic()+35;ok=False
 while time.monotonic()<deadline:
  rc,out=ex('client',['ping','-c','3','-W','2','10.77.1.1'],False)
  if rc==0:ok=True;break
  time.sleep(.5)
 check(stage+' actual authenticated three inner pings',ok)
 check(stage+' route through q33dkvpn','dev q33dkvpn' in ex('client',['ip','route','get','10.77.1.1'])[1])
def stop(role):
 owner=json.loads(run(['inspect',prefix+'-'+role],role+' ownership before stop')[1])[0];assert owner['Config']['Labels'].get('qeli.audit.root')==str(r)
 run(['stop','--time','20',prefix+'-'+role],role+' graceful stop',timeout=30)
 info=json.loads(run(['inspect',prefix+'-'+role],role+' stopped state')[1])[0];check(role+' exits without OOM or forced SIGKILL',not info['State']['OOMKilled'] and info['State']['ExitCode']==0);run(['logs',prefix+'-'+role],role+' final logs');run(['rm',prefix+'-'+role],role+' remove')
try:
 # No defaults, ambient socket, host ports, or host-network Qeli processes.
 run(['network','create','--driver','bridge','--subnet','10.93.0.0/24','--gateway','10.93.0.1','--opt','com.docker.network.bridge.name=q33dkbridge','--opt','com.docker.network.bridge.enable_ip_masquerade=false','--label','qeli.audit.root='+str(r),network],'owned bridge');network_created=True
 for role in ['server','client']:volumes(role)
 rc,text=run(['run','--rm',*volumes('help'),'--network','none',image,'--help'],'actual CLI help');check('help passes actual CLI without seeding files',rc==0 and state('help')=={})
 check('image contains exact qualified release SHA',run(['run','--rm',*volumes('inventory'),'--network','none','--entrypoint','sha256sum',image,'/usr/local/bin/qeli'],'image ELF SHA')[1].split()[0]=='f9c70e679ce68120a19e9ce93c10199860d04c89b7e6c919d1a45efc9b9a3cfd')
 run(['run','--rm',*volumes('inventory'),'--network','none','--entrypoint','sh',image,'-c','qeli --version; dpkg-query -W; command -v ip iptables curl ping dig ss tcpdump'],'actual image dependencies')
 # Seed in actual image by a deliberately invalid server option; no fake executable.
 rc,_=run(['run','--rm',*volumes('seed'),'--network','none',image,'server','--intentional-q33-invalid-option'],'actual first-run seeding',False)
 seed=state('seed');check('new actual seed config and empty users are root0600',rc!=0 and all(seed['etc/'+n]['mode']==0o600 and seed['etc/'+n]['uid']==0 for n in ['server.conf','users.conf']) and (r/'volumes/seed/etc/users.conf').read_bytes()==b'')
 # A readonly first-run volume must fail without partial creation.
 for kind in ['etc','lib']:(r/'readonly'/kind).mkdir(parents=True,exist_ok=True)
 rc,_=run(['run','--rm','--network','none','-v',str(r/'readonly/etc')+':/etc/qeli:ro','-v',str(r/'readonly/lib')+':/var/lib/qeli:ro',image,'server'],'readonly first-run refuses',False)
 check('readonly volume startup fails without writes',rc!=0 and not list((r/'readonly/etc').iterdir()))
 (r/'volumes/server/etc/server.conf').write_text('''[auth]
users_file = /etc/qeli/users.conf
require_client_key_proof = true
[web]
enabled = false
bind = 127.0.0.1
port = 24990
tls = false
[profile:docker]
bind.address = 0.0.0.0
bind.port = 443
bind.transport = tcp
tun.name = q33dkserver
identity_key = /etc/qeli/identity/docker.key
tun.address = 10.77.1.1
pool.cidr = 10.77.1.0/24
routing.forward_private = false
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
''');(r/'volumes/server/etc/server.conf').chmod(0o600)
 for args in [['add-client','audit-docker-user','--password','synthetic-docker-user-password'],['set-web-password','--password','synthetic-docker-panel-password'],['show-identity']]:
  _,text=run(['run','--rm','--network','none',*volumes('server'),'--entrypoint','qeli',image,*args,'--config','/etc/qeli/server.conf'],'actual config CLI '+args[0])
 key=re.findall(r'\b[0-9a-f]{64}\b',text);check('actual server static key available',len(key)==1)
 conf='[qeli]\nserver = 10.93.0.2:443\nproto = tcp\nuser = audit-docker-user\npass = synthetic-docker-user-password\nkey = '+key[0]+'\nmode = fake-tls\ndev = q33dkvpn\ngateway = true\ndns = off\nkill_switch = false\n[logging]\nlevel = info\n'
 (r/'volumes/client/etc/client.conf').write_text(conf);(r/'volumes/client/etc/client.conf').chmod(0o600)
 baseline=state('server');results['baseline_server_state']=baseline;create('server',['--sysctl','net.ipv4.ip_forward=1']);create('client');traffic('fresh')
 initial_state=baseline; baseline=state('server'); check('startup preserves configured state', all(baseline.get(k)==v for k,v in initial_state.items())); results['baseline_server_state']=baseline; save();
 _,health=ex('server',['curl','-sS','-o','/dev/null','-w','%{http_code}','http://127.0.0.1:24990/login']);check('real authenticated panel readiness HTTP200',health=='200')
 info=json.loads(run(['inspect',prefix+'-server',prefix+'-client'],'real security settings')[1]);check('Qeli uses private NET with default AppArmor and seccomp',all(x['HostConfig']['NetworkMode']==network and x['AppArmorProfile']=='docker-default' and not x['HostConfig']['Privileged'] and not x['HostConfig']['PortBindings'] for x in info));results['containers']=info;save()
 for role in ['client','server']:stop(role)
 check('graceful stop preserves server identity/config/users bytes owner mode',state('server')==baseline)
 create('server',['--sysctl','net.ipv4.ip_forward=1']);create('client');traffic('recreated');check('recreation preserves server identity/config/users',state('server')==baseline)
 for role in ['client','server']:stop(role)
 # Deliberate corrupt image has the same volumes, fails visibly; old image ID is recovery.
 (r/'fault').mkdir();(r/'fault/qeli').write_text('intentional invalid ELF\n');(r/'fault/qeli').chmod(0o755);check('local qualified build tag resolves to exact tested image',json.loads(run(['image','inspect','qeli-q33:qualified'],'fault parent image identity')[1])[0]['Id']==image);(r/'fault/Dockerfile').write_text('FROM qeli-q33:qualified\nCOPY qeli /usr/local/bin/qeli\n');run(['build','-t','qeli-q33:fault',str(r/'fault')],'build corrupt runtime image',timeout=90)
 create('server',['--sysctl','net.ipv4.ip_forward=1'],img='qeli-q33:fault');time.sleep(2);bad=json.loads(run(['inspect',prefix+'-server'],'bad image state')[1])[0];check('invalid image exits nonzero and never remains running',not bad['State']['Running'] and bad['State']['ExitCode']!=0);check('failed image preserves volume bytes/owner/mode',state('server')==baseline);run(['logs',prefix+'-server'],'bad image logs');run(['rm',prefix+'-server'],'bad image remove')
 create('server',['--sysctl','net.ipv4.ip_forward=1']);create('client');traffic('rollback-known-image');check('known-image recovery preserves identity/config/users',state('server')==baseline)
 for role in ['client','server']:stop(role)
 results['status']='PASS';save()
except BaseException:
 results['status']='FAIL';results['error']=traceback.format_exc();save();raise
finally:
 for role in ['client','server']:
  name=prefix+'-'+role
  rc,_=run(['inspect',name],'cleanup existence '+role,False)
  if rc==0:
   owner=json.loads(run(['inspect',name],'cleanup ownership '+role)[1])[0];assert owner['Config']['Labels'].get('qeli.audit.root')==str(r)
   run(['logs',name],'cleanup logs '+role,False);run(['stop','--time','20',name],'cleanup graceful '+role,False,30);run(['rm',name],'cleanup container '+role,False)
 if network_created:
  owner=json.loads(run(['network','inspect',network],'cleanup network ownership')[1])[0];assert owner['Labels'].get('qeli.audit.root')==str(r)
  run(['network','rm',network],'remove only owned bridge')
 print(json.dumps({'status':results['status'],'checks':len(results['checks'])}),flush=True)
