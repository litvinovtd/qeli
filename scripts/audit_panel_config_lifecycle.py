#!/usr/bin/env python3
"""Exercise panel INI/form/history/archive/reload in private NET/mount/PID namespaces.
Run through audit_release_matrix_lab.ISOLATED; parent namespace identities are mandatory.
No installed services or systemd restart endpoints are used.
"""
import argparse,concurrent.futures,copy,fcntl,hashlib,http.cookiejar,io,json,os,re,signal,subprocess,tarfile,threading,time,urllib.error,urllib.request
from pathlib import Path

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for name in ['qeli','sha256','artifacts','parent-net','parent-mnt','parent-pid']:ap.add_argument('--'+name,required=True)
 a=ap.parse_args()
 for kind in ['net','mnt','pid']:
  assert os.readlink('/proc/self/ns/'+kind)!=getattr(a,'parent_'+kind),'private '+kind+' namespace required'
 binary=Path(a.qeli).resolve(strict=True);assert hashlib.sha256(binary.read_bytes()).hexdigest()==a.sha256
 root=Path(a.artifacts);root.mkdir(mode=0o700,parents=True,exist_ok=False)
 cfg=Path('/etc/qeli/server.conf');state=root/'state';state.mkdir(mode=0o700)
 results=[];events=[];commands=[];sup=None;completed=False
 event_lock=threading.Lock()
 def check(name,condition,detail=None):
  results.append(dict(name=name,status='PASS' if condition else 'FAIL',detail=detail))
  (root/'checks.json').write_text(json.dumps(results,indent=2)+'\n')
  assert condition,(name,detail)
  print('PASS',name,flush=True)
 def run(argv,ok=True):
  p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=25)
  commands.append(dict(argv=argv,exit_code=p.returncode,output=p.stdout));(root/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  if ok:assert p.returncode==0,(argv,p.stdout)
  return p
 def until(f,label,seconds=25):
  end=time.monotonic()+seconds
  while not f():
   if sup is not None and sup.poll() is not None:raise RuntimeError((root/'supervisor.log').read_text())
   if time.monotonic()>end:raise RuntimeError(label)
   time.sleep(.05)
 def worker_pid():
  children=set()
  for task in Path('/proc',str(sup.pid),'task').iterdir():
   try:children.update((task/'children').read_text().split())
   except FileNotFoundError:pass
  for pid in children:
   try:
    if b'_worker' in Path('/proc',pid,'cmdline').read_bytes().split(b'\0'):return int(pid)
   except FileNotFoundError:pass
  return None
 def rules():
  return {family:[line for line in run([command]).stdout.splitlines() if line.startswith('-A ') or(line.startswith(':') and ' - ' in line)] for family,command in [('v4','iptables-save'),('v6','ip6tables-save')]}
 def network():
  return dict(rules=rules(),links=sorted(x['ifname'] for x in json.loads(run(['ip','-j','link']).stdout)),routes4=run(['ip','-4','route','show','table','all']).stdout,routes6=run(['ip','-6','route','show','table','all']).stdout,forward4=Path('/proc/sys/net/ipv4/ip_forward').read_text().strip(),forward6=Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip())
 def manual_write(text):
  with open(str(cfg)+'.lock','a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX);cfg.write_text(text);cfg.chmod(0o600)
 base='http://127.0.0.1:24480';password='private-audit-fixture-only';username='admin'
 jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
 def request(path,method='GET',body=None,opener=None,binary_response=False):
  headers={'Origin':base,'Referer':base+'/'}
  if isinstance(body,bytes):headers['Content-Type']='application/gzip';data=body
  elif body is not None:headers['Content-Type']='application/json';data=json.dumps(body).encode()
  else:data=None
  req=urllib.request.Request(base+path,data=data,headers=headers,method=method)
  try:
   with (opener or client).open(req,timeout=30) as r:code=r.status;raw=r.read()
  except urllib.error.HTTPError as r:code=r.code;raw=r.read()
  if binary_response:return code,raw
  try:value=json.loads(raw)
  except json.JSONDecodeError:value={'body':raw.decode(errors='replace')}
  # Fixture-only responses; GET raw/form already mask hashes and keys.
  with event_lock:
   events.append(dict(path=path,method=method,status=code,response=value));(root/'http.json').write_text(json.dumps(events,indent=2)+'\n')
  return code,value
 def getraw():
  code,v=request('/api/config/raw');assert code==200 and v.get('ok'),v;return v
 def save(raw,revision=None):return request('/api/config/raw','PUT',{'raw':raw,**({'expected_revision':revision} if revision is not None else {})})[1]
 def snapshot_id(v):
  item=v['snapshot'];return item['id'] if isinstance(item,dict) else item
 def restore(v,revision):return request('/api/config/history/'+snapshot_id(v)+'/restore','POST',{'expected_revision':revision})[1]
 for cmd in [['ip','link','set','lo','up'],['ip','link','add','wan0','type','dummy'],['ip','link','set','wan0','up'],['ip','addr','add','192.0.2.1/24','dev','wan0'],['ip','route','add','default','dev','wan0'],['iptables','-A','INPUT','-s','198.51.100.0/24','-j','DROP']]:run(cmd)
 Path('/proc/sys/net/ipv4/ip_forward').write_text('0');Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('0')
 Path('/etc/qeli/users.conf').write_text('')
 text='''[auth]
users_file = /etc/qeli/users.conf
[web]
enabled = true
bind = 127.0.0.1
port = 24480
tls = false
secure_cookie = false
brute_force.max_attempts = 100
[logging]
level = debug
'''
 for name,proto,port,net in [('a','tcp',24443,73),('b','udp',24444,74)]:
  text+=f'''[profile:mixed{name}]
identity_key = /etc/qeli/mixed{name}.key
bind.address = 127.0.0.1
bind.port = {port}
bind.transport = {proto}
tun.name = qmixed{name}
tun.address = 10.{net}.0.1
tun.queues = 1
pool.cidr = 10.{net}.0.0/24
routing.nat.enabled = true
routing.nat.interface = wan0
routing.forward_private = true
routing.ipv6.mode = off
routing.post_up = printf up >> {root}/up-{name}
routing.post_down = printf down >> {root}/down-{name}
dns.enabled = false
obf.mode = fake-tls
'''
 cfg.write_text(text);cfg.chmod(0o600)
 run([str(binary),'set-web-password','--username',username,'--password',password,'--config',str(cfg)])
 before=network();env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_CONTROL_SOCKET=str(root/'control.sock'))
 logfile=(root/'supervisor.log').open('w')
 try:
  sup=subprocess.Popen([str(binary),'server','-c',str(cfg)],env=env,stdout=logfile,stderr=subprocess.STDOUT)
  until(lambda:(root/'up-a').exists() and (root/'up-b').exists() and ':24443' in run(['ss','-lnt']).stdout and ':24444' in run(['ss','-lnu']).stdout,'profiles not ready')
  until(lambda:request('/login',binary_response=True)[0]==200,'panel not ready')
  check('authenticated panel login',request('/api/login','POST',dict(username=username,password=password))[1].get('ok'))
  initial_pid=worker_pid();check('real worker owned by supervisor',initial_pid is not None)
  keys={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/qeli').glob('mixed*.key')}
  initial=getraw();baseline_bytes=cfg.read_bytes()
  check('raw API masks password',password not in initial['raw'] and '$argon2' not in initial['raw'])
  denied=save(initial['raw']);check('INI write requires revision',denied.get('kind')=='config_revision_required' and cfg.read_bytes()==baseline_bytes)
  for label,bad in [('unknown key',initial['raw']+'unknown.setting = bad\n'),('bad MTU',initial['raw']+'tun.mtu = broken\n'),('changed privileged hook',initial['raw'].replace('printf up >>','printf altered >>',1))]:
   v=save(bad,initial['revision']);check('refuse '+label,not v.get('ok') and cfg.read_bytes()==baseline_bytes,v)
  code,form=request('/api/config');candidate=copy.deepcopy(form['config']);candidate['profiles'][0]['bind']['port']=99999
  code,v=request('/api/config','PUT',dict(config=candidate,expected_revision=form['revision']));check('form refuses port overflow',not v.get('ok') and cfg.read_bytes()==baseline_bytes,v)
  candidate=copy.deepcopy(form['config']);candidate['web']['brute_force']['max_attempts']=77
  code,v=request('/api/config','PUT',dict(config=candidate,expected_revision=form['revision']));check('form applies live web policy',v.get('ok') and v.get('web_settings_applied'),v)
  policy=request('/api/blocked/settings')[1];check('live policy matches saved INI',policy['panel_applied'] and policy['live_panel']['max_attempts']==77,policy)
  check('form preserves masked password',request('/api/login','POST',dict(username=username,password=password))[1].get('ok'))
  raw=getraw();stale=save(initial['raw'],initial['revision']);check('stale other editor refuses overwrite',stale.get('kind')=='config_conflict',stale)
  barrier=threading.Barrier(2)
  def race(name):barrier.wait();return save('# '+name+'\n'+raw['raw'],raw['revision'])
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   futures=[pool.submit(race,name) for name in ['tab-a','tab-b']];answers=[f.result() for f in futures]
  check('concurrent tabs have exactly one winner',sum(bool(x.get('ok')) for x in answers)==1 and sum(x.get('kind')=='config_conflict' for x in answers)==1,answers)
  check('successful save creates private INI',cfg.stat().st_mode&0o777==0o600)
  raw=getraw();lock=Path(str(cfg)+'.lock');lock_inode=lock.stat().st_ino
  locked=root/'writer-locked';release=root/'writer-release'
  writer=subprocess.Popen(['python3','-c','import fcntl,sys,time;from pathlib import Path;p=Path(sys.argv[1]);f=open(str(p)+".lock","a");fcntl.flock(f,fcntl.LOCK_EX);p.write_text("# external writer\\n"+p.read_text());Path(sys.argv[2]).touch();\nwhile not Path(sys.argv[3]).exists():time.sleep(.02)',str(cfg),str(locked),str(release)])
  try:
   until(locked.exists,'writer did not lock')
   with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
    pending=pool.submit(save,raw['raw'],raw['revision']);time.sleep(.3);check('panel waits for cooperative external writer',not pending.done());release.touch();writer.wait(timeout=5);v=pending.result()
   check('external writer bytes survive panel conflict',v.get('kind')=='config_conflict' and cfg.read_text().startswith('# external writer'),v)
  finally:
   release.touch()
   if writer.poll() is None:writer.kill();writer.wait(timeout=5)
  raw=getraw();manual_write('# hand edit\n'+cfg.read_text());v=save(raw['raw'],raw['revision']);check('completed hand edit detected by revision',v.get('kind')=='config_conflict',v)
  raw=getraw();v=save(raw['raw'].replace('port = 24480','port = 24481'),raw['revision']);check('startup-only web save reports full restart',v.get('ok') and v['needs_full_restart'],v)
  refused=request('/api/server/restart','POST',{})[1];check('worker restart refuses startup-only web change',refused.get('kind')=='full_restart_required' and worker_pid()==initial_pid,refused)
  rollback=restore(v,getraw()['revision']);check('history restore applies live and clears full restart',rollback.get('ok') and rollback['web_settings_applied'] and not rollback['needs_full_restart'],rollback)
  check('history requires current revision',request('/api/config/history/'+snapshot_id(v)+'/restore','POST',{})[1].get('kind')=='config_revision_required')
  raw=getraw();changed=re.sub(r'(?m)^bind\.port\s*=\s*24443$', 'bind.port = 24445',raw['raw']);check('fixture targets exactly one TCP bind',changed!=raw['raw'])
  saved=save(changed,raw['revision']);check('profile save is deferred until worker restart',saved.get('ok') and not saved['needs_full_restart'] and worker_pid()==initial_pid and ':24443' in run(['ss','-lnt']).stdout,saved)
  check('worker restart accepted',request('/api/server/restart','POST',{})[1].get('ok'))
  until(lambda:worker_pid() not in [None,initial_pid] and ':24445' in run(['ss','-lnt']).stdout,'new worker not ready')
  new_pid=worker_pid();check('restart applies TCP bind and preserves supervisor',sup.poll() is None and ':24443' not in run(['ss','-lnt']).stdout)
  good=cfg.read_text();manual_write(good+'tun.mtu = broken\n');os.kill(new_pid,signal.SIGHUP);time.sleep(.3)
  refused=request('/api/server/restart','POST',{})[1];check('bad hand edit preserves active worker',not refused.get('ok') and worker_pid()==new_pid and ':24445' in run(['ss','-lnt']).stdout,refused)
  manual_write(good);os.kill(new_pid,signal.SIGHUP);time.sleep(.2)
  raw=getraw();quick=request('/api/config/quickstart/fake-tls','POST',dict(expected_revision=raw['revision'],ip_mode='ipv4'))[1]
  check('Quick Start saves validated profile',quick.get('ok'),quick);check('Quick Start INI passes CLI',run([str(binary),'check-config','-c',str(cfg)],False).returncode==0)
  check('Quick Start does not restart worker implicitly',worker_pid()==new_pid)
  restored=restore(quick,getraw()['revision']);check('Quick Start can roll back through shared history',restored.get('ok'),restored)
  code,archive=request('/api/backup',binary_response=True);check('backup downloads gzip snapshot',code==200 and archive[:2]==b'\x1f\x8b');(root/'backup.tar.gz').write_bytes(archive)
  lock_inode=lock.stat().st_ino;keys_before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/qeli').glob('mixed*.key')}
  with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:
   members=tar.getmembers();configs=[m for m in members if m.name.rstrip('/')=='qeli/server.conf'];assert len(configs)==1;archived_ini=tar.extractfile(configs[0]).read()
  raw=getraw();v=save('# after backup\n'+raw['raw'],raw['revision']);assert v.get('ok');Path('/etc/qeli/obsolete.conf').write_text('fixture-only')
  badarchive=io.BytesIO()
  with tarfile.open(fileobj=badarchive,mode='w:gz') as tar:
   for member in members:
    if not member.isfile():tar.addfile(member);continue
    with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as source:data=source.extractfile(member).read()
    if member.name.rstrip('/')=='qeli/server.conf':data+=b'\n[profile:broken]\nbind.transport = invalid\n'
    member=copy.copy(member);member.size=len(data);tar.addfile(member,io.BytesIO(data))
  bytes_before=cfg.read_bytes();code,bad=request('/api/restore','POST',badarchive.getvalue());check('malformed archive refuses publication',code==400 and not bad.get('ok') and cfg.read_bytes()==bytes_before,bad)
  code,v=request('/api/restore?exact=true','POST',archive);check('exact archive restore succeeds',code==200 and v.get('ok'),v)
  check('archive restores exact INI bytes',cfg.read_bytes()==archived_ini)
  check('exact restore preserves lock inode and identity',lock.stat().st_ino==lock_inode and keys_before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/qeli').glob('mixed*.key')} and not Path('/etc/qeli/obsolete.conf').exists())
  check('archive restore leaves active generation until explicit restart',worker_pid()==new_pid and sup.poll() is None)
  raw=getraw();code,h=request('/api/hash-password','POST',dict(password='fixture-password-two'));assert h['hash'].startswith('$argon2')
  newraw=re.sub(r'(?m)^password_hash\s*=.*$',lambda m:'password_hash = '+h['hash'],raw['raw']);v=save(newraw,raw['revision']);check('password change applies live',v.get('ok') and v['web_settings_applied'],v)
  check('old authenticated cookie rejected',request('/api/config')[0]==401)
  check('old password rejected',not request('/api/login','POST',dict(username=username,password=password))[1].get('ok'))
  check('new password accepted without process restart',request('/api/login','POST',dict(username=username,password='fixture-password-two'))[1].get('ok') and worker_pid()==new_pid)
  sup.send_signal(signal.SIGTERM);exit_code=sup.wait(timeout=25);check('normal supervisor and worker stop',exit_code==0,exit_code)
  check('network and foreign rules restored',network()==before)
  check('identity keys survive every save and worker restart',keys=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/qeli').glob('mixed*.key')})
  check('ownership journal and control socket removed',not (state/'sysctls.state').exists() and not(root/'control.sock').exists())
  completed=True
 finally:
  if sup is not None and sup.poll() is None:sup.kill();sup.wait(timeout=5)
  logfile.close();(root/'result.json').write_text(json.dumps(dict(artifact_sha256=a.sha256,checks=results,status='PASS' if completed and results and all(r['status']=='PASS' for r in results) else 'FAIL',check_count=len(results)),indent=2)+'\n')
 return 0

if __name__=='__main__':raise SystemExit(main())
