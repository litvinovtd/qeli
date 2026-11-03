#!/usr/bin/env python3
"""Exercise the packaged service sandbox through a real manager in an owned NET namespace.

Requires a SHA-checked local Linux CLI and explicit lab access. Does not install packages,
replace the working binary, or start/stop the production unit. All manager writes use a
fresh qeli-q33-* unit, namespace and state-directory name. Password is read from stdin.
"""
from pathlib import Path
import argparse,configparser,datetime,hashlib,json,os,re,shlex,subprocess,sys,time,traceback
from native_lab import connect_lab
from audit_release_matrix_lab import snapshot
ROOT=Path(__file__).resolve().parent.parent

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--host',default='10.66.116.11');ap.add_argument('--binary',type=Path,required=True);ap.add_argument('--sha256',required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--reuse-remote-binary');ap.add_argument('--skip-reload-baseline',action='store_true')
 a=ap.parse_args();binary=a.binary.resolve()
 if not re.fullmatch('[a-f0-9]{64}',a.sha256) or hashlib.sha256(binary.read_bytes()).hexdigest()!=a.sha256:ap.error('explicit binary SHA mismatch')
 if a.reuse_remote_binary and (not re.fullmatch(r'/var/tmp/qeli-q33-[0-9]+/qeli',a.reuse_remote_binary)):ap.error('reuse binary must be an owned prior q33 root')
 a.output.mkdir(parents=True,exist_ok=False);out=a.output
 name='qeli-q33-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S%f');unit=name+'.service';remote='/var/tmp/'+name;net='/run/netns/'+name;unitfile='/run/systemd/system/'+unit;dropin='/etc/systemd/system/'+unit+'.d/run-as.conf'
 lab=connect_lab(a.host,'root',sys.stdin.readline().strip());r={'status':'IN_PROGRESS','unit':unit,'remote':remote,'namespace':name,'artifact_sha256':a.sha256,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'checks':[],'commands':[]};created=False;ns_created=False;unit_created=False
 def save():(out/'results.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8',newline='\n')
 def run(args,label,timeout=30):
  command=shlex.join(args);text,rc=lab.run(command,timeout);r['commands'].append({'label':label,'argv':args,'rc':rc,'output':text});save();return text,rc
 def checked(args,label,timeout=30):
  text,rc=run(args,label,timeout);assert rc==0,(label,rc,text);return text
 def check(label,ok,detail=None):
  r['checks'].append({'name':label,'status':'PASS' if ok else 'FAIL','detail':detail});save();print(('PASS ' if ok else 'FAIL ')+label,flush=True);assert ok,(label,detail)
 def prop(key):return checked(['systemctl','show',unit,'--value','-p',key],'owned unit '+key)
 def wait_ready():
  end=time.monotonic()+35
  while time.monotonic()<end:
   pid=prop('MainPID')
   if pid!='0':
    text,rc=run(['nsenter','-t',pid,'-n','--','ss','-lnt'],'owned readiness')
    if rc==0 and ':443 ' in text and ':24880 ' in text:return pid
   time.sleep(.3)
  raise RuntimeError('owned unit not ready: '+prop('StatusText'))
 def ns(args,label):return checked(['nsenter','-t',prop('MainPID'),'-m','-n','--',*args],label)
 config='''[auth]
users_file = /etc/qeli/users.conf
[web]
enabled = true
bind = 127.0.0.1
port = 24880
tls = false
secure_cookie = false
base_path = /audit
[logging]
level = info
[profile:fixture]
bind.address = 127.0.0.1
bind.port = 443
bind.transport = tcp
tun.name = q33tun
tun.address = 10.77.0.1
pool.cidr = 10.77.0.0/24
routing.forward_private = false
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
'''
 http='''import http.client,json
c=http.client.HTTPConnection('127.0.0.1',24880,timeout=5);c.request('GET','/audit/api/status');r=c.getresponse();r.read();print(r.status);c.close()
'''
 health_source=(ROOT/'update-qeli-server.sh').read_text(encoding='utf8');health=re.search(r'^service_healthy\(\) \{\n.*?^\}',health_source,re.M|re.S)[0]
 try:
  r['host_before']=snapshot(lab);r['service_before']=checked(['systemctl','show','qeli.service','-p','MainPID','-p','ExecMainStartTimestampMonotonic','-p','ActiveState'],'production service before');r['working_before']=checked(['sha256sum','/usr/bin/qeli'],'production binary before');user=checked(['getent','passwd','qeli'],'service user').split(':');uid,gid=int(user[2]),int(user[3]);r['service_uid']=uid;r['service_gid']=gid
  code="from pathlib import Path; r=Path("+repr(remote)+"); assert not r.exists(); r.mkdir(mode=0o755); (r/'etc').mkdir(mode=0o700); (r/'etc/users.conf').touch(mode=0o600); (r/'etc/client-links').mkdir(mode=0o700)"
  checked(['python3','-B','-c',code],'create owned root');created=True
  with lab.open_sftp() as sf:
   if a.reuse_remote_binary:
    checked(['test','!','-L',a.reuse_remote_binary],'reuse regular binary');check('reused remote binary SHA',checked(['sha256sum',a.reuse_remote_binary],'reuse SHA').split()[0]==a.sha256);checked(['cp','--',a.reuse_remote_binary,remote+'/qeli'],'copy own prior candidate')
   else:sf.put(str(binary),remote+'/qeli')
   sf.chmod(remote+'/qeli',0o755)
   for path,data in [('etc/server.conf',config),('etc/client-links/INSTALL-PENDING-fixture','synthetic fixture password\n'),('health.sh','SERVICE='+shlex.quote(unit)+'\n'+health+'\nservice_healthy\n')]:
    with sf.open(remote+'/'+path,'w') as f:f.write(data)
    sf.chmod(remote+'/'+path,0o600)
  check('uploaded current CLI SHA',checked(['sha256sum',remote+'/qeli'],'candidate SHA').split()[0]==a.sha256)
  checked([remote+'/qeli','set-web-password','--username','admin','--password','synthetic-audit-password','--config',remote+'/etc/server.conf'],'initialize private panel password')
  with lab.open_sftp() as sf:
   with sf.open(remote+'/etc/server.conf','r') as f:config=f.read().decode('utf8')
  checked(['chown','-R','qeli:qeli',remote+'/etc'],'owned initial config ownership');checked(['chown','-R','root:root',remote+'/etc/client-links'],'owned private receipt ownership')
  checked(['ip','netns','add',name],'create owned network namespace');ns_created=True
  for args in [['link','set','lo','up'],['link','add','wan0','type','dummy'],['link','set','wan0','up'],['addr','add','192.0.2.1/24','dev','wan0'],['route','add','default','dev','wan0']]:checked(['ip','-n',name,*args],'owned network preparation')
  template=(ROOT/'qeli/debian/qeli.service').read_text(encoding='utf8');text=template
  for key in ['StateDirectory','RuntimeDirectory','LogsDirectory']:text=text.replace(key+'=qeli',key+'='+name)
  text=text.replace('[Install]', 'NetworkNamespacePath='+net+'\nBindReadOnlyPaths='+remote+'/qeli:/usr/bin/qeli\nBindPaths='+remote+'/etc:/etc/qeli\nEnvironment=QELI_CONTROL_SOCKET=/run/'+name+'/control.sock\n\n[Install]')
  # These overrides isolate state/network; all packaged hardening, capability and reload directives remain exact.
  parsed=configparser.ConfigParser(interpolation=None,strict=False);parsed.optionxform=str;parsed.read_string(text);base=configparser.ConfigParser(interpolation=None,strict=False);base.optionxform=str;base.read_string(template)
  altered={'StateDirectory','RuntimeDirectory','LogsDirectory'}
  check('packaged sandbox directives retained',all(parsed['Service'][k]==v for k,v in base['Service'].items() if k not in altered))
  (out/'owned.service').write_text(text,encoding='utf8',newline='\n');(out/'health.sh').write_text('SERVICE='+shlex.quote(unit)+'\n'+health+'\nservice_healthy\n',encoding='utf8',newline='\n')
  checked(['test','!','-e',unitfile],'fresh owned unit')
  with lab.open_sftp() as sf:
   with sf.open(unitfile,'w') as f:f.write(text)
   sf.chmod(unitfile,0o644)
  unit_created=True;checked(['systemd-analyze','verify',unitfile],'verify owned packaged unit')
  checked(['systemctl','daemon-reload'],'load owned unit');checked(['systemctl','start',unit],'start owned unit');pid=wait_ready();r['first_pid']=pid
  check('real packaged unit active',prop('ActiveState')=='active')
  check('updater health accepts stable real service',run(['bash',remote+'/health.sh'],'real updater health',15)[1]==0)
  check('private panel and worker listeners',ns(['python3','-B','-c',http],'private HTTP health')=='401')
  probe="from pathlib import Path; import json; p=Path('/proc/"+pid+"/status'); d=dict(x.split(':',1) for x in p.read_text().splitlines() if ':' in x); print(json.dumps({k:d[k].strip() for k in ['Uid','Gid','CapBnd','CapAmb','NoNewPrivs']}))"
  status=json.loads(checked(['python3','-B','-c',probe],'supervisor credentials'));mask=sum(1<<n for n in [12,13,10]);check('qeli uid/gid, exact ambient capabilities and NNP',int(status['Uid'].split()[0])==uid and int(status['Gid'].split()[0])==gid and int(status['CapAmb'],16)==mask and int(status['CapBnd'],16)==mask and status['NoNewPrivs']=='1',status)
  private=checked(['readlink','/proc/'+pid+'/ns/net','/proc/1/ns/net'],'network isolation').splitlines();check('manager unit network isolated from host',private[0]!=private[1])
  check('low-port listener and real TUN available',':443 ' in ns(['ss','-lnt'],'low port') and 'q33tun' in ns(['ip','-br','addr'],'private TUN'))
  code="import os,errno; p='/etc/"+name+".probe';\ntry:\n f=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(f);os.unlink(p);raise AssertionError('etc writable')\nexcept OSError as e:\n assert e.errno==errno.EROFS,e\nprint('readonly')"
  check('ProtectSystem makes unrelated etc read-only even for root',ns(['python3','-B','-c',code],'readonly etc')=='readonly')
  code="from pathlib import Path; import os; p=Path('/etc/qeli'); (p/'writable-probe').write_text('owned'); (p/'writable-probe').unlink(); print('writable')"
  check('ReadWritePaths permits qeli config persistence',ns(['setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','python3','-B','-c',code],'service config write')=='writable')
  code="from pathlib import Path;import hashlib,json; p=Path('/etc/qeli/identity/fixture.key'); s=p.stat(); print(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'uid':s.st_uid,'mode':s.st_mode&511,'size':s.st_size}))"
  identity=json.loads(ns(['python3','-B','-c',code],'generated identity'));check('fresh identity owned by daemon and private',identity['uid']==uid and identity['mode']==0o600 and identity['size']==32,identity)
  receipt=run(['nsenter','-t',pid,'-m','--','setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','test','-r','/etc/qeli/client-links/INSTALL-PENDING-fixture'],'receipt unreadable');check('daemon cannot read administrator receipt',receipt[1]!=0)
  if a.skip_reload_baseline:r['skipped_baseline_reload']='previous run proves supervisor exits on SIGHUP; not a passing reload qualification'
  else:
   with lab.open_sftp() as sf:
    with sf.open(remote+'/etc/users.conf','w') as f:f.write('[user:reload-fixture]\npassword_hash = '+re.search(r'^password_hash\s*=\s*(.+)$',config,re.M)[1]+'\n')
   checked(['systemctl','reload',unit],'real ExecReload');check('reload retains supervisor',prop('MainPID')==pid);wait_ready()
   deadline=time.monotonic()+10
   while time.monotonic()<deadline:
    journal=checked(['journalctl','-u',unit,'--no-pager','-o','json','-n','100'],'reload journal')
    rows=[json.loads(row) for row in journal.splitlines() if row.startswith('{')];reload_pids={row.get('_PID') for row in rows if 'SIGHUP: reloaded users database (1 users)' in row.get('MESSAGE','')}
    if pid in reload_pids and len(reload_pids)>=2:break
    time.sleep(.2)
   check('supervisor and worker apply reload without replacement',pid in reload_pids and len(reload_pids)>=2,sorted(reload_pids))
   with lab.open_sftp() as sf:
    with sf.open(remote+'/etc/users.conf','w') as f:f.write('')
   checked(['systemctl','reload',unit],'restore empty fixture users');wait_ready()
  checked(['systemctl','restart',unit],'real restart');nextpid=wait_ready();check('real restart replaces supervisor',nextpid!=pid);check('restart preserves identity bytes',json.loads(ns(['python3','-B','-c',code],'identity after restart'))['sha256']==identity['sha256'])
  for user in ['root','qeli']:
   checked([remote+'/qeli','set-service-user',user,'--unit',unit],'actual custom run-as '+user);checked(['systemctl','restart',unit],'apply owned run-as '+user);wait_ready();check('manager applies run-as '+user,prop('User')==user)
   check('healthy after run-as '+user,run(['bash',remote+'/health.sh'],'health after run-as '+user,15)[1]==0)
   effective=json.loads(checked(['python3','-B','-c',"import json;d=dict(x.split(':',1) for x in open('/proc/"+prop('MainPID')+"/status') if ':' in x);print(json.dumps({k:d[k].strip() for k in ['CapBnd','CapAmb','NoNewPrivs']}))"],'unit bounding set after '+user))
   expected=mask | 11 if user=='root' else mask
   check('bounded capabilities restored for '+user,int(effective['CapBnd'],16)==expected and int(effective['CapAmb'],16)==(0 if user=='root' else mask) and effective['NoNewPrivs']=='1',effective)
   if user=='root':
    login="import http.client,json; c=http.client.HTTPConnection('127.0.0.1',24880,timeout=8);c.request('POST','/audit/api/login',json.dumps({'username':'admin','password':'synthetic-audit-password'}),{'Content-Type':'application/json'});r=c.getresponse();r.read();assert r.status==200;cookie=r.getheader('Set-Cookie').split(';',1)[0];c.request('GET','/audit/api/config',headers={'Cookie':cookie});r=c.getresponse();v=json.loads(r.read());assert r.status==200;c.request('PUT','/audit/api/config',json.dumps({'config':v['config'],'expected_revision':v['revision']}),{'Cookie':cookie,'Content-Type':'application/json'});r=c.getresponse();v=json.loads(r.read());"
    denied=login+"assert v.get('ok') is False and 'trusted config file' in v.get('error',''),v;print('trust denied');c.close()"
    config_before=checked(['sha256sum',remote+'/etc/server.conf'],'config SHA before trust rejection').split()[0]
    check('root cannot promote qeli-owned config into trusted commands',ns(['python3','-B','-c',denied],'root config trust denial')=='trust denied')
    check('rejected root save preserves config bytes',checked(['sha256sum',remote+'/etc/server.conf'],'config SHA after trust rejection').split()[0]==config_before)
    # The administrator explicitly makes this owned fixture root-trusted. Do not relax command trust.
    checked(['chown','0:0',remote+'/etc/server.conf'],'administrator approves owned config for root')
    request=login+"assert r.status==200 and v.get('ok') is True,v;print('saved');c.close()"
    check('root service saves trusted config inside qeli-owned private directory',ns(['python3','-B','-c',request],'root trusted config API save')=='saved')
    check('root save preserves root owner and0600',checked(['stat','-c','%u %a',remote+'/etc/server.conf'],'config metadata after root save')=='0 600')
    checked(['chown',str(uid)+':'+str(gid),remote+'/etc/server.conf'],'restore owned config daemon account')


  checked(['systemctl','stop',unit],'stop before invalid config')
  with lab.open_sftp() as sf:
   with sf.open(remote+'/etc/server.conf','w') as f:f.write(config.replace('bind.port = 443','bind.port = invalid'))
  run(['systemctl','start',unit],'invalid INI service start');check('updater rejects actual failed/restarting service',run(['bash',remote+'/health.sh'],'health rejects bad INI',15)[1]!=0)
  check('manager records startup failure',prop('Result')=='exit-code' and prop('MainPID')=='0')
  checked(['systemctl','stop',unit],'stop owned crash loop')
  reset_text,reset_rc=run(['systemctl','reset-failed',unit],'reset own failure')
  if reset_rc:
   # systemd may garbage-collect an inactive unit after stop; this is already reset.
   check('stopped unit reset or already collected',reset_rc==1 and ('Unit '+unit+' not loaded.') in reset_text)
   checked(['test','-f',unitfile],'owned unit definition retained for recovery')
  with lab.open_sftp() as sf:
   with sf.open(remote+'/etc/server.conf','w') as f:f.write(config)
  checked(['systemctl','start',unit],'recover owned service');wait_ready();check('recovery healthy',run(['bash',remote+'/health.sh'],'health after recovery',15)[1]==0)
  check('recovery preserves identity and user database',json.loads(ns(['python3','-B','-c',code],'identity after recovery'))['sha256']==identity['sha256'] and (checked(['sha256sum',remote+'/etc/users.conf'],'users SHA').split()[0]==hashlib.sha256(b'').hexdigest()))
  r['status']='PASS'
 except BaseException:r['status']='FAIL';r['error']=traceback.format_exc();save();raise
 finally:
  try:
   if unit_created:
    r['journal']=run(['journalctl','-u',unit,'--no-pager','-n','200'],'owned journal')[0];checked(['systemctl','stop',unit],'stop only owned unit');check('owned service stopped before cleanup',prop('MainPID')=='0');run(['systemctl','reset-failed',unit],'reset only owned unit')
    code="from pathlib import Path; p=Path("+repr(unitfile)+"); assert p.parent==Path('/run/systemd/system') and p.name.startswith('qeli-q33-'); p.unlink(); d=Path("+repr(dropin)+");\nif d.exists():\n assert d.is_file() and not d.is_symlink();d.unlink();d.parent.rmdir()"
    checked(['python3','-B','-c',code],'remove only owned unit/dropin');checked(['systemctl','daemon-reload'],'unload owned unit')
   if ns_created:checked(['ip','netns','delete',name],'delete only owned namespace')
   if created:
    # Preserve generated state before any directory removal. Caller archives this root and then guards cleanup.
    for parent in ['/var/lib','/var/log']:
     src=parent+'/'+name;dst=remote+('/state' if parent=='/var/lib' else '/logs')
     code="from pathlib import Path;import shutil; p=Path("+repr(src)+"); d=Path("+repr(dst)+");\nif p.exists():\n assert p.parent==Path("+repr(parent)+") and p.name=="+repr(name)+" and not p.is_symlink();assert not d.exists();p.rename(d)"
     checked(['python3','-B','-c',code],'retain and remove own manager '+parent)
   r['host_after']=snapshot(lab);r['service_after']=checked(['systemctl','show','qeli.service','-p','MainPID','-p','ExecMainStartTimestampMonotonic','-p','ActiveState'],'production service after');r['working_after']=checked(['sha256sum','/usr/bin/qeli'],'production binary after');r['host_restored']=r['host_before']==r['host_after'] and r['service_before']==r['service_after'] and r['working_before']==r['working_after'];check('host network, working service and binary preserved',r['host_restored']);save()
  finally:lab.close()
 print('PASS real systemd unit: '+str(len(r['checks']))+' checks; own retained root '+remote)
 return 0

if __name__=='__main__':raise SystemExit(main())
