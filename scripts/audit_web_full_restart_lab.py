import os,sys,json,hashlib,shlex,datetime,time,subprocess,traceback,re
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_lab import connect_lab
from audit_release_matrix_lab import snapshot,put,ISOLATED
import argparse
ap=argparse.ArgumentParser(description='Q05 real full restart of ONLY an owned transient unit, private NET/mount and state; running services preserved.')
ap.add_argument('--host',default='10.66.116.11');ap.add_argument('--qeli',required=True);ap.add_argument('--sha256',required=True);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
if not re.fullmatch(r'/[A-Za-z0-9_./-]+',a.qeli) or '..' in a.qeli.split('/'):ap.error('absolute safe binary path required')
if not re.fullmatch('[a-f0-9]{64}',a.sha256):ap.error('full SHA256 required')
if not os.environ.get('QELI_LAB_PASS'):ap.error('QELI_LAB_PASS required')
out=a.output;out.mkdir(parents=True,exist_ok=False)
sha=a.sha256;binary=a.qeli;unit='qeli-audit-q05-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S%f')+'.service';remote='/var/tmp/'+unit[:-8]
lab=connect_lab(a.host,'root',os.environ['QELI_LAB_PASS']);r={'status':'IN_PROGRESS','unit':unit,'remote':remote,'artifact_sha256':sha,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'checks':[],'events':[],'executed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def save():(out/'results.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
def check(name,ok,detail=None):r['checks'].append(dict(name=name,status='PASS' if ok else 'FAIL',detail=detail));save();print(('PASS ' if ok else 'FAIL ')+name,flush=True);assert ok,(name,detail)
def prop(key):return lab.checked(shlex.join(['systemctl','show',unit,'--value','-p',key]),'owned unit '+key,15)
def child():
 pid=prop('MainPID')
 if pid=='0':raise ConnectionError('unit restarting')
 return pid
request="import http.client,json,sys;port,path,method,body,token=sys.argv[1:];c=http.client.HTTPConnection('127.0.0.1',int(port),timeout=8);h={'Content-Type':'application/json'};h.update({'Cookie':'qeli_session='+token} if token else {});c.request(method,path,body or None,h);r=c.getresponse();b=r.read();print(json.dumps({'code':r.status,'body':json.loads(b),'cookie':r.getheader('Set-Cookie')}));c.close()"
def req(path,method='GET',body=None,cookie='',port=24880):
 cmd=['nsenter','-t',child(),'-n','--','python3','-c',request,str(port),'/audit'+path,method,json.dumps(body) if body is not None else '',cookie];text,rc=lab.run(shlex.join(cmd),15)
 if rc:raise ConnectionError('private HTTP unavailable')
 value=json.loads(text);r['events'].append(dict(path=path,method=method,status=value['code'],response_sha256=hashlib.sha256(json.dumps(value['body'],sort_keys=True).encode()).hexdigest()));save();return value

def wait(fn,label):
 end=time.monotonic()+45
 while time.monotonic()<end:
  try:
   if fn():return
  except (ConnectionError,RuntimeError,ValueError):pass
  time.sleep(.3)
 raise RuntimeError(label)
entry='''set -eu
case_root=$1; binary=$2
mount --make-rprivate /
mount --bind /run/systemd/private "$case_root/systemd-private"
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /var/lib
mount -t tmpfs tmpfs /var/log
mkdir -p /run/systemd/system /var/lib/qeli /var/log/qeli /run/q05-control
chmod 0700 /run/q05-control
: > /run/systemd/private
mount --bind "$case_root/systemd-private" /run/systemd/private
umount "$case_root/systemd-private"
mount --bind "$case_root/state" /var/lib/qeli
mount --bind "$case_root/etc" /etc/qeli
mount --bind "$case_root/tmp" /tmp
export STATE_DIRECTORY=/var/lib/qeli QELI_CONTROL_SOCKET=/run/q05-control/control.sock
ip link set lo up
ip link add wan0 type dummy
ip link set wan0 up
ip addr add 192.0.2.1/24 dev wan0
ip route add default dev wan0
if ! grep -q '^password_hash' /etc/qeli/server.conf; then
 "$binary" set-web-password --username admin --password 'fixture-only #; exact password' --config /etc/qeli/server.conf
fi
exec "$binary" server -c /etc/qeli/server.conf
'''
fixture=Path(__file__).resolve().parent/'audit_web_transactions.py';config=re.search(r"cfg.write_text\('''(.*?)'''\)",fixture.read_text(encoding='utf-8'),re.S)[1];started=False
try:
 r['host_before']=snapshot(lab);r['service_before']=lab.checked('systemctl show qeli.service -p MainPID -p ExecMainStartTimestampMonotonic -p ActiveState','working service',15);r['working_before']=lab.checked('sha256sum /root/qeli-src/target/release/qeli','working artifact',15).split()[0];assert lab.checked('sha256sum '+binary,'candidate',15).split()[0]==sha;save()
 lab.checked('test ! -e '+remote+' && mkdir -m 700 '+remote+' '+remote+'/etc '+remote+'/state '+remote+'/tmp && touch '+remote+'/systemd-private','owned root',15);sf=lab.open_sftp()
 for name,data in [('entry.sh',entry.encode()),('etc/server.conf',config.encode()),('etc/users.conf',b'')]:put(sf,remote+'/'+name,data)
 sf.close();r['entry_sha256']=hashlib.sha256(entry.encode()).hexdigest();r['fixture_config_sha256']=hashlib.sha256(config.encode()).hexdigest();r['start_command']=shlex.join(['systemd-run','--unit='+unit,'--collect','--property=Type=simple','--property=KillMode=control-group','--property=TimeoutStopSec=15s','--property=Restart=no','--','unshare','--net','--mount','bash',remote+'/entry.sh',remote,binary]);lab.checked(r['start_command'],'start ONLY owned temporary unit',20);started=True
 wait(lambda:req('/api/status')['code']==401,'panel not ready');auth=req('/api/login','POST',{'username':'admin','password':'fixture-only #; exact password'});check('owned unit login',auth['code']==200 and auth['body'].get('ok') is True);cookie=auth['cookie'].split(';',1)[0].split('=',1)[1];first=prop('MainPID');r['first_pid']=first;r['private_namespaces']=lab.checked('readlink /proc/'+child()+'/ns/net /proc/'+child()+'/ns/mnt /proc/'+child()+'/ns/pid','private namespace IDs',15)
 result=req('/api/server/full-restart','POST',{},cookie);check('real full restart selects only dedicated unit',result['code']==200 and result['body'].get('ok') is True and result['body'].get('unit')==unit,{'selected_unit':result['body'].get('unit')});wait(lambda:prop('MainPID') not in ('0',first) and req('/api/status',cookie=cookie)['code']==200,'first real full restart did not complete');second=prop('MainPID');r['second_pid']=second;check('real manager replaces supervisor',second!=first);check('cookie persists across real full restart',req('/api/status',cookie=cookie)['code']==200)
 conf=req('/api/config',cookie=cookie)['body'];conf['config']['web']['port']=24881;result=req('/api/config','PUT',{'config':conf['config'],'expected_revision':conf['revision']},cookie);check('listener change saved with full restart requirement',result['body'].get('ok') is True and result['body'].get('needs_full_restart') is True);result=req('/api/server/full-restart','POST',{},cookie);check('changed-listener restart selects only owned unit',result['body'].get('ok') is True and result['body'].get('unit')==unit);wait(lambda:prop('MainPID') not in ('0',second) and req('/api/status',cookie=cookie,port=24881)['code']==200,'new listener did not apply');third=prop('MainPID');r['third_pid']=third;check('new listener and cookie after full restart',third!=second and req('/api/status',cookie=cookie,port=24881)['code']==200);wait(lambda:':24843' in lab.checked('nsenter -t '+child()+' -n -- ss -lnt','private worker readiness',15),'worker not ready');listeners=lab.checked('nsenter -t '+child()+' -n -- ss -lnt','private listeners',15);check('old listener removed and worker available',':24880' not in listeners and ':24881' in listeners and ':24843' in listeners)
 sf=lab.open_sftp();original=sf.open(remote+'/etc/server.conf').read();put(sf,remote+'/etc/server.conf',b'not valid INI');sf.close();result=req('/api/server/full-restart','POST',{},cookie,port=24881);check('invalid disk config refuses real full restart',result['body'].get('ok') is False and 'restart refused' in result['body'].get('error',''));check('refused full restart preserves supervisor',prop('MainPID')==third);sf=lab.open_sftp();put(sf,remote+'/etc/server.conf',original);sf.close();check('admin remains usable after refused restart',req('/api/status',cookie=cookie,port=24881)['code']==200);r['status']='PASS'
except BaseException:r['status']='FAIL';r['error']=traceback.format_exc();save();raise
finally:
 if started:
  r['journal']=lab.checked(shlex.join(['journalctl','-u',unit,'--no-pager','-n','120']),'owned unit journal',15);lab.checked(shlex.join(['systemctl','stop',unit]),'stop ONLY owned unit',25)
 r['unit_load_after']=lab.checked(shlex.join(['systemctl','show',unit,'--value','-p','LoadState']),'owned unit collected',15);r['owned_unit_collected']=r['unit_load_after']=='not-found';r['host_after']=snapshot(lab);r['service_after']=lab.checked('systemctl show qeli.service -p MainPID -p ExecMainStartTimestampMonotonic -p ActiveState','working service after',15);r['working_after']=lab.checked('sha256sum /root/qeli-src/target/release/qeli','working artifact after',15).split()[0];r['host_restored']=r['host_before']==r['host_after'] and r['service_before']==r['service_after'] and r['working_before']==r['working_after'];r['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save();lab.close()
assert r['host_restored'] and r['owned_unit_collected'];print('PASS real owned systemd restart; '+str(len(r['checks']))+' checks; working services untouched')
