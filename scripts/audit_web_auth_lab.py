import os,sys,json,hashlib,shlex,subprocess,datetime,traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_lab import connect_lab
from audit_release_matrix_lab import snapshot,ISOLATED,put,pull_logs
import argparse,re

def inventory_routes(root):
 api=(root/'qeli/src/web/api/mod.rs').read_text(encoding='utf-8')
 rows=[]
 for chunk in re.split(r'\.route\(\s*"',api)[1:]:
  path,_,handlers=chunk.partition('"')
  methods=re.findall(r'\b(get|post|put|delete)\(\s*(\w+::\w+)',handlers)
  if not methods:raise RuntimeError('unrecognized route: '+path)
  for method,handler in methods:
   module,function=handler.split('::')
   source=(root/('qeli/src/web/api/'+module+'.rs')).read_text(encoding='utf-8')
   signature=re.search(r'pub async fn '+re.escape(function)+r'\((.*?)\)\s*(?:->|\{)',source,re.S)
   if not signature:raise RuntimeError('handler not found: '+handler)
   guarded='auth::AuthGuard' in signature[1];public=path=='/login' and method=='post'
   if not guarded and not public:raise RuntimeError('unguarded API: '+method+' '+path)
   fixture=re.sub(r'\{([^}]+)\}',lambda m:{'ip':'127.0.0.9','mode':'fake-tls'}.get(m[1],'fixture'),path)
   rows.append(dict(path='/api'+fixture,method=method.upper(),handler=handler,auth_guard=guarded,public=public))
 assert len(rows)==56 and sum(r['public'] for r in rows)==1
 assert len({(r['path'],r['method']) for r in rows})==len(rows)
 return rows

root=Path(__file__).resolve().parent.parent
ap=argparse.ArgumentParser(description='Q04/Q05/Q06 real HTTP audit in private Linux NET/mount/PID namespaces.')
ap.add_argument('--host',default='10.66.116.11');ap.add_argument('--qeli',required=True);ap.add_argument('--sha256',required=True);ap.add_argument('--output',required=True,type=Path)
ap.add_argument('--fixture',type=Path,default=root/'scripts/audit_web_auth_boundary.py')
ap.add_argument('--audit',choices=('q04','q05','q06','q07','q08'),default='q04')
ap.add_argument('--scenario',choices=('basic','runtime','faults','crash','nonroot','users','users-live','users-storage','users-policy','users-durability','users-admission','users-bandwidth','archives','archive-policy','archive-faults','archive-state','archive-prepare','keys','keys-rotation'))
a=ap.parse_args()
if not a.fixture.is_file():ap.error('fixture file not found')
if a.audit=='q04' and a.scenario is not None:ap.error('q04 does not support scenarios')
if a.audit=='q05' and a.scenario not in ('basic','runtime','faults','crash','nonroot'):ap.error('q05 requires its explicit scenario')
if a.audit=='q06' and a.scenario not in ('users','users-live','users-storage','users-policy','users-durability','users-admission','users-bandwidth'):ap.error('q06 requires an explicit users scenario')
if a.audit=='q07' and a.scenario not in ('archives','archive-policy','archive-faults','archive-state','archive-prepare'):ap.error('q07 requires the archives scenario')
if a.audit=='q08' and a.scenario not in ('keys','keys-rotation'):ap.error('q08 requires the keys scenario')
if not re.fullmatch('/[A-Za-z0-9_./-]+',a.qeli) or '..' in a.qeli.split('/'):ap.error('absolute safe binary path required')
if not re.fullmatch('[a-f0-9]{64}',a.sha256):ap.error('full SHA256 required')
if not os.environ.get('QELI_LAB_PASS'):ap.error('QELI_LAB_PASS required')
out=a.output;out.mkdir(parents=True,exist_ok=False);binary=a.qeli;sha=a.sha256
routes=inventory_routes(root);(out/'route-manifest.json').write_text(json.dumps(routes,indent=2)+'\n',encoding='utf-8')
remote='/var/tmp/qeli-'+a.audit+'-web-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
r={'audit':a.audit,'scenario':a.scenario,'fixture_source':str(a.fixture),'status':'STARTED','artifact_sha256':sha,'binary':binary,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'executed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'fixtures':{},'remote':remote,'route_count':len(routes)}

def save():(out/'results.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
lab=connect_lab(a.host,'root',os.environ['QELI_LAB_PASS'])
try:
 r['host_before']=snapshot(lab);r['service_before']=lab.checked('systemctl show qeli.service -p MainPID -p ExecMainStartTimestampMonotonic -p ActiveState','service',30);r['working_artifact_before']=lab.checked('sha256sum /root/qeli-src/target/release/qeli','working binary',30).split()[0];r['environment']=lab.checked('uname -srmo','kernel',30);save()
 assert lab.checked('sha256sum '+binary,'candidate hash',30).split()[0]==sha
 parents=[lab.checked('readlink /proc/self/ns/'+k,k,30) for k in ('net','mnt','pid')]
 lab.checked('test ! -e '+remote+' && mkdir -m 700 '+remote+' '+remote+'/isolated','private root',30)
 script=remote+'/case.sh';cmd=['python3',remote+'/audit_web_auth_boundary.py','--qeli',binary,'--sha256',sha,'--artifacts',remote+'/case','--routes',remote+'/routes.json']
 if a.scenario is not None:cmd+=['--scenario',a.scenario]
 for k,v in zip(('net','mnt','pid'),parents):cmd+=['--parent-'+k,v]
 sf=lab.open_sftp()
 for name,data in [('audit_web_auth_boundary.py',a.fixture.read_bytes()),('routes.json',(out/'route-manifest.json').read_bytes()),('isolated.sh',ISOLATED.encode()),('case.sh',('set -eu\nexec '+shlex.join(cmd)+'\n').encode())]:
  data=data.replace(b'\r\n',b'\n');put(sf,remote+'/'+name,data);r['fixtures'][name]=hashlib.sha256(data).hexdigest();assert lab.checked('sha256sum '+remote+'/'+name,'fixture hash',30).split()[0]==r['fixtures'][name]
 sf.close();command=shlex.join(['timeout','--signal=TERM','--kill-after=10','900','unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc','bash',remote+'/isolated.sh',remote+'/isolated',*parents,script]);r['command']=command;save();print('START '+a.audit.upper()+' isolated HTTP',flush=True)
 log,rc=lab.run(command+' 2>&1',930);(out/'runtime.log').write_text(log+'\n',encoding='utf-8');r['exit_code']=rc;print(log[-2400:],flush=True)
 sf=lab.open_sftp();sf.get(remote+'/case/result.json',str(out/'case-result.json'));sf.get(remote+'/case/http-events.json',str(out/'http-events.json'));(out/'logs').mkdir();pull_logs(sf,remote,out/'logs');sf.close();r['case_result']=json.loads((out/'case-result.json').read_text(encoding='utf-8'));r['status']='PASS' if rc==0 and r['case_result']['status']=='PASS' else 'FAIL';save()
 assert r['status']=='PASS'
except BaseException:r['status']='FAIL';r['error']=traceback.format_exc();save();raise
finally:
 r['host_after']=snapshot(lab);r['service_after']=lab.checked('systemctl show qeli.service -p MainPID -p ExecMainStartTimestampMonotonic -p ActiveState','service after',30);r['working_artifact_after']=lab.checked('sha256sum /root/qeli-src/target/release/qeli','working binary after',30).split()[0];r['host_restored']=r['host_before']==r['host_after'] and r['service_before']==r['service_after'] and r['working_artifact_before']==r['working_artifact_after'];r['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save();lab.close()
assert r['host_restored'];print('PASS '+a.audit.upper()+' runtime '+str(r['case_result']['check_count'])+' checks; host and service preserved',flush=True)
