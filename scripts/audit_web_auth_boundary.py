#!/usr/bin/env python3
"""Q04 real HTTP boundaries; requires private NET/mount/PID namespaces and exact binary SHA.
Never invokes systemd, delivers notifications, or contacts external endpoints.
"""
import argparse,ssl,base64,concurrent.futures,hashlib,hmac,http.client,json,os,re,signal,subprocess,threading,time
from pathlib import Path

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for k in ('qeli','sha256','artifacts','routes','parent-net','parent-mnt','parent-pid'):ap.add_argument('--'+k,required=True)
 a=ap.parse_args()
 for k in ('net','mnt','pid'):assert os.readlink('/proc/self/ns/'+k)!=getattr(a,'parent_'+k),'private namespace required: '+k
 binary=Path(a.qeli).resolve(strict=True);assert hashlib.sha256(binary.read_bytes()).hexdigest()==a.sha256
 root=Path(a.artifacts);root.mkdir(mode=0o700,parents=True,exist_ok=False);routes=json.loads(Path(a.routes).read_text());checks=[];events=[];observations=[];sup=None;stream=None;complete=False
 cfg=Path('/etc/qeli/server.conf');state=root/'state';state.mkdir(mode=0o700);port=24880;prefix='/audit';tls_mode=False;password='fixture-only #; exact password';cookie='';env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_CONTROL_SOCKET=str(root/'control.sock'))
 def save(finished=False):
  (root/'result.json').write_text(json.dumps(dict(status='PASS' if complete else 'FAIL' if finished else 'IN_PROGRESS',artifact_sha256=a.sha256,checks=checks,observations=observations,check_count=len(checks)),indent=2)+'\n')
 def check(name,ok,detail=None):
  checks.append(dict(name=name,status='PASS' if ok else 'FAIL',detail=detail));save();print(('PASS ' if ok else 'FAIL ')+name,flush=True);assert ok,(name,detail)
 def run(argv):
  p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=25);assert p.returncode==0,(argv[0:2],p.stdout);return p.stdout
 def req(path,method='GET',body=None,headers=None,token=None,source='127.0.0.1',use_prefix=True):
  hs={'X-Forwarded-For':'203.0.113.101'};hs.update(headers or {})
  if token is not None:hs['Cookie']='qeli_session='+token
  if isinstance(body,(dict,list)):body=json.dumps(body).encode();hs.setdefault('Content-Type','application/json')
  elif isinstance(body,str):body=body.encode();hs.setdefault('Content-Type','application/json')
  c=http.client.HTTPSConnection('127.0.0.1',port,timeout=30,source_address=(source,0),context=ssl._create_unverified_context()) if tls_mode else http.client.HTTPConnection('127.0.0.1',port,timeout=30,source_address=(source,0))
  try:
   c.request(method,(prefix if use_prefix else '')+path,body=body,headers=hs);r=c.getresponse();code=r.status;rh={k.lower():v for k,v in r.getheaders()};data=r.read()
  finally:c.close()
  try:value=json.loads(data)
  except (ValueError,UnicodeError):value={}
  events.append(dict(path=path,method=method,status=code,response_bytes=len(data),response_sha256=hashlib.sha256(data).hexdigest()));return code,value,rh,data
 def wait(f,label):
  end=time.monotonic()+25
  while time.monotonic()<end:
   if sup and sup.poll() is not None:raise RuntimeError('private supervisor exited: '+(root/'server.log').read_text()[-2000:])
   try:
    if f():return
   except (ConnectionError,OSError):pass
   time.sleep(.05)
  raise RuntimeError(label)
 def start():
  nonlocal sup,stream
  stream=(root/'server.log').open('a');sup=subprocess.Popen([str(binary),'server','-c',str(cfg)],env=env,stdout=stream,stderr=subprocess.STDOUT)
  wait(lambda:req('/login')[0] in (200,303,403),'panel not ready');wait(lambda:':24843' in run(['ss','-lnt']) and Path('/etc/qeli/identity/fixture.key').exists(),'private worker not ready')
 def stop():
  if sup and sup.poll() is None:sup.send_signal(signal.SIGTERM);assert sup.wait(timeout=25)==0
  if stream:stream.close()
 def login(user='admin',pw=password,**kw):return req('/api/login','POST',{'username':user,'password':pw},**kw)
 def token_from(r):return r[2]['set-cookie'].split(';',1)[0].split('=',1)[1]
 def basic(user='admin',pw=password,scheme='Basic'):return {'Authorization':scheme+' '+base64.b64encode((user+':'+pw).encode()).decode()}
 def tree():return {str(p.relative_to('/etc/qeli')):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/qeli').rglob('*') if p.is_file() and not p.name.endswith('.lock')}
 def network():return {'links':run(['ip','-j','link']),'routes4':run(['ip','-4','route','show','table','all']),'routes6':run(['ip','-6','route','show','table','all']),'rules4':re.sub(r'\[\d+:\d+\]','[COUNTERS]','\n'.join(x for x in run(['iptables-save']).splitlines() if x.startswith('-A ') or (x.startswith(':') and ' - ' in x))),'rules6':re.sub(r'\[\d+:\d+\]','[COUNTERS]','\n'.join(x for x in run(['ip6tables-save']).splitlines() if x.startswith('-A ') or (x.startswith(':') and ' - ' in x)))}
 def snapshot_state():return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in state.glob('session*') if p.is_file() and not p.name.endswith('.lock')}
 for argv in (['ip','link','set','lo','up'],['ip','link','add','wan0','type','dummy'],['ip','link','set','wan0','up'],['ip','addr','add','192.0.2.1/24','dev','wan0'],['ip','route','add','default','dev','wan0']):run(argv)
 Path('/etc/qeli/users.conf').write_text('');cfg.write_text('''[auth]
users_file = /etc/qeli/users.conf
[web]
enabled = true
bind = 127.0.0.1
port = 24880
tls = false
secure_cookie = false
base_path = /audit
trusted_proxies = 127.0.0.1,198.51.100.0/24
public_host = panel.fixture.invalid
allowed_origins = https://extra.fixture.invalid:9443/panel,ssh.fixture.invalid:19000
session_ttl_secs = 60
brute_force.max_attempts = 3
brute_force.window_secs = 60
brute_force.lockout_secs = 2
[logging]
level = info
[profile:fixture]
bind.address = 127.0.0.1
bind.port = 24843
bind.transport = tcp
tun.name = qauth
tun.address = 10.77.0.1
pool.cidr = 10.77.0.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
''');cfg.chmod(0o600)
 run([str(binary),'set-web-password','--username','admin','--password',password,'--config',str(cfg)])
 before=network()
 try:
  start();old=tree();r=req('/api/status',token='9999999999.'+'a'*64);check('first forged cookie denied; lazy signer initialization only',r[0]==401 and tree()==old and (state/'session.key').stat().st_mode&0o777==0o600);protected=[r for r in routes if not r['public']]
  for style,hs in [('anonymous',{}),('forged cookie',{'Cookie':'qeli_session=9999999999.'+'a'*64}),('malformed Basic',{'Authorization':'Basic !!!'})]:
   old=tree();oldstate=snapshot_state();pid=sup.pid
   for row in protected:
    code,value,h,data=req(row['path'],row['method'],None if row['method']=='GET' else {},headers=hs)
    check(style+' denies '+row['method']+' '+row['path'],code==401 and value.get('ok') is False and password.encode() not in data and b'$argon2' not in data,code)
   check(style+' leaves config/identity/session files and supervisor unchanged',tree()==old and snapshot_state()==oldstate and sup.pid==pid and sup.poll() is None,{'before_files':old,'after_files':tree(),'before_session':oldstate,'after_session':snapshot_state()})
  check('anonymous probes do not lock out admin',login()[0]==200)
  r=login();cookie=token_from(r);attrs=r[2]['set-cookie'];check('cookie HttpOnly/Strict/root path/TTL',all(x in attrs for x in ['HttpOnly','SameSite=Strict','Path=/','Max-Age=60']) and 'Secure' not in attrs)
  check('token expiry matches configured TTL',58<=int(cookie.split('.')[0])-int(time.time())<=60)
  pages=['','/users','/config','/client','/transport','/logs','/blocked','/notifications','/quickstart']
  for page in pages:
   r=req(page,headers=basic());check('HTML ignores Basic '+page,r[0]==303 and r[2].get('location')=='/audit/login',{'status':r[0],'location':r[2].get('location')})
   check('cookie opens HTML '+page,req(page,token=cookie)[0]==200)
  r=req('/login',token=cookie);location=r[2].get('location');observations.append(dict(name='authenticated login redirect',status_code=r[0],location=location));save()
  check('authenticated login redirects within panel mount',r[0]==303 and location=='/audit',{'status':r[0],'location':location})
  check('trailing slash redirects canonically',req('/')[2].get('location')=='/audit')
  check('unprefixed panel is not mounted',req('/login',use_prefix=False)[0]==404)
  r=req('/login');r2=req('/login');csp=r[2]['content-security-policy'];nonce=re.search(r"'nonce-([^']+)'",csp)[1]
  check('CSP fresh nonce stamps every inline script',nonce!=re.search(r"'nonce-([^']+)'",r2[2]['content-security-policy'])[1] and all('nonce="'+nonce+'"' in tag for tag in re.findall(r'<script[^>]*>',r[3].decode())) and 'unsafe-eval' not in csp and "script-src 'self' 'nonce-" in csp)
  check('security headers and no-store protect responses',r[2].get('x-frame-options')=='DENY' and r[2].get('x-content-type-options')=='nosniff' and r[2].get('referrer-policy')=='no-referrer' and 'no-store' in r[2].get('cache-control','') and 'noindex' in r[2].get('x-robots-tag',''))
  check('assets public and cache policy separate',req('/assets/app.css')[0]==200 and req('/assets/app.css')[2].get('cache-control')=='no-cache' and 'immutable' in req('/assets/inter-400.woff2')[2].get('cache-control',''))
  old=tree()
  for row in [r for r in routes if r['method']!='GET']:
   r=req(row['path'],row['method'],{},headers={'Origin':'https://evil.fixture.invalid'},token=cookie)
   check('CSRF rejects '+row['method']+' '+row['path'],r[0]==403)
  check('CSRF rejection leaves persistent config and identity unchanged',tree()==old)
  for origin in ['null','https://panel.fixture.invalid.evil','https://extra.fixture.invalid:9444','https://evil@panel.fixture.invalid','http://localhost:3000']:
   check('CSRF rejects origin '+origin,req('/api/hash-password','POST',{'password':'fixture hash'},headers={'Origin':origin},token=cookie)[0]==403)
  for origin in ['http://127.0.0.1:24880','https://panel.fixture.invalid','https://extra.fixture.invalid:9443','http://ssh.fixture.invalid:19000']:
   r=req('/api/hash-password','POST',{'password':'fixture hash'},headers={'Origin':origin},token=cookie);check('allowed origin '+origin,r[0]==200 and r[1].get('ok') is True)
  check('Referer accepted when Origin absent',req('/api/hash-password','POST',{'password':'fixture hash'},headers={'Referer':'http://localhost:24880/audit/config'},token=cookie)[1].get('ok') is True)
  check('Origin takes precedence over good Referer',req('/api/hash-password','POST',{'password':'fixture hash'},headers={'Origin':'null','Referer':'http://localhost:24880/audit/config'},token=cookie)[0]==403)
  check('cookie CLI request without Origin supported',req('/api/hash-password','POST',{'password':'fixture hash'},token=cookie)[1].get('ok') is True)
  check('Basic API succeeds',req('/api/status',headers=basic())[0]==200)
  check('Basic CLI mutator without Origin supported',req('/api/hash-password','POST',{'password':'fixture hash'},headers=basic())[1].get('ok') is True)
  check('Basic also subject to CSRF',req('/api/hash-password','POST',{'password':'fixture hash'},headers=dict(basic(),Origin='https://evil.fixture.invalid'))[0]==403)
  for scheme in ['basic','bAsIc']:
   r=req('/api/status',headers=basic(scheme=scheme));check('case-insensitive Basic scheme '+scheme,r[0]==200)
  check('oversized login rejected before authentication',req('/api/login','POST',{'username':'admin','password':'x'*9000})[0]==413)
  check('hash empty/oversize/invalid fields rejected',all(req('/api/hash-password','POST',v,token=cookie)[1].get('ok') is False for v in [{'password':''},{'password':'x'*1025},{'password':1},{}]))
  check('oversized authorized API body bounded',req('/api/hash-password','POST',b'x'*(16*1024*1024+1),headers={'Content-Type':'application/json'},token=cookie)[0]==413)
  # Independent signed-token oracle uses private fixture key, never records its bytes.
  stored_hash=re.search(r'(?m)^password_hash\s*=\s*(.*)$',cfg.read_text())[1].encode();key=(state/'session.key').read_bytes();generation=int((state/'session.gen').read_text()) if (state/'session.gen').exists() else 0
  prk=hmac.new(stored_hash,key,hashlib.sha256).digest();derived=hmac.new(prk,('qeli-web-session-v1:'+str(generation)).encode()+b'\x01',hashlib.sha256).digest()
  for payload in [str(int(time.time())-1),'bad','-1','99999999999999999999999']:
   signed=payload+'.'+hmac.new(derived,payload.encode(),hashlib.sha256).hexdigest();check('signed invalid/expired payload rejected '+payload,req('/api/status',token=signed)[0]==401)
  check('trusted HTTPS forwarding sets Secure', 'Secure' in login(headers={'X-Forwarded-Proto':'https'})[2].get('set-cookie',''))
  check('untrusted HTTPS forwarding ignored','Secure' not in login(source='127.0.0.2',headers={'X-Forwarded-Proto':'https'})[2].get('set-cookie',''))
  for source,hs,base in [('127.0.0.1',{'X-Forwarded-Prefix':'/front'},'/front/'),('127.0.0.2',{'X-Forwarded-Prefix':'/evil'},'/audit/'),('127.0.0.1',{'X-Forwarded-Prefix':'x"><script>'},'/audit/')]:
   r=req('/login',source=source,headers=hs);check('forwarded prefix trust '+source+' '+base,('<base href="'+base+'">').encode() in r[3] and b'{{basehref}}' not in r[3])
  # Per-client lockout behind a trusted chain, and refusal to use forged left hops.
  client='203.0.113.71';hs={'X-Forwarded-For':'192.0.2.99,'+client+',198.51.100.7'}
  for n in range(3):check('count failure at real proxy-chain client '+str(n),login(user='unknown'+str(n),pw='wrong',headers=hs)[0]==401)
  check('real client locked via login and Basic',login(headers=hs)[0]==429 and req('/api/status',headers=dict(basic(),**hs))[0]==429)
  check('another real client not globally locked',login(headers={'X-Forwarded-For':'203.0.113.72,198.51.100.7'})[0]==200)
  time.sleep(2.1);check('expired lockout recovers correct credentials',login(headers=hs)[0]==200)
  # Queued jobs must recheck lockout after acquiring an Argon2 permit.
  barrier=threading.Barrier(24);peak=[0];done=threading.Event()
  def sample():
   while not done.wait(.01):
    try:peak[0]=max(peak[0],int(re.search(r'VmRSS:\s+(\d+)',Path('/proc',str(sup.pid),'status').read_text())[1]))
    except FileNotFoundError:return
  thread=threading.Thread(target=sample);thread.start()
  def attempt(n):barrier.wait();return login(user='burst-'+str(n),pw='wrong',headers={'X-Forwarded-For':'203.0.113.81'})[0]
  try:
   with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:codes=list(pool.map(attempt,range(24)))
  finally:done.set();thread.join()
  observations.append(dict(name='24 queued login attempts from one IP',codes=codes,unauthorized=codes.count(401),rate_limited=codes.count(429),supervisor_peak_rss_kib=peak[0],argon2_capacity=len(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else os.cpu_count()));save()
  capacity=min(8,max(2,len(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else os.cpu_count()))
  check('queued login attempts respect lockout admission',0<codes.count(401)<=3+capacity-1 and codes.count(429)>0,{'unauthorized':codes.count(401),'rate_limited':codes.count(429),'capacity':capacity})
  check('parallel login batch stays responsive and resource bounded',all(c in [401,429] for c in codes) and peak[0]<200*1024 and req('/api/status',token=token_from(login(headers={'X-Forwarded-For':'203.0.113.82'})))[0]==200)
  barrier=threading.Barrier(24)
  def mixed_attempt(n):
   barrier.wait();hs={'X-Forwarded-For':'203.0.113.83'}
   return login(user='mixed-'+str(n),pw='wrong',headers=hs)[0] if n%2 else req('/api/status',headers=dict(basic(user='mixed-'+str(n),pw='wrong',scheme='bAsIc'),**hs))[0]
  with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:mixed=list(pool.map(mixed_attempt,range(24)))
  observations.append(dict(name='24 mixed login/Basic attempts from one IP',codes=mixed,unauthorized=mixed.count(401),rate_limited=mixed.count(429)));save()
  check('login and Basic share queued lockout admission',all(c in [401,429] for c in mixed) and 0<mixed.count(401)<=3+capacity-1 and mixed.count(429)>0,{'unauthorized':mixed.count(401),'rate_limited':mixed.count(429)})
  # Durable login/logout behavior across private process restarts.
  cookie=token_from(login());secret_before=(state/'session.key').read_bytes();stop();start();check('persisted cookie survives private supervisor restart',req('/api/status',token=cookie)[0]==200 and (state/'session.key').read_bytes()==secret_before)
  r=req('/api/logout','POST',{},token=cookie);check('logout durable revocation and browser clear',r[0]==200 and r[1].get('ok') is True and 'Max-Age=0' in r[2].get('set-cookie','') and req('/api/status',token=cookie)[0]==401)
  stop();start();check('revoked cookie remains rejected after restart',req('/api/status',token=cookie)[0]==401)
  cookie=token_from(login());saved_gen=(state/'session.gen').read_bytes();(state/'session.gen').write_text('corrupt fixture');r=req('/api/logout','POST',{},token=cookie)
  check('logout persistence failure is explicit',r[0]==500 and r[1].get('ok') is False and 'Max-Age=0' in r[2].get('set-cookie',''))
  check('failed revocation does not falsely promise old-token invalidation',req('/api/status',token=cookie)[0]==200)
  (state/'session.gen').write_bytes(saved_gen);check('logout retry succeeds after repair',req('/api/logout','POST',{},token=cookie)[0]==200 and req('/api/status',token=cookie)[0]==401)
  cookie=token_from(login());saved_gen=(state/'session.gen').read_bytes();stop();(state/'session.gen').write_text('corrupt fixture');start();check('corrupt generation fails closed on restart',req('/api/status',token=cookie)[0]==401)
  check('corrupt generation preserved for operator repair',(state/'session.gen').read_text()=='corrupt fixture');stop();(state/'session.gen').write_bytes(saved_gen)
  # IP allowlist must apply to public pages/assets, not just protected APIs.
  original=cfg.read_text();cfg.write_text(original.replace('public_host = panel.fixture.invalid','allowed_ips = 203.0.113.90\npublic_host = panel.fixture.invalid'));start()
  for path in ['/login','/assets/app.css','/api/status']:
   denied=req(path,headers={'X-Forwarded-For':'192.0.2.8,203.0.113.91,198.51.100.7'});check('allowlist rejects actual untrusted chain '+path,denied[0]==403 and 'no-store' in denied[2].get('cache-control',''))
   check('allowlisted chain reaches '+path,req(path,headers={'X-Forwarded-For':'192.0.2.8,203.0.113.90,198.51.100.7'})[0]==(401 if path=='/api/status' else 200))
   check('untrusted peer cannot forge allowlist '+path,req(path,source='127.0.0.2',headers={'X-Forwarded-For':'203.0.113.90'})[0]==403)
  stop();cfg.write_text(original);start();cookie=token_from(login())
  # Direct owned INI change followed by an explicit private restart; no live .11 service.
  stop();cfg.write_text(re.sub(r'(?m)^password_hash\s*=.*$', 'password_hash =',original).replace('secure_cookie = false','secure_cookie = false\ninsecure_no_auth = true'));start()
  check('explicit passwordless API opens',req('/api/status')[0]==200)
  check('passwordless mutator retains CSRF',req('/api/hash-password','POST',{'password':'fixture'},headers={'Origin':'https://evil.fixture.invalid'})[0]==403 and req('/api/hash-password','POST',{'password':'fixture'},headers={'Origin':'http://localhost:24880'})[1].get('ok') is True)
  stop();cfg.write_text(original);start();cookie=token_from(login());stop();(state/'session.key').write_bytes(b'truncated fixture');start()
  check('damaged persistent key rejects old cookie and is not overwritten',req('/api/status',token=cookie)[0]==401 and (state/'session.key').read_bytes()==b'truncated fixture')
  check('key fallback permits explicit new login',login()[0]==200)
  stop();(state/'session.key').write_bytes(secret_before);cfg.write_text(original.replace('tls = false','tls = true'));tls_mode=True;start();r=login();check('native TLS emits Secure cookie and HSTS','Secure' in r[2].get('set-cookie','') and r[2].get('strict-transport-security')=='max-age=63072000');check('TLS cookie authenticates private API',req('/api/status',token=token_from(r))[0]==200)
  stop();check('private server network cleanup restored',network()==before)
  complete=True;save()
 finally:
  if sup and sup.poll() is None:sup.kill();sup.wait(timeout=5)
  if stream and not stream.closed:stream.close()
  (root/'http-events.json').write_text(json.dumps(events,indent=2)+'\n');save(True)
 return 0
if __name__=='__main__':raise SystemExit(main())
