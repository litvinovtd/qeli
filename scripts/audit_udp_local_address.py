#!/usr/bin/env python3
"""Real UDP wildcard reply-source audit; disposable Linux/root, private namespaces only."""
import argparse,hashlib,json,os,signal,socket,subprocess,sys,time
from pathlib import Path
CAPTURE=r'''
import socket,struct,json,sys
sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));sock.bind(('br0',0));print('READY',flush=True)
while True:
 p=sock.recv(65535)
 if len(p)<42:continue
 kind=p[12:14]
 if kind==b'\x08\x00' and p[23]==17:
  if struct.unpack('!H',p[20:22])[0]&8191:continue
  pos=14+(p[14]&15)*4;src=socket.inet_ntop(socket.AF_INET,p[26:30]);dst=socket.inet_ntop(socket.AF_INET,p[30:34])
 elif kind==b'\x86\xdd' and len(p)>=62 and p[20]==17:
  pos=54;src=socket.inet_ntop(socket.AF_INET6,p[22:38]);dst=socket.inet_ntop(socket.AF_INET6,p[38:54])
 else:continue
 sport,dport=struct.unpack('!HH',p[pos:pos+4])
 if 24443 in (sport,dport):print(json.dumps(dict(src=src,dst=dst,sport=sport,dport=dport,length=len(p))),flush=True)
'''
ECHO=r'''
import socket,sys
from pathlib import Path
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('10.86.0.1',33333));Path(sys.argv[1]).touch()
while True:
 p,peer=s.recvfrom(65535);s.sendto(p,peer)
'''
PROBE=r'''
import socket,json
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(8)
packets=[i.to_bytes(2,'big')+bytes([i])*(64 if i%2 else 1200) for i in range(32)]
for p in packets:s.sendto(p,('10.86.0.1',33333))
received=set()
for _ in packets:
 p,peer=s.recvfrom(65535);assert peer==('10.86.0.1',33333) and p in packets;received.add(p)
assert len(received)==32;print(json.dumps(dict(sent=32,replies=32,bytes=sum(map(len,received)))))
'''
def identity(kind):return str(os.stat('/proc/self/ns/'+kind).st_ino)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--qeli',type=Path,required=True);ap.add_argument('--baseline',type=Path,required=True);ap.add_argument('--artifacts',type=Path,required=True);ap.add_argument('--inside',choices=['v4-plain','v4-obfs','v6-plain','v6-obfs']);ap.add_argument('--version',choices=['baseline','fixed'],default='fixed');a=ap.parse_args()
 root=a.artifacts.resolve();binary=(a.baseline if a.version=='baseline' else a.qeli).resolve(strict=True)
 if not a.inside:
  assert os.geteuid()==0;root.mkdir(mode=0o700,parents=True,exist_ok=False);rows=[]
  for version,case in [('baseline','v4-plain'),('baseline','v4-obfs')]+[('fixed',f'{fam}-{mode}') for fam in ['v4','v6'] for mode in ['plain','obfs']]:
   folder=root/(version+'-'+case);folder.mkdir(mode=0o700)
   cmd=['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),'--qeli',str(a.qeli.resolve()),'--baseline',str(a.baseline.resolve()),'--artifacts',str(folder),'--inside',case,'--version',version]
   with (folder/'fixture.log').open('w') as log:p=subprocess.run(cmd,env=dict(os.environ,QELI_UL_NET=identity('net'),QELI_UL_MNT=identity('mnt')),stdout=log,stderr=subprocess.STDOUT,timeout=130)
   result=folder/'result.json';rows.append(dict(version=version,case=case,exit_code=p.returncode,result=json.loads(result.read_text()) if result.exists() else None));(root/'results.json').write_text(json.dumps(rows,indent=2));print(version,case,p.returncode,flush=True)
  assert len(rows)==6 and all(r['exit_code']==0 for r in rows),rows
  return
 assert identity('net')!=os.environ['QELI_UL_NET'] and identity('mnt')!=os.environ['QELI_UL_MNT']
 commands=[];processes=[]
 def run(*cmd,input=None):
  p=subprocess.run(list(map(str,cmd)),input=input,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20);commands.append(dict(cmd=list(map(str,cmd)),rc=p.returncode,output=p.stdout));(root/'commands.json').write_text(json.dumps(commands,indent=2));assert p.returncode==0,(cmd,p.stdout);return p.stdout
 def wait(check,seconds=30):
  end=time.monotonic()+seconds
  while not check():
   assert time.monotonic()<end,'readiness timeout';time.sleep(.05)
 def start(cmd,log,env=None):
  p=subprocess.Popen(list(map(str,cmd)),stdout=(root/log).open('w'),stderr=subprocess.STDOUT,env=env);processes.append(p);return p
 def state(path):
  try:return json.loads(path.read_text())['state']
  except (ValueError,FileNotFoundError):return None
 run('mount','--make-rprivate','/')
 for path in ['/run','/var/lib','/var/log','/tmp']:run('mount','-t','tmpfs','tmpfs',path)
 Path('/run/netns').mkdir();etc=root/'etc';etc.mkdir();run('mount','--bind',etc,'/etc/qeli');run('ip','link','set','lo','up')
 run('ip','link','add','br0','type','bridge');run('ip','link','set','br0','up')
 for address in ['192.0.2.1/24','192.0.2.3/24']:run('ip','addr','add',address,'dev','br0')
 for address in ['fd42::1/64','fd42::3/64']:run('ip','-6','addr','add',address,'dev','br0','nodad')
 def cli(n,*args):return run('ip','netns','exec','qc'+str(n),*args)
 for n in [1,2]:
  ns='qc'+str(n);run('ip','netns','add',ns);run('ip','link','add','peer'+str(n),'type','veth','peer','name','wan0','netns',ns);run('ip','link','set','peer'+str(n),'master','br0');run('ip','link','set','peer'+str(n),'up')
  cli(n,'ip','link','set','lo','up');cli(n,'ip','link','set','wan0','up');cli(n,'ip','addr','add',f'192.0.2.{n*2}/24','dev','wan0');cli(n,'ip','-6','addr','add',f'fd42::{n*2}/64','dev','wan0','nodad')
 def snapshot(n,name):
  data=dict(routes=[cli(n,'ip',f,'route','show','table','all') for f in ['-4','-6']],rules=[cli(n,t,'-S') for t in ['iptables','ip6tables']],links=json.loads(cli(n,'ip','-j','link')));(root/f'{name}-{n}.json').write_text(json.dumps(data,indent=2));return data
 v6=a.inside.startswith('v6');keyed=a.inside.endswith('obfs');mode='obfs' if keyed else 'fake-tls';key='audit-shared-key' if keyed else '';bind='::' if v6 else '0.0.0.0';cfg=etc/'server.ini';users=etc/'users.ini';users.touch()
 cfg.write_text(f'[auth]\nusers_file = {users}\nrequire_client_key_proof = false\nbind_static_to_session = false\n[web]\nenabled = false\n[logging]\nlevel = debug\n[profile:audit]\nidentity_key = {etc}/identity.key\nbind.address = {bind}\nbind.port = 24443\nbind.transport = udp\ntun.name = qsource\ntun.address = 10.86.0.1\ntun.queues = 2\npool.cidr = 10.86.0.0/24\npool.exclude = 10.86.0.1\nrouting.nat.enabled = false\nrouting.ipv6.mode = off\nrouting.forward_private = true\ndns.enabled = false\nobf.mode = {mode}\nobf.obfs_key = {key}\n');cfg.chmod(0o600)
 for n in [1,2]:run(binary,'add-client','audit'+str(n),'--password-stdin','--profiles','audit','--static-ip',f'10.86.0.{n+1}','-c',cfg,input='fixture-password\n')
 try:
  capture=start([sys.executable,'-u','-c',CAPTURE],'capture.jsonl');wait(lambda:'READY' in (root/'capture.jsonl').read_text())
  server=start([binary,'server','-c',cfg],'server.log',dict(os.environ,QELI_CONTROL_SOCKET=str(root/'control.sock')));wait(lambda:':24443' in run('ss','-lnu'))
  echo=start([sys.executable,'-u','-c',ECHO,root/'echo-ready'],'echo.log');wait(lambda:(root/'echo-ready').exists())
  clients=[];before=[]
  for n in [1,2]:
   work=root/('client'+str(n));work.mkdir();status=work/'status.json';target=f'[fd42::{n*2-1}]' if v6 else f'192.0.2.{n*2-1}';ccfg=etc/f'client{n}.ini'
   ccfg.write_text(f'[qeli]\nserver = {target}:24443\nproto = udp\nuser = audit{n}\npass = fixture-password\nmode = {mode}\nobfs_key = {key}\ndev = qlocal\nbind_static = false\ngateway = false\ndns = off\nkill_switch = false\ntimeout = 10\nreconnect = false\n[logging]\nlevel = debug\n');ccfg.chmod(0o600)
   wait(lambda:'tentative' not in cli(n,'ip','-6','addr','show','dev','wan0'))
   (work/'state').mkdir(mode=0o700)
   before.append(snapshot(n,'before'));env=dict(os.environ,STATE_DIRECTORY=str(work/'state'),QELI_KNOWN_HOSTS=str(work/'known-hosts'),QELI_DEVICE_ID_FILE=str(work/'device-id'),QELI_CLIENT_STATUS=str(status))
   client=start(['ip','netns','exec','qc'+str(n),binary,'client','-c',ccfg],f'client{n}.log',env);clients.append((client,status))
  wait(lambda:all(state(s)=='running' or p.poll() is not None for p,s in clients))
  states=[state(s) for _,s in clients];assert states[0]=='running',states
  assert states[1]==('failed' if a.version=='baseline' else 'running'),states
  probes=[]
  for n,(client,status) in enumerate(clients,1):
   if state(status)=='running':probes.append(json.loads(cli(n,sys.executable,'-c',PROBE)))
  for client,status in clients:
   if client.poll() is None:client.send_signal(signal.SIGTERM)
  codes=[p.wait(timeout=25) for p,_ in clients];assert codes==([0,1] if a.version=='baseline' else [0,0]),codes
  for n in [1,2]:
   after=snapshot(n,'after');assert after['routes']==before[n-1]['routes'] and after['rules']==before[n-1]['rules'] and not any(l['ifname']=='qlocal' for l in after['links']);assert not list((root/('client'+str(n))/'state').rglob('*.state'))
  capture.terminate();capture.wait(timeout=5)
  packets=[json.loads(line) for line in (root/'capture.jsonl').read_text().splitlines() if line.startswith('{')];replies=[p for p in packets if p['sport']==24443]
  expected={('fd42::'+str(n*2) if v6 else '192.0.2.'+str(n*2)):('fd42::'+str(n*2-1) if v6 else '192.0.2.'+str(n*2-1)) for n in [1,2]}
  wrong=[p for p in replies if p['src']!=expected[p['dst']]]
  assert bool(wrong)==(a.version=='baseline'),wrong
  assert set(p['dst'] for p in replies)==set(expected)
  serverlog=(root/'server.log').read_text();assert '2 worker(s)' in serverlog
  result=dict(case=a.inside,version=a.version,sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),states=states,client_exits=codes,probes=probes,replies=len(replies),wrong_source=len(wrong),clean=True)
  (root/'result.json').write_text(json.dumps(result,indent=2))
 finally:
  for p in reversed(processes):
   if p.poll() is None:
    p.terminate()
    try:p.wait(timeout=20)
    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
if __name__=='__main__':main()
