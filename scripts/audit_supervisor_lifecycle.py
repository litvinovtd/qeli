#!/usr/bin/env python3
"""Full supervisor regression in fresh NET/mount/PID namespaces only."""
import argparse,concurrent.futures,json,os,signal,socket,subprocess,sys,time,urllib.request
from pathlib import Path

def ns(kind): return os.readlink('/proc/self/ns/'+kind)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--qeli',required=True);ap.add_argument('--artifacts',required=True);ap.add_argument('--inside',action='store_true',help=argparse.SUPPRESS);args=ap.parse_args()
 binary=Path(args.qeli).resolve(strict=True);root=Path(args.artifacts).resolve()
 if not args.inside:
  if os.geteuid()!=0:raise RuntimeError('requires root in a disposable Linux lab')
  root.mkdir(mode=0o700,parents=True,exist_ok=False)
  env=dict(os.environ,**{'QELI_AUDIT_PARENT_'+k.upper():ns(k) for k in ('net','mnt','pid')})
  return subprocess.run(['unshare','--net','--mount','--pid','--fork','--kill-child=KILL','--mount-proc',sys.executable,str(Path(__file__).resolve()),'--qeli',str(binary),'--artifacts',str(root),'--inside'],env=env,timeout=240).returncode
 if not all(os.environ.get('QELI_AUDIT_PARENT_'+k.upper()) and ns(k)!=os.environ['QELI_AUDIT_PARENT_'+k.upper()] for k in ('net','mnt','pid')):raise RuntimeError('fresh NET/mount/PID namespaces required')
 commands=[];results=[]
 def run(argv,check=True):
  p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20);commands.append(dict(argv=argv,exit_code=p.returncode,output=p.stdout));(root/'commands.json').write_text(json.dumps(commands,indent=2))
  if check and p.returncode:raise RuntimeError(p.stdout)
  return p
 run(['mount','--make-rprivate','/']);run(['ip','link','set','lo','up'])
 for path in ('/run','/var/lib','/var/log'):run(['mount','-t','tmpfs','tmpfs',path])
 Path('/var/lib/qeli').mkdir();Path('/var/log/qeli').mkdir();etc=root/'etc';etc.mkdir(mode=0o700)
 if not Path('/etc/qeli').is_dir():raise RuntimeError('host /etc/qeli mount point required')
 run(['mount','--bind',str(etc),'/etc/qeli']);(etc/'users.conf').write_text('')
 def wait(condition,deadline=20):
  end=time.monotonic()+deadline
  while time.monotonic()<end:
   if condition():return
   time.sleep(.05)
  raise AssertionError('condition timed out')
 def snapshot():
  return dict(links=sorted(x['ifname'] for x in json.loads(run(['ip','-j','link','show']).stdout)),rules4=[x for x in run(['iptables-save']).stdout.splitlines() if x.startswith('-A ') or (x.startswith(':') and ' - ' in x)],rules6=[x for x in run(['ip6tables-save']).stdout.splitlines() if x.startswith('-A ') or (x.startswith(':') and ' - ' in x)],routes4=run(['ip','-4','route','show','table','all']).stdout,routes6=run(['ip','-6','route','show','table','all']).stdout,forwarding4=Path('/proc/sys/net/ipv4/ip_forward').read_text(),forwarding6=Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text())
 for transport in ('tcp','udp'):
  case=root/transport;case.mkdir(mode=0o700);state=case/'state';state.mkdir(mode=0o700);control=case/'control.sock';cfg=etc/'server.conf';checks=[];peers=[];http='http://127.0.0.1:24880'
  def check(name,condition):
   checks.append(dict(name=name,passed=bool(condition)));(case/'checks.json').write_text(json.dumps(checks,indent=2));assert condition,name
  def api(path,post=False):
   req=urllib.request.Request(http+path,data=b'{}' if post else None,headers={'Content-Type':'application/json','Origin':http})
   with urllib.request.urlopen(req,timeout=15) as response:return json.load(response)
  def profile(name,tun,port,kind):
   return f'''[profile:{name}]
identity_key = /etc/qeli/{name}.key
bind.address = 127.0.0.1
bind.port = {port}
bind.transport = {kind}
tun.name = {tun}
tun.address = 10.74.{port-24442}.1
tun.queues = 1
pool.cidr = 10.74.{port-24442}.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
routing.post_up = printf u >> {case/name}-up
routing.post_down = printf d >> {case/name}-down
'''
  run(['ip','link','add','q14foreign','type','dummy']);foreign_before=json.loads(run(['ip','-j','link','show','q14foreign']).stdout)
  foreign_bind=socket.socket();foreign_bind.bind(('127.0.0.1',24444));foreign_bind.listen()
  cfg.write_text('''[auth]
users_file = /etc/qeli/users.conf
[web]
enabled = true
insecure_no_auth = true
bind = 127.0.0.1
port = 24880
tls = false
[logging]
level = debug
'''+profile('healthy','q14healthy',24443,transport)+profile('bind-busy','q14bind',24444,'tcp')+profile('tun-busy','q14foreign',24445,'tcp'));cfg.chmod(0o600);run([str(binary),'check-config','-c',str(cfg)])
  Path('/proc/sys/net/ipv4/ip_forward').write_text('0');Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('0');before=snapshot()
  env=dict(os.environ,STATE_DIRECTORY=str(state),QELI_CONTROL_SOCKET=str(control))
  with (case/'supervisor.log').open('w') as log:
   supervisor=subprocess.Popen([str(binary),'server','-c',str(cfg)],env=env,stdout=log,stderr=subprocess.STDOUT)
   def child():
    try:
     for name in Path('/proc',str(supervisor.pid),'task').iterdir():
      for value in (name/'children').read_text().split():
       p=Path('/proc',value,'cmdline')
       if p.exists() and b'_worker' in p.read_bytes().split(b'\0'):return int(value)
    except FileNotFoundError:pass
    return None
   try:
    # Control reply and healthy ingress are the readiness authority; panel status
    # spelling is kept as raw evidence rather than inferred from a log alone.
    def ingress():
     if supervisor.poll() is not None:raise AssertionError('supervisor exited')
     if not child() or not control.exists() or not (case/'healthy-up').exists():return False
     p=run([str(binary),'list-clients','--socket',str(control)],False)
     return p.returncode==0
    wait(ingress);initial=child();check('worker started and panel serves status',api('/api/status').get('ok') is not False)
    check('foreign TUN type/address unchanged',json.loads(run(['ip','-j','link','show','q14foreign']).stdout)==foreign_before)
    check('foreign bind still owned',foreign_bind.getsockname()==('127.0.0.1',24444))
    check('healthy TUN present with failing siblings',run(['ip','link','show','q14healthy'],False).returncode==0)
    os.kill(initial,signal.SIGHUP);time.sleep(.5);check('SIGHUP retains worker generation',child()==initial and ingress())
    os.kill(initial,signal.SIGKILL);wait(lambda:child() not in (None,initial));wait(ingress);after_crash=child();check('crashed worker respawned with new PID',after_crash!=initial)
    check('panel remains up after crash',api('/api/system').get('ok') is not False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:replies=list(pool.map(lambda _:api('/api/server/restart',True),range(6)))
    (case/'restart-replies.json').write_text(json.dumps(replies,indent=2));check('six panel restart requests accepted',all(x.get('ok') for x in replies))
    wait(lambda:child() not in (None,after_crash));wait(ingress);time.sleep(.7);wait(ingress);check('worker recovered after restart burst',child()!=after_crash)
    worker=child();base_fds=len(list(Path('/proc',str(worker),'fd').iterdir()))
    for number in range(24):
     peer=socket.socket(socket.AF_UNIX);peer.settimeout(2);peer.connect(str(control));peers.append(peer)
     if number>=16:
      try:peer.sendall(b'x'*(65536+3)+b'\n')
      except (BrokenPipeError,ConnectionResetError):pass
    time.sleep(.25);peak_fds=len(list(Path('/proc',str(worker),'fd').iterdir()));check('control pressure remains bounded',peak_fds<=base_fds+64 and supervisor.poll() is None)
    # Stop while silent/oversized requests are still admitted or queued.
    started=time.monotonic();supervisor.send_signal(signal.SIGTERM);rc=supervisor.wait(timeout=25);elapsed=time.monotonic()-started
    check('normal stop succeeds under control pressure',rc==0);check('stop/drain finishes within 20 seconds',elapsed<20)
    check('worker PID reaped',not Path('/proc',str(worker)).exists());check('control socket removed',not control.exists())
    check('healthy and failed-bind TUNs removed',all(run(['ip','link','show',x],False).returncode!=0 for x in ('q14healthy','q14bind')))
    check('foreign TUN preserved after stop',json.loads(run(['ip','-j','link','show','q14foreign']).stdout)==foreign_before)
    check('foreign listening socket preserved after stop',foreign_bind.getsockname()==('127.0.0.1',24444))
    check('network restored to exact normalized baseline',snapshot()==before)
    check('no panel listener remains after CLI exit',run(['ss','-ltn']).stdout.find(':24880')<0)
    results.append(dict(transport=transport,status='PASS',checks=checks,initial_pid=initial,respawn_pid=after_crash,stop_seconds=elapsed,control_fd_baseline=base_fds,control_fd_peak=peak_fds))
    (root/'results.json').write_text(json.dumps(results,indent=2));print(transport,len(checks),'supervisor checks PASS',flush=True)
   finally:
    for peer in peers:peer.close()
    if supervisor.poll() is None:supervisor.kill();supervisor.wait(timeout=5)
    foreign_bind.close();run(['ip','link','del','q14foreign'])
 return 0
if __name__=='__main__':raise SystemExit(main())
