#!/usr/bin/env python3
"""IPv4 C->A->B fail-closed guard using iptables/ip6tables only.

Early mangle/FORWARD DROP precedes Qeli's filter/FORWARD permits. The watcher
does not remove protection on stop. No global iptables backend changes.
"""
import argparse,fcntl,json,os,re,signal,subprocess,time
from pathlib import Path

CHAIN='QELI_CHAIN_IN'
def require(condition,message):
 if not condition:raise RuntimeError(message)

def run(*args,check=True):
 p=subprocess.run(args,text=True,capture_output=True)
 if check and p.returncode:raise RuntimeError(f'{args[:4]}: {p.stderr.strip()}')
 return p

def ipt(binary,*args,check=True):return run(binary,'-w','5','-t','mangle',*args,check=check)

def log(event,**fields):print(json.dumps(dict(time=time.time(),event=event,**fields)),flush=True)

def rule_owned(rule,table,ingress):return str(rule.get('table'))==str(table) and rule.get('iif')==ingress

def chain_exists(binary):return ipt(binary,'-S',CHAIN,check=False).returncode==0

def publish(binary,ingress,upstream,ipv6,owned):
 exists=chain_exists(binary)
 require(not exists or owned,'foreign chain uses reserved name '+CHAIN)
 expected=([['-o',upstream,'-j','RETURN']] if not ipv6 else [])+[['-j','DROP']]
 if not exists:
  ipt(binary,'-N',CHAIN)
  for args in expected:ipt(binary,'-A',CHAIN,*args)
 for args in expected:require(ipt(binary,'-C',CHAIN,*args,check=False).returncode==0,'guard rule missing')
 rows=[x for x in ipt(binary,'-S',CHAIN).stdout.splitlines() if x.startswith('-A ')]
 require(len(rows)==len(expected),'unexpected rule in owned guard chain')
 jump=['-i',ingress,'-j',CHAIN]
 if ipt(binary,'-C','FORWARD',*jump,check=False).returncode:ipt(binary,'-I','FORWARD','1',*jump)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--ingress',default='qeli-in');p.add_argument('--upstream',default='qeli-out')
 p.add_argument('--table',type=int,default=208);p.add_argument('--priority',type=int,default=20800)
 p.add_argument('--once',action='store_true');p.add_argument('--state',default='/run/qeli-chain-guard');a=p.parse_args()
 require(os.geteuid()==0,'root required')
 require(all(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}',x) for x in (a.ingress,a.upstream)) and a.ingress!=a.upstream,'invalid interfaces')
 require(1<=a.table<=2147483647 and a.table not in (253,254,255) and 1<=a.priority<=32765,'reserved table/priority')
 state=Path(a.state);state.mkdir(mode=0o700,parents=True,exist_ok=True)
 require(not state.is_symlink() and state.stat().st_uid==0 and state.stat().st_mode&0o022==0,'unsafe state directory')
 lock=open(state/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 spec=dict(ingress=a.ingress,upstream=a.upstream,table=a.table,priority=a.priority,backend='iptables-mangle-v1')
 receipt=state/'owner.json';owned=receipt.exists()
 if owned:require(json.loads(receipt.read_text())==spec,'ownership/config mismatch')
 rules=json.loads(run('ip','-4','-j','rule','show').stdout);conflicts=[r for r in rules if r.get('priority')==a.priority]
 current=run('ip','-4','route','show','table',str(a.table),check=False).stdout.strip()
 if not owned:
  require(not chain_exists('iptables') and not chain_exists('ip6tables') and not conflicts and not current,'reserved routing/firewall resources already used')
  receipt.write_text(json.dumps(spec));os.chmod(receipt,0o600)
 else:require(all(rule_owned(r,a.table,a.ingress) for r in conflicts),'foreign policy rule at reserved priority')
 # Complete rules are populated before the jump; ingress must not start before --once succeeds.
 publish('iptables',a.ingress,a.upstream,False,owned);publish('ip6tables',a.ingress,a.upstream,True,owned)
 run('ip','-4','route','replace','blackhole','default','metric','32767','table',str(a.table))
 if not conflicts:run('ip','-4','rule','add','priority',str(a.priority),'iif',a.ingress,'lookup',str(a.table))
 log('protected',**spec);running=True;previous=None
 def stop(*_):
  nonlocal running
  running=False
 signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
 while running:
  link=next((x for x in json.loads(run('ip','-j','link','show').stdout) if x['ifname']==a.upstream and 'UP' in x['flags']),None)
  generation=link['ifindex'] if link else None
  if link:
   text=run('ip','-4','route','show','table',str(a.table)).stdout
   if f'default dev {a.upstream} ' not in text:
    run('ip','-4','route','replace','default','dev',a.upstream,'metric','10','table',str(a.table));log('route_restored',ifindex=generation)
  if generation!=previous:log('generation',ifindex=generation);previous=generation
  if a.once:break
  time.sleep(.2)
 log('watcher_stopped_protection_retained')
if __name__=='__main__':main()
