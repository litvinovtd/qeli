#!/usr/bin/env python3
"""Reproduce terminal KICK racing TCP EOF with actual paused CLI clients.
Only run through a lab runner with fresh NET/mount/PID namespaces.
"""
import argparse,json,os,signal,socket,subprocess,time
from pathlib import Path
from audit_udp_handshake_contracts import hashed,stop,wait_for,control


def run(*args):return subprocess.check_output(args,stderr=subprocess.STDOUT,text=True)


def case(binary,root,rounds):
    root.mkdir(mode=0o700);(root/'state').mkdir(mode=0o700);port=24943;root=str(root);p=Path(root)
    env=dict(os.environ,STATE_DIRECTORY=root+'/state',QELI_CONTROL_SOCKET=root+'/control.sock')
    config=f'''[auth]
users_file = {root}/users.ini
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = debug
[profile:terminal]
identity_key = {root}/identity.key
bind.address = 198.18.0.1
bind.port = {port}
bind.transport = tcp
tun.name = q09srv
tun.address = 10.79.0.1
pool.cidr = 10.79.0.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = false
obf.traffic_shaping.enabled = false
perf.connection.handshake_timeout_secs = 10
perf.connection.new_session_rate_max = 1000
[user:fixture]
password_hash = {hashed()}
enabled = true
'''
    (p/'server.ini').write_text(config);(p/'server.ini').chmod(0o600);(p/'users.ini').write_text('')
    logs=[];clients=[];server=None;paused=None;observations=[]
    try:
        sl=(p/'server.log').open('w');logs.append(sl)
        server=subprocess.Popen([binary,'server','-c',root+'/server.ini'],env=env,stdout=sl,stderr=subprocess.STDOUT,start_new_session=True)
        wait_for(lambda:':24943' in run('ss','-lnt'),12)
        for index in range(rounds):
            current=[]
            for i in range(2):
                ns='q09n'+str(i);name=f'round{index}-client{i}';log_path=p/(name+'.log')
                config=p/(name+'.ini')
                config.write_text(f'[qeli]\nserver=198.18.0.1:{port}\nproto=tcp\nuser=fixture\npass=fixture-password\nmode=fake-tls\nbind_static=false\ndev=q09c{i}\ngateway=false\ndns=off\nkill_switch=false\ntimeout=8\n[logging]\nlevel=debug\n');config.chmod(0o600)
                cl=log_path.open('w');logs.append(cl)
                client_env=dict(env,QELI_DEVICE_ID_FILE=root+'/shared-device-id',QELI_KNOWN_HOSTS=root+'/'+name+'-known')
                # One CPU makes publication+EOF reach the supervisor in the same scheduling turn.
                cpus=sorted(os.sched_getaffinity(0));command=['ip','netns','exec',ns,'taskset','-c',str(cpus[0]),binary,'client','-c',str(config)]
                client=subprocess.Popen(command,env=client_env,stdout=cl,stderr=subprocess.STDOUT,start_new_session=True);clients.append(client);current.append(client)
                wait_for(lambda:'TUN writer started' in log_path.read_text() or client.poll() is not None,12)
                assert client.poll() is None,log_path.read_text()
                run('ip','netns','exec',ns,'ping','-I','q09c'+str(i),'-c','1','-W','2','10.79.0.1')
                if i==0:
                    os.killpg(client.pid,signal.SIGSTOP);paused=client
                else:
                    # Supersede has now waited for the paused old client's ACK, then closed it.
                    rows=control(p,'list-clients')['clients'];assert len(rows)==1 and rows[0]['peer'].startswith('198.18.2.2:'),rows
            os.killpg(paused.pid,signal.SIGCONT);paused=None
            old_path=p/f'round{index}-client0.log'
            wait_for(lambda:'server terminated the session: Session replaced by a newer connection' in old_path.read_text() or 'Reconnecting in' in old_path.read_text(),5)
            text=old_path.read_text();terminal='server terminated the session: Session replaced by a newer connection' in text
            reconnect='Reconnecting in' in text
            observations.append(dict(round=index,terminal=terminal,reconnect=reconnect))
            for client in current:stop(client)
            if control(p,'list-clients')['clients']:
                control(p,'kick',username='fixture')
            wait_for(lambda:not control(p,'list-clients')['clients'])
            print('ROUND',index,'terminal',terminal,'reconnect',reconnect,flush=True)
        return observations
    finally:
        if paused is not None:os.killpg(paused.pid,signal.SIGCONT)
        for client in clients:stop(client)
        stop(server)
        for f in logs:f.close()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline',required=True);ap.add_argument('--fixed');ap.add_argument('--output',required=True,type=Path);ap.add_argument('--rounds',type=int,default=4)
    a=ap.parse_args();a.output.mkdir(mode=0o700);r=dict(status='RUNNING',cases=[])
    for args in [('ip','link','set','lo','up'),('ip','link','add','wan09','type','dummy'),('ip','addr','add','198.18.0.1/32','dev','wan09'),('ip','link','set','wan09','up'),('ip','route','add','default','dev','wan09')]:run(*args)
    for i in range(2):
        ns='q09n'+str(i);srv='q09s'+str(i);peer='q09v'+str(i);base=f'198.18.{i+1}.'
        for args in [('ip','netns','add',ns),('ip','link','add',srv,'type','veth','peer','name',peer),('ip','link','set',peer,'netns',ns),('ip','addr','add',base+'1/30','dev',srv),('ip','link','set',srv,'up'),('ip','netns','exec',ns,'ip','link','set','lo','up'),('ip','netns','exec',ns,'ip','addr','add',base+'2/30','dev',peer),('ip','netns','exec',ns,'ip','link','set',peer,'up'),('ip','netns','exec',ns,'ip','route','add','default','via',base+'1')]:run(*args)
    try:
        baseline=case(a.baseline,a.output/'baseline',a.rounds);r['cases'].append(dict(id='baseline',observations=baseline));assert any(x['reconnect'] and not x['terminal'] for x in baseline),'baseline race not reproduced'
        if a.fixed:
            fixed=case(a.fixed,a.output/'fixed',a.rounds);r['cases'].append(dict(id='fixed',observations=fixed));assert all(x['terminal'] and not x['reconnect'] for x in fixed),'fixed lost terminal reason'
        r['status']='PASS';r['checks_passed']=sum(len(c['observations']) for c in r['cases'])
    except BaseException:r['status']='FAIL';raise
    finally:
        (a.output/'result.json').write_text(json.dumps(r,indent=2)+'\n')
        for i in range(2):
            subprocess.run(['ip','netns','del','q09n'+str(i)],check=False,capture_output=True)
            # Deleting the namespace normally deletes both ends of its veth.
            subprocess.run(['ip','link','del','q09s'+str(i)],check=False,capture_output=True)


if __name__=='__main__':main()
