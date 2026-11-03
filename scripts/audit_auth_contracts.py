#!/usr/bin/env python3
"""Actual PQ/AEAD peers exercise decrypted proof/capabilities, with a private server.
Run only within the NET/mount/PID isolation provided by the lab runner.
"""
import argparse,json,os,subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from audit_udp_handshake_contracts import hashed,wait_for,control,stop


def scenario(binary,peer,root,transport):
    root.mkdir(mode=0o700);(root/'state').mkdir(mode=0o700)
    config=f'''[auth]
users_file = {root}/users.ini
require_client_key_proof = true
bind_static_to_session = false
[web]
enabled = false
[logging]
level = debug
[profile:auth-contracts]
identity_key = {root}/identity.key
bind.address = 127.0.0.1
bind.port = 24943
bind.transport = {'tcp' if transport=='tcp' else 'udp'}
tun.name = q09srv
tun.address = 10.79.0.1
pool.cidr = 10.79.0.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = false
obf.traffic_shaping.enabled = false
perf.connection.handshake_timeout_secs = 5
perf.connection.new_session_rate_max = 1000
[user:fixture]
password_hash = {hashed()}
enabled = true
'''
    (root/'server.ini').write_text(config);(root/'server.ini').chmod(0o600);(root/'users.ini').write_text('')
    env=dict(os.environ,STATE_DIRECTORY=str(root/'state'),QELI_CONTROL_SOCKET=str(root/'control.sock'))
    observations=[];checks=[]
    def invoke(case,index):
        result=subprocess.run([peer,transport,'127.0.0.1:24943',str(root/'identity.key'),case],capture_output=True,text=True,timeout=12)
        (root/f'peer-{index}.log').write_text(result.stdout+result.stderr)
        assert result.returncode==0,(case,result.stdout,result.stderr)
        row=json.loads(result.stdout);assert row['server_proof_verified']
        return row
    def clear():
        if control(root,'list-clients')['clients']:control(root,'kick',username='fixture')
        wait_for(lambda:not control(root,'list-clients')['clients'])
    log=(root/'server.log').open('w');server=None
    try:
        server=subprocess.Popen([binary,'server','-c',str(root/'server.ini')],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        wait_for(lambda:':24943' in subprocess.check_output(['ss','-lnt' if transport=='tcp' else '-lnu'],text=True),12)
        # A valid peer before and after negatives proves fixture/key schedule/pin correctness.
        for index,case in enumerate(['legacy','forged-proof','version','length','policy','truncated','ipv6-required','valid']):
            before=(root/'server.log').read_text();row=invoke(case,index);observations.append(row)
            if case not in ('legacy','valid'):
                assert not control(root,'list-clients')['clients'],case
                checks.append(case+' leaves no admitted session')
                expected={'forged-proof':'server key not pinned','version':'unsupported client capability version','length':'malformed client capability','policy':'invalid client IPv6 policy','truncated':'truncated client capability','ipv6-required':'IPv4-only'}[case]
                wait_for(lambda:expected in (root/'server.log').read_text()[len(before):])
                checks.append(case+' reaches expected decrypted server rejection')
            else:
                assert row['accepted'];checks.append(case+' accepted after verified server proof')
                clear()
        # Valid and invalid AUTH are concurrent; parser/proof refusal must not starve admission.
        cases=['valid']*4+['forged-proof','version','policy','truncated']
        with ThreadPoolExecutor(max_workers=8) as executor:
            parallel=list(executor.map(lambda item:invoke(item[1],'parallel-'+str(item[0])),enumerate(cases)))
        assert sum(row['accepted'] for row in parallel)==4
        observations.extend(parallel);checks.extend('concurrent '+row['case']+' '+('accepted' if row['accepted'] else 'rejected') for row in parallel)
        clear()
        return dict(transport=transport,observations=observations,checks=checks,status='PASS')
    finally:
        stop(server);log.close()


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--qeli',required=True);ap.add_argument('--peer',required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args();a.output.mkdir(mode=0o700)
    subprocess.run(['ip','link','set','lo','up'],check=True)
    r=dict(status='RUNNING',cases=[])
    try:
        for transport in ['tcp','udp','quic']:
            r['cases'].append(scenario(a.qeli,a.peer,a.output/transport,transport));print('PASS',transport,len(r['cases'][-1]['checks']),flush=True)
        r['status']='PASS';r['checks_passed']=sum(len(c['checks']) for c in r['cases'])
    except BaseException:r['status']='FAIL';raise
    finally:(a.output/'result.json').write_text(json.dumps(r,indent=2)+'\n')
if __name__=='__main__':main()
