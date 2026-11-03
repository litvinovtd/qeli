#!/usr/bin/env python3
"""Q09 TCP AUTH deadline: real CLI traffic delayed by a transparent plain proxy.
Run only inside the guarded lab runner's fresh NET/mount/PID namespaces.
"""
import argparse, ctypes, json, os, select, signal, socket, struct, subprocess, time
from pathlib import Path


def stop(p):
    if p is not None and p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=3)


def exact(s, n):
    out = b''
    while len(out) < n:
        b = s.recv(n - len(out))
        if not b: raise EOFError('handshake peer closed')
        out += b
    return out


def raw_record(s):
    header = exact(s, 2)
    return header + exact(s, struct.unpack('>H', header)[0])


def password_hash():
    lib = ctypes.CDLL('libargon2.so.1')
    f = lib.argon2id_hash_encoded
    f.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                  ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t,
                  ctypes.c_void_p, ctypes.c_size_t]
    f.restype = ctypes.c_int
    out = ctypes.create_string_buffer(256)
    password, salt = b'fixture-password', b'q09-fixture-salt'
    start = time.monotonic()
    assert f(16, 16384, 1, password, len(password), salt, len(salt), 32, out, len(out)) == 0
    duration = time.monotonic() - start
    rounds = max(2, min(50, round(16 * .25 / duration)))
    start = time.monotonic()
    assert f(rounds, 16384, 1, password, len(password), salt, len(salt), 32, out, len(out)) == 0
    return out.value.decode(), dict(memory_kib=16384, rounds=rounds, calibration_seconds=time.monotonic()-start)


def case(binary, root, hashed, expect_late):
    root.mkdir(mode=0o700)
    state=root/'state';state.mkdir(mode=0o700)
    env=dict(os.environ, STATE_DIRECTORY=str(state), QELI_CONTROL_SOCKET=str(root/'control.sock'),
             QELI_KNOWN_HOSTS=str(root/'known-hosts'), QELI_DEVICE_ID_FILE=str(root/'device-id'))
    cfg=root/'server.ini'
    cfg.write_text(f'''[auth]
users_file = {root}/users.ini
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = debug
[profile:deadline]
identity_key = {root}/identity.key
bind.address = 127.0.0.1
bind.port = 24943
bind.transport = tcp
tun.name = q09srv
tun.address = 10.79.0.1
pool.cidr = 10.79.0.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = plain
perf.connection.handshake_timeout_secs = 1
perf.connection.new_session_rate_max = 1000
[user:fixture]
password_hash = {hashed}
enabled = true
''',encoding='utf8');cfg.chmod(0o600)
    (root/'users.ini').write_text('',encoding='utf8')
    server=client=None;rows=[]
    with (root/'server.log').open('w') as sl:
        server=subprocess.Popen([binary,'server','-c',str(cfg)],env=env,stdout=sl,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            until=time.monotonic()+12
            while ':24943' not in subprocess.check_output(['ss','-lnt'],text=True):
                assert server.poll() is None
                assert time.monotonic()<until
                time.sleep(.05)
            for label, delay in [('late',.85), ('normal',0)]:
                cc=root/(label+'.ini');cl=root/(label+'.log')
                with socket.socket() as listener, cl.open('w') as log:
                    listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
                    cc.write_text(f'[qeli]\nserver=127.0.0.1:{listener.getsockname()[1]}\nproto=tcp\nuser=fixture\npass=fixture-password\nmode=plain\nbind_static=false\ndev=q09cli\ngateway=false\ndns=off\nkill_switch=false\ntimeout=8\n[logging]\nlevel=info\n',encoding='utf8');cc.chmod(0o600)
                    initial=(root/'server.log').stat().st_size
                    client=subprocess.Popen([binary,'client','-c',str(cc)],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                    peer,_=listener.accept()
                    with peer, socket.create_connection(('127.0.0.1',24943),timeout=5) as upstream:
                        started=time.monotonic();peer.settimeout(5);upstream.settimeout(5)
                        upstream.sendall(exact(peer,32));peer.sendall(exact(upstream,32));peer.sendall(raw_record(upstream))
                        auth=raw_record(peer)
                        time.sleep(max(0, started+delay-time.monotonic()))
                        sent=time.monotonic()-started;upstream.sendall(auth)
                        admitted=False;closed=False;until=time.monotonic()+6
                        while time.monotonic()<until:
                            text=(root/'server.log').read_text()[initial:]
                            if 'connected on profile' in text:
                                admitted=True;break
                            if 'handshake authentication deadline exceeded' in text:break
                            ready,_,_=select.select([peer,upstream],[],[],.05)
                            for src in ready:
                                data=src.recv(65536)
                                if not data:closed=True;break
                                (upstream if src is peer else peer).sendall(data)
                            if closed:break
                        expected=expect_late if label=='late' else True
                        assert admitted==expected, (label,admitted,expected,(root/'server.log').read_text()[initial:])
                        rows.append(dict(name=label+' actual TCP AUTH '+('admitted' if expected else 'deadline rejected'),status='PASS',auth_forwarded_seconds=sent,elapsed_seconds=time.monotonic()-started,admitted=admitted))
                        if label=='late' and not expect_late:
                            time.sleep(.05)
                            assert 'handshake authentication deadline exceeded' in (root/'server.log').read_text()[initial:]
                            rows.append(dict(name='original deadline reported',status='PASS'))
                stop(client);client=None
                # The cancelled blocking password job retains its Argon2 permit until done.
                time.sleep(1)
            if not expect_late:
                sockets = []
                initial = (root/'server.log').stat().st_size
                started = time.monotonic()
                try:
                    for index in range(280):
                        sock = socket.create_connection(('127.0.0.1',24943),timeout=2)
                        sock.setblocking(False)
                        sockets.append(sock)
                        # Avoid filling the kernel SYN backlog before the listener wakes.
                        if index % 8 == 7: time.sleep(.005)
                    assert time.monotonic() - started < .8, "fixture opens must precede the one-second expiry"
                    until = started + .8
                    while time.monotonic() < until and 'pre-auth gate full' not in (root/'server.log').read_text()[initial:]:
                        time.sleep(.01)
                    text = (root/'server.log').read_text()[initial:]
                    assert 'pre-auth gate full' in text, text
                    assert text.count('New TCP connection') <= 256, text
                    rows.append(dict(name='280 idle sockets exhaust bounded 256 pre-auth slots before spawn',status='PASS'))
                    until = started + 3
                    alive = set(sockets)
                    while alive and time.monotonic() < until:
                        ready,_,_ = select.select(list(alive),[],[],.05)
                        for sock in ready:
                            try: data = sock.recv(65536)
                            except ConnectionResetError: data = b''
                            if not data: alive.remove(sock)
                    assert not alive, len(alive)
                    rows.append(dict(name='all idle and refused sockets close within handshake deadline',status='PASS'))
                    with socket.create_connection(('127.0.0.1',24943),timeout=2) as probe:
                        probe.settimeout(.1)
                        try: probe.recv(1)
                        except socket.timeout: pass
                        else: raise AssertionError('pre-auth slot was not recovered')
                    rows.append(dict(name='listener accepts a fresh handshake after saturated gate recovers',status='PASS'))
                finally:
                    for sock in sockets: sock.close()
        finally:stop(client);stop(server)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ['baseline','fixed','output']:ap.add_argument('--'+name,required=True)
    a=ap.parse_args();root=Path(a.output);root.mkdir(mode=0o700,parents=True)
    subprocess.run(['ip','link','set','lo','up'],check=True)
    subprocess.run(['ip','link','add','wan09','type','dummy'],check=True)
    subprocess.run(['ip','addr','add','198.18.9.1/24','dev','wan09'],check=True)
    subprocess.run(['ip','link','set','wan09','up'],check=True)
    subprocess.run(['ip','route','add','default','dev','wan09'],check=True)
    hashed,cost=password_hash();r=dict(status='IN_PROGRESS',hash_cost=cost,cases=[])
    try:
        for label,binary,expected in [('baseline',a.baseline,True),('fixed',a.fixed,False)]:
            rows=case(binary,root/label,hashed,expected);r['cases'].append(dict(name=label,checks=rows))
        r['checks_passed']=sum(len(c['checks']) for c in r['cases']);r['status']='PASS'
    except BaseException:
        r['status']='FAIL'
        raise
    finally:(root/'result.json').write_text(json.dumps(r,indent=2)+'\n',encoding='utf8')
    print(json.dumps(r,indent=2))


if __name__=='__main__':main()
