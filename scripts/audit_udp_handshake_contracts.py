#!/usr/bin/env python3
"""Q09 UDP contracts through real CLI PQ handshakes in fresh lab namespaces.
The private ip shim delays only fixture-owned iroute installation; it delegates
all commands to the real ip executable. No working service or host route is used.
"""
import argparse, ctypes, json, os, select, signal, socket, struct, subprocess, time
from pathlib import Path

MAGIC = b'\xf0\x9b\x71'
ENDPOINT = ('127.0.0.1', 24943)


def stop(p):
    if p is not None and p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=3)


def wait_for(predicate, seconds=8):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        if predicate(): return
        time.sleep(.01)
    raise AssertionError('fixture condition timed out')


def control(root, cmd, **kw):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(4);s.connect(str(root/'control.sock'))
        s.sendall((json.dumps(dict(cmd=cmd,**kw))+'\n').encode());s.shutdown(socket.SHUT_WR)
        data=b''
        while b'\n' not in data:
            chunk=s.recv(65536)
            if not chunk:break
            data+=chunk
        result=json.loads(data)
        assert result['ok'],result
        return result


def receive(s, seconds):
    packets=[];until=time.monotonic()+seconds
    while time.monotonic()<until:
        if select.select([s],[],[],max(0,until-time.monotonic()))[0]:
            packet,peer=s.recvfrom(65535)
            if peer==ENDPOINT:packets.append(packet) # Client shutdown may leave an unsent tail in the proxy.
    return packets


def body(packet, quic):
    if not quic:return packet
    if packet[0]==0x43:return packet[9:]
    assert packet[0] in (0xc3,0xe3)
    at=12;size=1 << (packet[at]>>6)
    return packet[at+size+4:]


def recode(packet, replacement, quic):
    if not quic:return replacement
    assert packet[0] in (0xc3,0xe3)
    length=4+len(replacement)
    return packet[:12]+struct.pack('>H',0x4000|length)+packet[14:18]+replacement


def hashed():
    lib=ctypes.CDLL('libargon2.so.1');f=lib.argon2id_hash_encoded
    f.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t];f.restype=ctypes.c_int
    out=ctypes.create_string_buffer(256);password=b'fixture-password';salt=b'q09-udp-fixture'
    assert f(2,8192,1,password,len(password),salt,len(salt),32,out,len(out))==0
    return out.value.decode()


class Server:
    def __init__(self,binary,root,hash_value,routes=(),timeout=20,delay=0,proof=False):
        self.binary=str(binary);self.root=root;root.mkdir(mode=0o700);(root/'state').mkdir(mode=0o700)
        self.env=dict(os.environ,STATE_DIRECTORY=str(root/'state'),QELI_CONTROL_SOCKET=str(root/'control.sock'),QELI_KNOWN_HOSTS=str(root/'known-hosts'),QELI_DEVICE_ID_FILE=str(root/'device-id'))
        self.client=None;self.log=(root/'server.log').open('w')
        config=f'''[auth]
users_file = {root}/users.ini
require_client_key_proof = {str(proof).lower()}
bind_static_to_session = false
[web]
enabled = false
[logging]
level = debug
[profile:contracts]
identity_key = {root}/identity.key
bind.address = 127.0.0.1
bind.port = 24943
bind.transport = udp
tun.name = q09srv
tun.address = 10.79.0.1
pool.cidr = 10.79.0.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
obf.mode = fake-tls
obf.heartbeat.enabled = false
obf.traffic_shaping.enabled = false
perf.connection.handshake_timeout_secs = {timeout}
perf.connection.new_session_rate_max = 1000
[user:fixture]
password_hash = {hash_value}
enabled = true
'''+''.join('client_subnet = '+route+'\n' for route in routes)
        (root/'server.ini').write_text(config);(root/'server.ini').chmod(0o600);(root/'users.ini').write_text('')
        if delay:
            shim=root/'bin';shim.mkdir(mode=0o700)
            # Delay at most .6 seconds inside the existing one-second route-operation limit.
            real_ip=subprocess.check_output(['which','ip'],text=True).strip()
            text='#!/usr/bin/python3\nimport os,sys,time\nfrom pathlib import Path\na=sys.argv[1:]\nif a[:1]==["-4"]:a=a[1:]\n'
            text+=f"if len(a)>2 and a[:2]==['route','add'] and a[2] in {list(routes)!r}:\n Path({str(root/'entered')!r}).write_text(a[2])\n time.sleep({delay!r})\n Path({str(root/'done')!r}).write_text(a[2])\nos.execv({real_ip!r},[{real_ip!r}]+a)\n"
            (shim/'ip').write_text(text);(shim/'ip').chmod(0o700)
            self.env['PATH']=str(shim)+':'+os.environ['PATH']
        self.process=subprocess.Popen([self.binary,'server','-c',str(root/'server.ini')],env=self.env,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
        wait_for(lambda: ':24943' in subprocess.check_output(['ss','-lnu'],text=True) if self.process.poll() is None else (_ for _ in ()).throw(AssertionError((root/'server.log').read_text())),12)

    def start_client(self,proxy,quic,user='fixture',password='fixture-password'):
        cfg=self.root/'client.ini'
        cfg.write_text(f'[qeli]\nserver=127.0.0.1:{proxy.getsockname()[1]}\nproto=udp\nuser={user}\npass={password}\nmode=fake-tls\nbind_static=false\nquic={str(quic).lower()}\ndev=q09cli\ngateway=false\ndns=off\nkill_switch=false\ntimeout=8\n[logging]\nlevel=info\n');cfg.chmod(0o600)
        self.client_log=(self.root/'client.log').open('w')
        self.client=subprocess.Popen([self.binary,'client','-c',str(cfg)],env=self.env,stdout=self.client_log,stderr=subprocess.STDOUT,start_new_session=True)

    def capture(self,proxy,quic,forward_hello=True):
        fragments=[];auth=None;until=time.monotonic()+8
        while time.monotonic()<until:
            if not select.select([proxy],[],[],.05)[0]:continue
            packet,peer=proxy.recvfrom(65535)
            if peer==ENDPOINT:
                if not forward_hello:
                    os.killpg(self.client.pid,signal.SIGKILL);self.client.wait(timeout=2);self.client=None
                    self.initial_hello=[packet]+receive(proxy,.1)
                    return fragments,None
                proxy.sendto(packet,self.client_peer)
            else:
                self.client_peer=peer;inner=body(packet,quic)
                if inner[:4]==MAGIC+b'\x01':
                    fragments.append(packet);proxy.sendto(packet,ENDPOINT)
                else:
                    auth=packet;os.killpg(self.client.pid,signal.SIGKILL);self.client.wait(timeout=2);self.client=None;receive(proxy,.05)
                    return fragments,auth
        raise AssertionError('real PQ CLI handshake not captured: '+(self.root/'server.log').read_text()+(self.root/'client.log').read_text())

    def close(self):
        stop(self.client);stop(self.process);self.log.close()
        if hasattr(self,'client_log'):self.client_log.close()


def auth_case(binary,root,hash_value,quic,fixed,late):
    routes=['172.31.9.0/24','172.31.10.0/24','172.31.11.0/24'] if late else ['172.31.9.0/24']
    server=Server(binary,root,hash_value,routes,1 if late else 20,.45 if late else .6)
    checks=[]
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as proxy:
            proxy.bind(('127.0.0.1',0));server.start_client(proxy,quic)
            fragments,auth=server.capture(proxy,quic);assert auth
            # Corrupt ciphertext first: it must not invoke authentication or allocate a session.
            corrupt=bytearray(auth);corrupt[-1]^=1;proxy.sendto(corrupt,ENDPOINT)
            assert receive(proxy,.1)==[]
            assert 'AUTH attempt UDP' not in (root/'server.log').read_text()
            assert not control(root,'list-clients')['clients'];checks.append('AEAD mutation silent before AUTH/admission')
            proxy.sendto(auth,ENDPOINT);wait_for(lambda:(root/'entered').exists())
            assert not (root/'done').exists()
            proxy.sendto(auth,ENDPOINT);early=receive(proxy,.15)
            assert bool(early)==(not fixed),(fixed,late,[p.hex() for p in early],(root/'server.log').read_text())
            assert not (root/'done').exists(),'fixture missed the admission window'
            checks.append('no cached AuthOK before route commit' if fixed else 'baseline early cached AuthOK reproduced')
            if late:
                wait_for(lambda:'admission rolled back' in (root/'server.log').read_text() if fixed else 'authenticated on profile' in (root/'server.log').read_text(),8)
                packets=receive(proxy,.2)
                if fixed:
                    assert not packets,packets
                    assert not control(root,'list-clients')['clients']
                    table=subprocess.check_output(['ip','-4','route','show'],text=True)
                    assert not any(route in table for route in routes),table
                    checks.extend(['expired AuthOK not sent','session registry rolled back','all installed fixture iroutes removed'])
                else:
                    assert packets and control(root,'list-clients')['clients']
                    checks.append('baseline admitted after original deadline')
            else:
                wait_for(lambda:'authenticated on profile' in (root/'server.log').read_text(),8)
                primary=receive(proxy,.1);assert primary
                expected=[body(p,quic) for p in primary]
                assert control(root,'list-clients')['clients'];checks.append('initial AuthOK follows completed admission')
                # QUIC replay matching is by inner ciphertext; change PN for each retry.
                replies=0
                for n in range(7):
                    wire=(auth[:5]+struct.pack('>I',100+n)+auth[9:]) if quic else auth
                    proxy.sendto(wire,ENDPOINT);packets=receive(proxy,.035)
                    if packets:
                        assert [body(p,quic) for p in packets]==expected
                        replies+=1
                assert replies==(5 if fixed else 4),replies
                checks.append('cached retransmit ciphertext identical; five-send cap enforced')
                control(root,'kick',username='fixture');receive(proxy,.1)
                wire=(auth[:5]+struct.pack('>I',200)+auth[9:]) if quic else auth
                proxy.sendto(wire,ENDPOINT);assert receive(proxy,.1)==[]
                assert not control(root,'list-clients')['clients'];checks.append('kick leaves no registry entry or replay reply')
        return checks
    finally:server.close()


def direction_case(binary,root,hash_value,quic,fixed):
    server=Server(binary,root,hash_value);checks=[]
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as proxy:
            proxy.bind(('127.0.0.1',0));server.start_client(proxy,quic)
            fragments,_=server.capture(proxy,quic,False)
            parts={body(p,quic)[4]:p for p in fragments};assert len(parts)==body(fragments[0],quic)[5]
            for direction in (2,6):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as source:
                    source.bind(('127.0.0.1',0))
                    for packet in parts.values():
                        inner=body(packet,quic);replacement=inner[:3]+bytes([direction])+inner[4:]
                        source.sendto(recode(packet,replacement,quic),ENDPOINT)
                    replies=receive(source,.15)
                    assert bool(replies)==(not fixed),(direction,fixed)
                    checks.append(f'direction {direction}: '+('silent' if fixed else 'baseline ServerHello oracle reproduced'))
            if fixed:
                # A fresh source sees reverse order plus a duplicate tail, then one ServerHello.
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as source:
                    source.bind(('127.0.0.1',0));reverse=list(parts.values())[::-1]
                    source.sendto(reverse[0],ENDPOINT);source.sendto(reverse[0],ENDPOINT)
                    assert receive(source,.08)==[]
                    for packet in reverse[1:]:source.sendto(packet,ENDPOINT)
                    replies=receive(source,.15);assert replies
                    assert all(body(p,quic)[:4]==MAGIC+b'\x02' for p in replies)
                    checks.extend(['missing fragments/duplicate tail do not respond','out-of-order complete PQ ClientHello responds'])
                complete=b''.join(body(parts[i],quic)[6:] for i in sorted(parts))
                signature=b'\x11\xec\x04\xc0'
                assert complete.count(signature)==1,'real hybrid key-share shape missing'
                key_at=complete.index(signature)+4
                for name,at,replacement in [('noncanonical ML-KEM key',key_at,b'\xff\xff'),('low-order X25519 share',key_at+1184,b'\0'*32),('missing mandatory hybrid group',key_at-4,b'\x0a\x0a')]:
                    mutated=complete[:at]+replacement+complete[at+len(replacement):]
                    if name=='low-order X25519 share':
                        # Qeli's legacy camouflage extracts the separate classic share for DH.
                        classic=b'\x00\x1d\x00\x20';assert complete.count(classic)==1
                        classic_at=complete.index(classic)+4
                        mutated=mutated[:classic_at]+b'\0'*32+mutated[classic_at+32:]
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as source:
                        source.bind(('127.0.0.1',0));offset=0
                        for i in sorted(parts):
                            packet=parts[i];inner=body(packet,quic);length=len(inner)-6
                            source.sendto(recode(packet,inner[:6]+mutated[offset:offset+length],quic),ENDPOINT);offset+=length
                        assert receive(source,.15)==[],name
                        checks.append(name+' silently rejected before AUTH')
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as source:
                    source.bind(('127.0.0.1',0));tail=reverse[0];bad=bytearray(tail);bad[-1]^=1
                    source.sendto(tail,ENDPOINT);source.sendto(bad,ENDPOINT)
                    for packet in reverse[1:]:source.sendto(packet,ENDPOINT)
                    assert receive(source,.1)==[]
                    checks.append('conflicting duplicate clears partial reassembly without reply')
            if fixed:
                input_bytes=sum(len(p) for p in fragments)
                output_bytes=sum(len(p) for p in server.initial_hello)
                for n in range(100):
                    trigger=MAGIC+bytes([1,0,1])+b'X'
                    wire=recode(fragments[0],trigger,quic)
                    input_bytes+=len(wire);proxy.sendto(wire,ENDPOINT)
                    output_bytes+=sum(len(p) for p in receive(proxy,.003))
                assert output_bytes<=3*input_bytes+72,(input_bytes,output_bytes)
                checks.append('100 tiny valid-direction retry triggers stay within charged 3x budget plus bounded wrapper slack')
            assert 'AUTH attempt UDP' not in (root/'server.log').read_text()
            assert not control(root,'list-clients')['clients'];checks.append('no AUTH or authenticated resource from fragment probes')
        return checks
    finally:server.close()


def negative_case(binary,root,hash_value,quic,kind):
    server=Server(binary,root,hash_value,proof=kind=='proof');checks=[]
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as proxy:
            proxy.bind(('127.0.0.1',0));server.start_client(proxy,quic,user='missing' if kind=='user' else 'fixture',password='wrong' if kind=='password' else 'fixture-password')
            if kind=='proof':
                until=time.monotonic()+5
                while time.monotonic()<until:
                    if select.select([proxy],[],[],.03)[0]:
                        packet,peer=proxy.recvfrom(65535)
                        if peer==ENDPOINT:proxy.sendto(packet,server.client_peer)
                        else:server.client_peer=peer;proxy.sendto(packet,ENDPOINT)
                    if 'server sent proof-only' in (root/'client.log').read_text():break
                else:raise AssertionError('proof-only refusal missing')
                os.killpg(server.client.pid,signal.SIGKILL);server.client.wait(timeout=2);server.client=None
                assert 'AUTH attempt UDP' not in (root/'server.log').read_text()
                assert not control(root,'list-clients')['clients']
                return ['proof-only identity refuses unpinned/TOFU client before AUTH','proof-only rejection leaves no authenticated registry resource']
            _,auth=server.capture(proxy,quic);proxy.sendto(auth,ENDPOINT)
            wait_for(lambda:'AUTH failed' in (root/'server.log').read_text() or 'AUTH FAIL' in (root/'server.log').read_text() or 'AUTH DENIED' in (root/'server.log').read_text(),4)
            assert receive(proxy,.15)==[]
            assert not control(root,'list-clients')['clients']
            checks.extend([kind+' rejected without AuthOK',kind+' leaves no authenticated registry resource'])
        return checks
    finally:server.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','fixed','output'):parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args();root=args.output;root.mkdir(mode=0o700);hash_value=hashed()
    for argv in (['ip','link','set','lo','up'],['ip','link','add','wan09','type','dummy'],['ip','addr','add','198.18.9.1/24','dev','wan09'],['ip','link','set','wan09','up'],['ip','route','add','default','dev','wan09']):subprocess.run(argv,check=True,capture_output=True)
    result=dict(status='RUNNING',cases=[])
    try:
        for label,binary,fixed in [('baseline',args.baseline.resolve(),False),('fixed',args.fixed.resolve(),True)]:
            for quic in (False,True):
                for name,fun in [('auth',lambda p:auth_case(binary,p,hash_value,quic,fixed,False)),('deadline',lambda p:auth_case(binary,p,hash_value,quic,fixed,True)),('direction',lambda p:direction_case(binary,p,hash_value,quic,fixed))]:
                    case_id=label+'-'+('quic' if quic else 'udp')+'-'+name
                    checks=fun(root/case_id);result['cases'].append(dict(id=case_id,status='PASS',checks=checks));print('PASS',case_id,len(checks),flush=True)
        for quic in (False,True):
            for kind in ('password','user','proof'):
                case_id='fixed-'+('quic' if quic else 'udp')+'-'+kind
                checks=negative_case(args.fixed.resolve(),root/case_id,hash_value,quic,kind);result['cases'].append(dict(id=case_id,status='PASS',checks=checks));print('PASS',case_id,len(checks),flush=True)
        result['checks_passed']=sum(len(c['checks']) for c in result['cases']);result['status']='PASS'
    except BaseException:result['status']='FAIL';raise
    finally:(root/'result.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
