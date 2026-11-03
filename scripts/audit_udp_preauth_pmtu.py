#!/usr/bin/env python3
"""Reproduce half-open UDP PMTU replies against baseline and fixed Linux binaries.
Run only through a lab runner that verifies fresh NET/mount/PID namespaces.
A UDP proxy forwards real Qeli ClientHello fragments but withholds ServerHello,
so the server has a half-open session and never receives AUTH.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


def case(binary, root, quic, expect_reply):
    root.mkdir(mode=0o700)
    state = root / 'state'
    state.mkdir(mode=0o700)
    env = dict(os.environ, STATE_DIRECTORY=str(state), QELI_CONTROL_SOCKET=str(root / 'control.sock'))
    server = client = None
    rows = []
    endpoint = ('127.0.0.1', 24943)
    cfg = root / 'server.ini'
    cfg.write_text(f"""[auth]
users_file = {root}/users.ini
require_client_key_proof = false
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:preauth]
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
perf.connection.handshake_timeout_secs = 20
""", encoding='utf8')
    (root / 'users.ini').write_text('', encoding='utf8')
    cfg.chmod(0o600)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as proxy, (root / 'server.log').open('w') as sl, (root / 'client.log').open('w') as cl:
        proxy.bind(('127.0.0.1', 0))
        proxy.setblocking(False)
        server = subprocess.Popen([str(binary), 'server', '-c', str(cfg)], env=env, stdout=sl, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                assert server.poll() is None, 'server exited'
                if ':24943' in subprocess.check_output(['ss', '-lnu'], text=True):
                    break
                time.sleep(.1)
            else:
                raise AssertionError('server listener missing')
            cc = root / 'client.ini'
            cc.write_text(f'[qeli]\nserver=127.0.0.1:{proxy.getsockname()[1]}\nproto=udp\nuser=unused\npass=unused\nmode=fake-tls\nbind_static=false\nquic={str(quic).lower()}\ndev=q09cli\ngateway=false\ndns=off\nkill_switch=false\ntimeout=10\n[logging]\nlevel=info\n', encoding='utf8')
            cc.chmod(0o600)
            client = subprocess.Popen([str(binary), 'client', '-c', str(cc)], env=env, stdout=cl, stderr=subprocess.STDOUT, start_new_session=True)
            hello = None
            forwarded = 0
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not select.select([proxy], [], [], .1)[0]:
                    continue
                packet, peer = proxy.recvfrom(65535)
                if peer == endpoint:
                    hello = packet
                    break
                forwarded += 1
                proxy.sendto(packet, endpoint)
            assert hello is not None and forwarded > 0, 'real ClientHello did not create a half-open session'
            cid = hello[6:10] if quic else b''
            assert (hello[0] == 0xC3 and len(cid) == 4) if quic else hello[:4] == b'\xf0\x9b\x71\x02'
            rows.append('real fragmented PQ ClientHello created AwaitingAuth')
            stop(client)
            client = None
            # Withhold every ServerHello; no client can decrypt it or emit AUTH.
            while select.select([proxy], [], [], .15)[0]:
                proxy.recvfrom(65535)
            magic = b'\xf0\x9b\x71'
            for version in (1, 2):
                size = 1200 if version == 1 else 1400
                body = struct.pack('<HH', 0xBEEF, size) if version == 1 else bytes(range(16)) + struct.pack('<H', size)
                request = magic + bytes([4 if version == 1 else 7, 0, 1]) + body
                request += b'\0' * (size - len(request))
                wire = b'\x43' + cid + struct.pack('>I', version + 20) + request if quic else request
                proxy.sendto(wire, endpoint)
                expected = magic + bytes([5 if version == 1 else 8, 0, 1]) + body
                received = []
                deadline = time.monotonic() + .6
                while time.monotonic() < deadline:
                    if select.select([proxy], [], [], .05)[0]:
                        packet, peer = proxy.recvfrom(65535)
                        assert peer == endpoint
                        received.append(packet[9:] if quic else packet)
                assert received == ([expected] if expect_reply else []), (version, expect_reply, [p.hex() for p in received])
                rows.append(f'PMTU V{version}: ' + ('baseline bug reproduced' if expect_reply else 'no pre-auth ACK'))
            assert 'AUTH attempt UDP' not in (root / 'server.log').read_text(encoding='utf8'), 'unexpected AUTH invalidates the half-open test'
            rows.append('no AUTH reached server')
            return rows
        finally:
            stop(client)
            stop(server)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--fixed', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    result = {'cases': [], 'status': 'RUNNING'}
    try:
        for argv in (['ip', 'link', 'set', 'lo', 'up'], ['ip', 'link', 'add', 'wan09', 'type', 'dummy'], ['ip', 'link', 'set', 'wan09', 'up'], ['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'wan09'], ['ip', 'route', 'add', 'default', 'dev', 'wan09']):
            subprocess.run(argv, check=True, capture_output=True)
        for label, binary, expect in [('baseline', args.baseline, True), ('fixed', args.fixed, False)]:
            for quic in (False, True):
                name = label + ('-quic' if quic else '-udp')
                checks = case(binary.resolve(), args.output / name, quic, expect)
                result['cases'].append({'id': name, 'status': 'PASS', 'checks': checks})
                print('PASS', name, len(checks), flush=True)
        result['status'] = 'PASS'
        result['checks_passed'] = sum(len(row['checks']) for row in result['cases'])
    finally:
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print('PASS old/new UDP+QUIC regression:', result['checks_passed'], flush=True)


if __name__ == '__main__':
    main()
