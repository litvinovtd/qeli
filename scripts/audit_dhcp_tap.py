#!/usr/bin/env python3
"""Exercise the real profile DHCP socket through a private multiqueue TAP.

Run only via audit_release_matrix_lab.ISOLATED. An additional kernel TAP queue
injects Ethernet requests; AF_PACKET observes actual UDP replies. No VPN session
or lease table is injected. This qualifies the DHCP service, not client AUTH.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time


def checksum(data):
    if len(data) & 1: data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16: total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def options(data):
    found = {}; pos = 240
    assert data[236:240] == bytes([99, 130, 83, 99])
    while pos < len(data):
        code = data[pos]
        if code == 255: return found
        if code == 0: pos += 1; continue
        assert pos + 2 <= len(data)
        size = data[pos + 1]; end = pos + 2 + size
        assert end <= len(data)
        found[code] = data[pos + 2:end]; pos = end
    raise AssertionError('reply missing END')


def main(args):
    for kind in ('net', 'mnt', 'pid'):
        assert os.readlink('/proc/self/ns/' + kind) != getattr(args, 'parent_' + kind)
    binary = Path(args.qeli).resolve(strict=True)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256
    root = Path(args.artifacts); root.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = []; packets = []; server = None; tap = None; capture = None
    def run(argv):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        assert p.returncode == 0, (argv, p.stdout, p.stderr)
        return p.stdout
    def check(name, passed, detail=None):
        checks.append(dict(name=name, passed=bool(passed), detail=detail))
        (root/'checks.json').write_text(json.dumps(checks, indent=2)+'\n')
        print(('PASS ' if passed else 'FAIL ') + name, flush=True)
        assert passed, (name, detail)
    try:
        run(['ip', 'link', 'set', 'lo', 'up'])
        users = root/'users.conf'; users.write_text(''); users.chmod(0o600)
        cfg = root/'server.conf'
        cfg.write_text(f'''[auth]
users_file = {users}
[web]
enabled = false
[logging]
level = debug
[profile:dhcp]
identity_key = {root}/identity.key
bind.address = 127.0.0.1
bind.port = 26443
bind.transport = tcp
tun.name = qdhcp0
tun.device_type = tap
tun.address = 10.91.0.1
tun.queues = 1
pool.cidr = 10.91.0.0/24
routing.nat.enabled = false
routing.ipv6.mode = off
dns.enabled = false
dns.push_servers = 10.91.0.3, 10.91.0.4
dhcp.enabled = true
dhcp.pool_start = 10.91.0.100
dhcp.pool_end = 10.91.0.102
dhcp.lease_time_secs = 8
dhcp.domain_name = qeli.test
obf.mode = fake-tls
'''); cfg.chmod(0o600)
        # Exercise the actual INI/check-config boundary as well as the wire encoder.
        for count, enabled, expected in [(63, True, 0), (64, True, 1), (64, False, 0)]:
            admission = root/f'admission-{count}-{enabled}.conf'
            text = cfg.read_text().replace('dns.push_servers = 10.91.0.3, 10.91.0.4',
                                          'dns.push_servers = '+', '.join(f'10.91.0.{n}' for n in range(1,count+1)))
            if not enabled: text = text.replace('dhcp.enabled = true', 'dhcp.enabled = false')
            admission.write_text(text); admission.chmod(0o600)
            result = subprocess.run([str(binary),'check-config','-c',str(admission)],capture_output=True,text=True,timeout=30)
            (root/(admission.stem+'.log')).write_text(result.stdout+result.stderr)
            check(f'INI admission DNS count={count} DHCP={enabled}',
                  (result.returncode == 0 if expected == 0 else result.returncode != 0 and 'at most 63' in result.stdout+result.stderr))
        with (root/'server.log').open('w') as log:
            server = subprocess.Popen([str(binary), 'server', '-c', str(cfg)], stdout=log, stderr=subprocess.STDOUT)
        end = time.monotonic() + 30
        while 'DHCP server bound' not in (root/'server.log').read_text():
            assert time.monotonic() < end and server.poll() is None
            time.sleep(.1)
        links = json.loads(run(['ip', '-d', '-j', 'link', 'show', 'dev', 'qdhcp0'])); sockets = run(['ss', '-lnu']); check('real worker owns TAP and DHCP UDP/67', links[0]['linkinfo']['info_data']['type'] == 'tap' and ':67' in sockets, dict(links=links,sockets=sockets))
        tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH22x', b'qdhcp0', 0x0002 | 0x1000 | 0x0100))
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); capture.bind(('qdhcp0', 0))
        xid = 0x71200000
        def request(kind, mac, extra=b'', ciaddr='0.0.0.0', raw=None, header=None, overload=None, expected=None, label='', wait=.15, keep_xid=False):
            nonlocal xid
            if not keep_xid: xid += 1
            payload = bytearray(240); payload[:3] = bytes([1, 1, 6]); payload[4:8] = xid.to_bytes(4, 'big')
            payload[10:12] = b'\x80\0'; payload[12:16] = ipaddress.IPv4Address(ciaddr).packed; payload[28:34] = mac
            payload[236:240] = bytes([99, 130, 83, 99])
            if header:
                for offset, value in header: payload[offset] = value
            if overload: payload[108:108+len(overload)] = overload
            payload.extend(raw if raw is not None else bytes([53, 1, kind]) + extra + b'\xff')
            udp = struct.pack('!HHHH', 68, 67, 8+len(payload), 0) + payload
            ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(udp), 1, 0, 64, 17, 0, b'\0'*4, b'\xff'*4))
            ip[10:12] = checksum(ip).to_bytes(2, 'big')
            frame = b'\xff'*6 + mac + b'\x08\x00' + ip + udp
            os.write(tap, frame)
            replies = []; deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                capture.settimeout(max(.001, deadline-time.monotonic()))
                try: reply = capture.recv(65535)
                except socket.timeout: break
                if len(reply) < 14+20+8+240 or reply[12:14] != b'\x08\x00' or reply[23] != 17: continue
                ihl = (reply[14] & 15) * 4; offset = 14+ihl
                if reply[offset:offset+4] != struct.pack('!HH', 67, 68): continue
                bootp = reply[offset+8:]
                if bootp[0] != 2 or bootp[4:8] != payload[4:8]: continue
                opt = options(bootp); replies.append(dict(type=opt[53][0], ip=str(ipaddress.IPv4Address(bootp[16:20])), options={str(k):v.hex() for k,v in opt.items()}, hex=reply.hex()))
            packets.append(dict(label=label, xid=xid, request=frame.hex(), replies=replies))
            (root/'packets.json').write_text(json.dumps(packets, indent=2)+'\n')
            check(label, [r['type'] for r in replies] == ([] if expected is None else [expected]), replies)
            return replies[0] if replies else None
        def addr(code, address): return bytes([code, 4]) + ipaddress.IPv4Address(address).packed
        macs = [bytes([2, 0x54, 0, 0x12, 0, suffix]) for suffix in range(1, 9)]
        malformed = [(b'\x35\x02\x01\0\xff', None), (bytes([53,1,1,50,3,10,91,0,255]), None), (bytes([53,1,1,53,1,3,255]), None), (bytes([53,1,1,200,10,1]), None), (bytes([53,1,1,255]), [(2,16)]), (bytes([53,1,1,255]), [(1,2)])]
        for index, (raw, header) in enumerate(malformed): request(1, macs[5], raw=raw, header=header, label=f'malformed request {index} is silent')
        request(1, macs[5], raw=bytes([53,1,1])+b'\0'*1600+bytes([200,10,1]), label='malformed tail beyond old 1500-byte receive buffer is rejected')
        offer = request(1, macs[0], expected=2, label='DISCOVER broadcast from 0.0.0.0 receives OFFER')
        chosen = offer['ip']; check('OFFER contains DNS, mask, gateway, domain and timers', offer['options']['6'] == '0a5b00030a5b0004' and offer['options']['15'] == b'qeli.test'.hex() and all(str(c) in offer['options'] for c in (1, 3, 51, 58, 59, 54)))
        repeat = request(1, macs[0], expected=2, label='duplicate xid and MAC receives OFFER', keep_xid=True); check('repeated MAC retains exact offered address', repeat['ip'] == chosen)
        ack = request(3, macs[0], addr(50, chosen)+addr(54, '10.91.0.1'), expected=5, label='REQUEST selecting our server receives ACK')
        check('ACK commits exact offered address', ack['ip'] == chosen)
        request(3, macs[0], ciaddr=chosen, expected=5, label='ciaddr renewal receives ACK')
        request(3, macs[1], addr(50, chosen), expected=6, label='occupied exact REQUEST receives NAK')
        request(3, macs[1], addr(50, '192.0.2.1'), expected=6, label='out-of-pool REQUEST receives NAK')
        request(3, macs[1], addr(50, '10.91.0.101')+addr(54, '10.91.0.99'), label='selection of another server is silent')
        # Wrong MAC cannot release an owner's reservation; owner can.
        request(7, macs[1], ciaddr=chosen, label='foreign MAC RELEASE is silent')
        request(3, macs[1], addr(50, chosen), expected=6, label='foreign RELEASE did not free the address')
        request(7, macs[0], ciaddr=chosen, label='owner RELEASE is silent')
        request(3, macs[1], addr(50, chosen), expected=5, label='released address can be requested by next owner')
        request(4, macs[1], addr(50, chosen), label='owner DECLINE is silent')
        request(3, macs[2], addr(50, chosen), expected=6, label='declined address is quarantined')
        for suffix in (2, 3):
            offered = request(1, macs[suffix], expected=2, label=f'available pool slot {suffix}')
            if suffix == 2: request(3, macs[suffix], addr(50, offered['ip']), expected=5, label='second slot commits a short lease')
        request(1, macs[4], label='exhausted pool is silent')
        time.sleep(9)
        request(1, macs[4], expected=2, label='expired committed lease frees a pool slot')
        # Sixty silent requests for another server consume this MAC's bucket without
        # changing the pool. The 61st request is dropped; a different full MAC must work.
        for index in range(60):
            request(3, macs[7], addr(54, '10.91.0.99'), label=f'rate primer {index}', wait=0)
        time.sleep(.1)
        request(3, macs[7], addr(50, chosen), label='61st request from limited MAC is silent')
        # Reuse a quarantined exact request to check overloaded option 50 parsing.
        request(3, macs[6], extra=bytes([52,1,1]), overload=addr(50, chosen)+b'\xff', expected=6, label='option 50 in overloaded file field is parsed')
        capture.close();capture=None;os.close(tap);tap=None
        server.send_signal(signal.SIGTERM); server.wait(timeout=30);server=None
        check('profile stop removes TAP and DHCP listener', subprocess.run(['ip','link','show','qdhcp0'],capture_output=True).returncode != 0 and ':67' not in run(['ss','-lnu']))
        result = dict(status='PASS', artifact_sha256=args.sha256, checks_passed=len(checks), checks_failed=0, scope='Real worker DHCP socket and TAP ingress; not VPN client AUTH or platform DHCP daemon')
        (root/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    finally:
        if capture is not None: capture.close()
        if tap is not None: os.close(tap)
        if server is not None and server.poll() is None:
            server.send_signal(signal.SIGTERM)
            try: server.wait(timeout=30)
            except subprocess.TimeoutExpired: server.kill();server.wait(timeout=10)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('qeli','sha256','artifacts','parent-net','parent-mnt','parent-pid'): parser.add_argument('--'+name, required=True)
    main(parser.parse_args())
