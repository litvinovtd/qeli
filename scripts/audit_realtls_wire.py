#!/usr/bin/env python3
"""Inspect an owned REALITY/TLS capture; optionally replay its accepted ClientHello.

This fixture requires a private network namespace and lab endpoints. It does not
claim public-site JA4 equality or resistance to a DPI vendor's active probes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import time


def streams(path):
    capture = path.read_bytes()
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}[capture[:4]]
    assert len(capture) >= 24 and struct.unpack(endian + 'I', capture[20:24])[0] == 1
    flows = {}; offset = 24; packets = 0
    while offset + 16 <= len(capture):
        size = struct.unpack(endian + 'I', capture[offset + 8:offset + 12])[0]
        offset += 16
        if size > len(capture) - offset: break  # live capture may have a partial last write
        frame = capture[offset:offset + size]; offset += size; packets += 1
        if len(frame) < 54 or frame[12:14] != b'\x08\x00': continue
        ip = frame[14:]; ihl = (ip[0] & 15) * 4
        if ip[0] >> 4 != 4 or ip[9] != 6 or len(ip) < ihl + 20: continue
        tcp = ip[ihl:struct.unpack('!H', ip[2:4])[0]]; thl = (tcp[12] >> 4) * 4
        if len(tcp) < thl or len(tcp) == thl: continue
        source, dest, seq = struct.unpack('!HHI', tcp[:8])
        if 4443 not in (source, dest): continue
        key = (socket.inet_ntoa(ip[12:16]), source, socket.inet_ntoa(ip[16:20]), dest)
        entry = flows.setdefault(key, [seq, {}]); relative = (seq - entry[0]) & 0xffffffff
        if relative > 16 * 1024 * 1024: continue  # old duplicate before the observed prefix
        entry[1][relative] = tcp[thl:]
    result = {}
    for key, (_, chunks) in flows.items():
        joined = bytearray()
        for position, chunk in sorted(chunks.items()):
            if position > len(joined): break
            end = position + len(chunk)
            if end > len(joined): joined.extend(chunk[len(joined) - position:])
        records = []; offset = 0
        while offset + 5 <= len(joined):
            total = 5 + int.from_bytes(joined[offset + 3:offset + 5], 'big')
            if total > len(joined) - offset: break
            records.append(bytes(joined[offset:offset + total])); offset += total
        result[key] = records
    return result, packets


def server_hello(record):
    assert record[0] == 0x16 and record[5] == 2
    msg = record[5:]; assert int.from_bytes(msg[1:4], 'big') == len(msg) - 4
    assert msg[4:6] == b'\x03\x03'
    sid = msg[38]; offset = 39 + sid
    cipher = int.from_bytes(msg[offset:offset + 2], 'big'); assert cipher in (0x1301, 0x1302)
    assert msg[offset + 2] == 0
    offset += 3; length = int.from_bytes(msg[offset:offset + 2], 'big'); offset += 2
    assert offset + length == len(msg)
    extensions = {}
    while offset < len(msg):
        kind = int.from_bytes(msg[offset:offset + 2], 'big'); size = int.from_bytes(msg[offset + 2:offset + 4], 'big'); offset += 4
        assert offset + size <= len(msg) and kind not in extensions
        extensions[kind] = msg[offset:offset + size]; offset += size
    assert extensions[0x2b] == b'\x03\x04'
    share = extensions[0x33]; group = int.from_bytes(share[:2], 'big')
    assert len(share) - 4 == int.from_bytes(share[2:4], 'big') == {0x1d: 32, 0x11ec: 1120}[group]
    return {'cipher': hex(cipher), 'group': hex(group), 'extensions': [hex(k) for k in extensions]}


def probe(capture, log):
    flows, _ = streams(capture)
    before = log.read_text(errors='replace')
    peers = re.findall(r'Qeli client detected from ([0-9.]+):(\d+)', before)
    hello = next(records[0] for (ip, port, _, destination), records in flows.items()
                 if destination == 4443 and records and (ip, str(port)) in peers
                 and records[0][0] == 0x16 and records[0][5] == 1)
    assert hello[43] == 32
    corrupt = bytearray(hello); corrupt[44] ^= 1
    for record in (hello, corrupt):
        with socket.create_connection(('10.40.3.2', 4443), timeout=3) as stream:
            stream.sendall(record); response = stream.recv(4096)
            assert response and response[0] == 0x16, 'probe must reach the private TLS cover target'
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        after = log.read_text(errors='replace')
        if 'replayed session_id' in after[len(before):]: break
        time.sleep(0.05)
    else: raise AssertionError('captured accepted token was not classified as replay')
    assert after.count('Qeli client detected') == before.count('Qeli client detected')
    return {'replay_bridged': True, 'tampered_token_bridged': True, 'accepted_client_count_unchanged': True,
            'client_hello_sha256': hashlib.sha256(hello).hexdigest()}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('capture', type=Path)
    parser.add_argument('--probe-log', type=Path); args = parser.parse_args()
    if args.probe_log: result = probe(args.capture, args.probe_log)
    else:
        flows, packets = streams(args.capture)
        replies = []
        for (_, source, _, _), records in flows.items():
            if source != 4443: continue
            hellos = [record for record in records if record[0] == 0x16 and record[5:6] == b'\x02']
            if hellos:
                info = server_hello(hellos[0]); assert any(record[0] == 0x17 for record in records)
                info['encrypted_records'] = sum(record[0] == 0x17 for record in records); replies.append(info)
        assert len(replies) >= 2, 'capture must include cover probe and authenticated Qeli TLS traffic'
        result = {'packets': packets, 'server_hellos': replies, 'capture_sha256': hashlib.sha256(args.capture.read_bytes()).hexdigest(),
                  'scope': 'private TLS 1.3 wire structure; no public fingerprint or DPI certification'}
    print(json.dumps({'status': 'PASS', **result}, indent=2))


if __name__ == '__main__': main()
