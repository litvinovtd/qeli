#!/usr/bin/env python3
"""Bounded private-netns UDP echo probe; reports counts, never session material."""
import argparse
import json
import selectors
import socket
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('mode', choices=('server', 'probe', 'flood-probe'))
p.add_argument('--seconds', type=float, default=10)
p.add_argument('--reverse', action='store_true')
a = p.parse_args()
echo_ip, probe_ip = ('10.88.0.2', '10.88.0.1') if a.reverse else ('10.88.0.1', '10.88.0.2')
if not 1 <= a.seconds <= 30:
    p.error('seconds must be 1..30')
sel = selectors.DefaultSelector()
sockets = []
for i in range(16):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    s.bind((echo_ip, 5600+i) if a.mode == 'server' else (probe_ip, 34000+i))
    sel.register(s, selectors.EVENT_READ, i)
    sockets.append(s)
start = time.monotonic()
if a.mode == 'server':
    while time.monotonic()-start < a.seconds:
        for key, _ in sel.select(.01):
            try:
                data, peer = key.fileobj.recvfrom(2048)
                key.fileobj.sendto(data, peer)
            except (BlockingIOError, OSError):
                pass
    raise SystemExit(0)
flood = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
flood.setblocking(False)
flood.bind((probe_ip, 35000))
counts = [0]*int(a.seconds+1)
flows = set()
sent = 0
next_probe = next_flood = start
while time.monotonic()-start < a.seconds:
    now = time.monotonic()
    if now >= next_probe:
        for i, s in enumerate(sockets):
            try:
                s.sendto(b'q24-probe-'+bytes([i]), (echo_ip, 5600+i))
                sent += 1
            except (BlockingIOError, OSError):
                pass
        next_probe = now+.1
    if a.mode == 'flood-probe' and now >= next_flood:
        # 80 datagrams/10ms: at most ~90 Mbps and 10 seconds; no unbounded loop.
        for i in range(80):
            try:
                flood.sendto(b'x'*1400, (echo_ip, 6000+(sent+i)%256))
            except (BlockingIOError, OSError):
                pass
        next_flood = now+.01
    for key, _ in sel.select(.001):
        try:
            data, peer = key.fileobj.recvfrom(2048)
            if peer == (echo_ip, 5600+key.data) and data == b'q24-probe-'+bytes([key.data]):
                counts[min(int(time.monotonic()-start), len(counts)-1)] += 1
                flows.add(key.data)
        except (BlockingIOError, OSError):
            pass
print(json.dumps({'mode':a.mode, 'seconds':a.seconds, 'sent':sent, 'received':sum(counts),
                  'received_per_second':counts, 'distinct_echo_flows':len(flows),
                  'last_half_received':sum(counts[int(a.seconds/2):])}))
