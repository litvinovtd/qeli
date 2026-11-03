#!/usr/bin/env python3
"""Qualify the shipped Windows C ABI without opening Wintun or changing OS routes."""
import argparse, ctypes as c, hashlib, json, socket, struct, threading, time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    library = args.library.resolve()
    dll = c.CDLL(str(library))
    checks, handles = [], set()
    completed = False
    u64, size, ptr = c.c_uint64, c.c_size_t, c.c_void_p
    signatures = {
        'abi_version': (c.c_uint32, []), 'core_capabilities': (u64, []),
        'new': (c.c_int, [c.c_char_p, size, u64, c.c_uint32, c.POINTER(u64)]),
        'start': (c.c_int, [u64]), 'stop': (c.c_int, [u64]), 'free': (c.c_int, [u64]),
        'state': (c.c_int, [u64, c.POINTER(c.c_uint32)]),
        'stats': (c.c_int, [u64, ptr]), 'set_device_id': (c.c_int, [u64, c.c_char_p, size]),
        'poll_event': (c.c_int, [u64, ptr, ptr, size, c.POINTER(size)]),
        'publish_handshake_network': (c.c_int, [u64, c.c_char_p, size, c.POINTER(u64)]),
        'network_plan_result': (c.c_int, [u64, u64, c.c_int, c.c_char_p, size]),
        'tun_push': (c.c_int, [u64, u64, c.c_char_p, size, ptr, size, c.POINTER(size)]),
        'tun_pull': (c.c_int, [u64, u64, ptr, size, ptr, size, c.POINTER(size), c.POINTER(size)]),
        'run': (c.c_int, [u64, c.c_char_p, size]),
    }
    functions = {}
    for name, (restype, argtypes) in signatures.items():
        fn = getattr(dll, 'qeli_client_'+name); fn.restype = restype; fn.argtypes = argtypes; functions[name] = fn
    def check(label, condition):
        checks.append({'check': label, 'passed': bool(condition)})
        assert condition, label
    def config(port=443):
        return ('[qeli]\nserver = 127.0.0.1:'+str(port)+'\nproto = tcp\nuser = test\npass = fixture-only\nkey = '+'11'*32+'\nmode = fake-tls\ngateway = false\n').encode()
    def create(caps=7, port=443):
        data = config(port); h = u64()
        assert functions['new'](data, len(data), caps, 0, c.byref(h)) == 0 and h.value
        handles.add(h.value); return h.value
    def state(h):
        value = c.c_uint32(99); rc = functions['state'](h, c.byref(value)); return rc, value.value
    def poll(h):
        header = (c.c_ubyte*56)(*([0xa5]*56)); struct.pack_into('<I', header, 0, 56); needed = size()
        rc = functions['poll_event'](h, header, None, 0, c.byref(needed))
        if rc == 1: return None
        assert rc in (0,-6)
        sequence = struct.unpack_from('<Q', header, 24)[0]
        payload = b''
        if rc == -6:
            output = (c.c_ubyte*needed.value)()
            assert functions['poll_event'](h, header, output, len(output), c.byref(needed)) == 0
            assert struct.unpack_from('<Q', header, 24)[0] == sequence
            payload = bytes(output[:needed.value])
        assert bytes(header[48:]) == bytes([0xa5])*8
        assert struct.unpack_from('<I', header, 0)[0] == 56
        return struct.unpack_from('<I', header, 8)[0], sequence, payload
    def drain(h):
        events = []
        for _ in range(256):
            event = poll(h)
            if event is None: return events
            events.append(event)
        raise AssertionError('event queue did not quiesce')
    try:
        check('ABI 1.16 and declared capabilities', functions['abi_version']() == 0x10010 and functions['core_capabilities']() & 0x100)
        out = u64(99)
        check('null configuration rejected before allocation', functions['new'](None, 1, 7, 0, c.byref(out)) == -1)
        check('invalid UTF8 returns no handle', functions['new'](b'\xff', 1, 7, 0, c.byref(out)) == -2 and out.value == 0)
        h = create(7 | (1<<4)); check('Created state', state(h) == (0,0))
        check('device identity requires sixteen nonzero bytes', functions['set_device_id'](h, b'\0'*16, 16) == -1 and functions['set_device_id'](h, b'\1'*16, 16) == 0)
        check('start transitions once', functions['start'](h) == 0 and functions['start'](h) == -3)
        auth = {'client_ip':'10.8.0.2','server_ip':'10.8.0.1','prefix':24,'mtu':1400,'dns':'10.8.0.1','dns_port':53,'routes':[]}
        envelope = json.dumps({'auth_ok':'OK:'+json.dumps(auth),'effective_mtu':1400}).encode(); generation = u64()
        check('publish copies plan and enters AwaitingNetwork', functions['publish_handshake_network'](h,envelope,len(envelope),c.byref(generation)) == 0 and state(h) == (0,2))
        events = drain(h); plans = [json.loads(e[2]) for e in events if e[0] == 2]
        check('buffer size probe preserves plan and future event tail', len(plans) == 1 and plans[0]['generation'] == generation.value and plans[0]['tunnel_address'] == '10.8.0.2')
        check('stale generation cannot accept network', functions['network_plan_result'](h,generation.value+1,0,None,0) == -4 and state(h) == (0,2))
        check('positive ACK enters Running', functions['network_plan_result'](h,generation.value,0,None,0) == 0 and state(h) == (0,3))
        stats = (c.c_ubyte*160)(*([0xa5]*160)); struct.pack_into('<I',stats,0,64)
        check('old stats prefix and caller tail preserved', functions['stats'](h,stats) == 0 and struct.unpack_from('<I',stats,0)[0] == 64 and bytes(stats[64:]) == bytes([0xa5])*96)
        lengths = (c.c_uint32*64)(*([20]*64)); accepted = size(); packet = bytes([0x45])+bytes(19)
        check('malformed batch has no partial acceptance', functions['tun_push'](h,generation.value,b'123',3,lengths,64,c.byref(accepted)) == -1 and accepted.value == 0)
        for _ in range(4): assert functions['tun_push'](h,generation.value,packet*64,1280,lengths,64,c.byref(accepted)) == 0 and accepted.value == 64
        check('fixed packet pool applies backpressure', functions['tun_push'](h,generation.value,packet*64,1280,lengths,64,c.byref(accepted)) == 1 and accepted.value == 0)
        storage = (c.c_ubyte*65535)(); count, used = size(), size()
        check('empty downlink reports zero bytes', functions['tun_pull'](h,generation.value,storage,len(storage),lengths,64,c.byref(count),c.byref(used)) == 1 and count.value == used.value == 0)
        check('stop terminates generation', functions['stop'](h) == 0 and state(h) == (0,5))
        check('stopped bridge is unavailable', functions['tun_push'](h,generation.value,packet,20,lengths,1,c.byref(accepted)) == -3)
        check('free and stale handle refuse reuse', functions['free'](h) == 0 and functions['free'](h) == -7 and state(h)[0] == -7); handles.remove(h)
        prior = h
        for _ in range(100):
            h = create(); assert h != prior; assert functions['free'](h) == 0; handles.remove(h); assert state(prior)[0] == -7; prior = h
        check('100 registry reuse cycles preserve stale-handle isolation', True)
        h = create(); barrier = threading.Barrier(8); outcomes = []
        def dispose():
            barrier.wait(); outcomes.append(functions['free'](h))
        threads = [threading.Thread(target=dispose) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(3); assert not t.is_alive()
        check('eight concurrent frees destroy one generation exactly once', outcomes.count(0) == 1 and outcomes.count(-7) == 7); handles.remove(h)
        # A localhost listener stalls the real native handshake; no platform/TUN ACK is issued.
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); listener.listen(); listener.settimeout(10)
            h = create(port=listener.getsockname()[1]); assert functions['set_device_id'](h,b'\1'*16,16) == 0; assert functions['start'](h) == 0
            result = []; runtime_input = b'{"carrier_addresses":["127.0.0.1"]}'
            worker = threading.Thread(target=lambda: result.append(functions['run'](h,runtime_input,len(runtime_input)))); worker.start()
            with listener.accept()[0]:
                check('second native runner cannot enter an active generation', functions['run'](h,runtime_input,len(runtime_input)) == -10)
                start = time.monotonic(); check('free invalidates public handle while runner is leased', functions['free'](h) == 0 and state(h)[0] == -7); handles.remove(h)
                worker.join(3); check('free cancels and joins pending native handshake', not worker.is_alive() and result == [0] and time.monotonic()-start < 3)
        completed = True
    finally:
        for h in handles: functions['free'](h)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps({'status':'PASS' if completed and checks and all(x['passed'] for x in checks) else 'FAIL','library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),'checks':checks,'scope':'Windows packaged C ABI and real localhost handshake cancellation; no Wintun or OS network mutation.'},indent=2)+'\n')
    print('PASS',len(checks),'Windows ABI/control/runner checks')


if __name__ == '__main__':
    main()
