#!/usr/bin/env python3
"""Bounded loopback AUTH bursts; run inside private NET/mount namespaces only.

Three fresh servers per transport/concurrency. Server and peers share a two-vCPU
VM; the resulting finite-burst rate is not network or sustained server capacity.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from audit_udp_handshake_contracts import control, stop, wait_for
from benchmark_auth import admit_burst


def password_hash():
    # Same PHC work factors as crypto::password_hasher(), not the old 8-MiB fixture.
    lib = ctypes.CDLL('libargon2.so.1')
    function = lib.argon2id_hash_encoded
    function.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
    function.restype = ctypes.c_int
    output = ctypes.create_string_buffer(256)
    password, salt = b'fixture-password', b'q36-auth-fixture'
    if function(2, 19456, 1, password, len(password), salt, len(salt), 32, output, len(output)):
        raise RuntimeError('fixture password hashing failed')
    result = output.value.decode()
    if not result.startswith('$argon2id$v=19$m=19456,t=2,p=1$'):
        raise RuntimeError('unexpected PHC work factors')
    return result


def process_sample(pid):
    proc = Path('/proc') / str(pid)
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    status = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines())
    host = [int(value) for value in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
    return dict(monotonic_ns=time.monotonic_ns(), ticks=int(fields[11]) + int(fields[12]),
        start=fields[19], rss_kib=int(status['VmRSS'].split()[0]),
        cpu_affinity=status['Cpus_allowed_list'].strip(), nice=int(fields[16]),
        host_load=[float(value) for value in Path('/proc/loadavg').read_text().split()[:3]],
        host_total=sum(host), host_steal=host[7])


def scenario(binary, peer, root, transport, concurrency, repeat):
    root.mkdir(mode=0o700)
    (root / 'state').mkdir(mode=0o700)
    barrier = root / 'barrier'; barrier.mkdir(mode=0o700)
    config = f'''[auth]
users_file = {root}/users.ini
require_client_key_proof = true
bind_static_to_session = false
[web]
enabled = false
[logging]
level = info
[profile:auth-contracts]
identity_key = {root}/identity.key
bind.address = 127.0.0.1
bind.port = 24943
bind.transport = {'tcp' if transport == 'tcp' else 'udp'}
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
password_hash = {password_hash()}
enabled = true
max_sessions = 0
'''
    (root / 'server.ini').write_text(config)
    (root / 'server.ini').chmod(0o600)
    (root / 'users.ini').write_text('')
    env = dict(os.environ, STATE_DIRECTORY=str(root / 'state'), QELI_CONTROL_SOCKET=str(root / 'control.sock'))
    peers, streams, server, sampler = [], [], None, None
    finished = threading.Event()
    samples = []
    errors = []
    row = dict(status='RUNNING', transport=transport, concurrency=concurrency, repeat=repeat, peers=[])
    def save(): (root / 'result.json').write_text(json.dumps(row, indent=2, allow_nan=False) + '\n')
    def sample():
        try:
            while not finished.wait(.05): samples.append(process_sample(server.pid))
        except Exception as error: errors.append(str(error))
    try:
        log = (root / 'server.log').open('w'); streams.append(log)
        # _worker avoids a supervisor PID in the measured server process counters.
        server = subprocess.Popen([binary, '_worker', '-c', str(root / 'server.ini')], env=env,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        wait_for(lambda: (root / 'control.sock').exists() and (root / 'identity.key').exists(), 12)
        if control(root, 'list-clients')['clients']: raise RuntimeError('server not fresh')
        for index in range(concurrency):
            out = (root / f'peer-{index}.json').open('w'); err = (root / f'peer-{index}.stderr').open('w')
            streams.extend([out, err])
            peers.append(subprocess.Popen([peer, transport, '127.0.0.1:24943', str(root / 'identity.key'), 'valid'],
                env=dict(env, QELI_AUTH_BARRIER=str(barrier)), stdout=out, stderr=err, start_new_session=True))
        row['pids'] = dict(server=server.pid, peers=[process.pid for process in peers]); save()
        def ready():
            if any(process.poll() is not None for process in peers): raise RuntimeError('peer exited before release')
            return {path.name for path in barrier.glob('ready-*')} == {f'ready-{process.pid}' for process in peers}
        wait_for(ready, 12)
        samples.append(process_sample(server.pid))
        sampler = threading.Thread(target=sample); sampler.start()
        (barrier / 'go').write_text('release prepared peers')
        def complete():
            if server.poll() is not None or any(process.poll() is not None for process in peers):
                raise RuntimeError('fixture process exited during admission')
            return all((root / f'peer-{index}.json').read_text().endswith('\n') for index in range(concurrency))
        wait_for(complete, 12)
        samples.append(process_sample(server.pid)); finished.set(); sampler.join(2)
        if sampler.is_alive() or errors: raise RuntimeError('server sampler failed: ' + str(errors))
        row['peers'] = [json.loads((root / f'peer-{index}.json').read_text()) for index in range(concurrency)]
        row['metrics'] = admit_burst(row['peers'], transport, concurrency)
        samples.sort(key=lambda value: value['monotonic_ns'])
        if len({(value['start'], value['cpu_affinity'], value['nice']) for value in samples}) != 1:
            raise RuntimeError('server process identity or CPU policy changed')
        if not (samples[0]['monotonic_ns'] <= min(value['hello_started_ns'] for value in row['peers'])
                < max(value['auth_verified_ns'] for value in row['peers']) <= samples[-1]['monotonic_ns']):
            raise RuntimeError('server sampler does not enclose admitted burst')
        first, last = samples[0], samples[-1]
        elapsed = (last['monotonic_ns'] - first['monotonic_ns']) / 1e9
        row['server'] = dict(pid=server.pid, clock_ticks=os.sysconf('SC_CLK_TCK'), samples=samples,
            cpu_avg_pct=100 * (last['ticks'] - first['ticks']) / os.sysconf('SC_CLK_TCK') / elapsed,
            rss_peak_kib=max(value['rss_kib'] for value in samples), elapsed=elapsed,
            host_steal_pct=100 * (last['host_steal'] - first['host_steal']) / max(1, last['host_total'] - first['host_total']))
        clients = control(root, 'list-clients')['clients']
        if len(clients) != concurrency or any(client['username'] != 'fixture' or client['profile'] != 'auth-contracts' for client in clients):
            raise RuntimeError('registry does not contain exactly the accepted peers')
        if len({client['ip'] for client in clients}) != concurrency: raise RuntimeError('duplicate admitted pool address')
        row['registry'] = [{key: client[key] for key in ('username', 'profile', 'ip')} for client in clients]
        # Keep peers alive until the observed fixture sessions have been revoked.
        # Closing TCP peers first can legitimately remove the last session before kick.
        control(root, 'kick', username='fixture')
        wait_for(lambda: not control(root, 'list-clients')['clients'])
        (barrier / 'release').write_text('release observed peers')
        for process in peers:
            if process.wait(timeout=3) != 0: raise RuntimeError('accepted peer failed after measurement')
        row['status'] = 'COMPLETED'
        return row
    except BaseException as error:
        row.update(status='FAIL', error=str(error)); raise
    finally:
        finished.set()
        if sampler: sampler.join(2)
        for process in peers: stop(process)
        stop(server)
        for stream in streams: stream.close()
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qeli', required=True); parser.add_argument('--peer', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(mode=0o700)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    result = dict(status='RUNNING', runs=[], errors=[], topology='server and prepared peers on private loopback on one VM',
        phc=dict(algorithm='argon2id', version=19, memory_kib=19456, iterations=2, parallelism=1),
        scope='finite synchronized PQ/proof/AUTH bursts; TCP connect, key generation, process/TUN startup excluded; not sustained server capacity')
    try:
        for repeat in (1, 2, 3):
            transports = ('tcp', 'udp', 'quic') if repeat != 2 else ('quic', 'udp', 'tcp')
            for transport in transports:
                for concurrency in ((1, 4, 16) if repeat != 2 else (16, 4, 1)):
                    label = f'r{repeat}-{transport}-c{concurrency}'
                    row = scenario(args.qeli, args.peer, args.output / label, transport, concurrency, repeat)
                    row['label'] = label; result['runs'].append(row)
                    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    print('COMPLETED', label, round(row['metrics']['burst_admissions_per_second'], 2), flush=True)
        result['status'] = 'MEASUREMENTS_COMPLETE'
    except BaseException as error: result.update(status='FAIL', errors=[str(error)]); raise
    finally: (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__': main()
