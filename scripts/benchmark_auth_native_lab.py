#!/usr/bin/env python3
"""Bounded loopback AUTH bursts; run inside private NET/mount namespaces only.

Three fresh servers per native wire-mode/concurrency. Server and peers share a two-vCPU
VM. Peers stop before client NetworkPlan application; the resulting finite-burst rate is not network or sustained server capacity.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from audit_udp_handshake_contracts import control, stop, wait_for
from benchmark_auth_native import admit_native_burst, validate_control_path, validate_instrumented_peer
from benchmark_isolated_lab import configs
from benchmark import MODES
import re


from benchmark_auth_lab import password_hash, process_sample


def scenario(binary, peer, root, mode_name, concurrency, repeat):
    validate_control_path(root)
    root.mkdir(mode=0o700)
    (root / 'state').mkdir(mode=0o700)
    barrier = root / 'barrier'; barrier.mkdir(mode=0o700)
    mode = next(value for value in MODES if value['name'] == mode_name)
    transport = 'quic' if mode.get('quic') else mode['transport']
    config, _ = configs(mode, '00' * 32)
    config = config.replace('[auth]\n', '[auth]\nbind_static_to_session = true\n')
    config = config.replace('require_client_key_proof = false', 'require_client_key_proof = true')
    config = config.replace('/etc/qeli/users.conf', str(root / 'users.ini'))
    config = config.replace('/etc/qeli/identity/bench.key', str(root / 'identity.key'))
    config = config.replace('bind.address = 10.255.42.1', 'bind.address = 127.0.0.1')
    config = config.replace('bind.port = ' + str(mode['port']), 'bind.port = 24943')
    config = config.replace('tun.name = qbench0', 'tun.name = q09srv')
    config = config.replace('obf.tls.reality_proxy.target = 10.255.42.1', 'obf.tls.reality_proxy.target = 127.0.0.1')
    config = config.replace('obf.heartbeat.enabled = true', 'obf.heartbeat.enabled = false')
    config = config.replace('[profile:bench]', '[profile:auth-contracts]')
    config = config.replace('[user:bench]', '[user:fixture]')
    config = re.sub(r'^password_hash = .*$', 'password_hash = ' + password_hash(), config, flags=re.M)
    config = config.replace('[user:fixture]\n', '[user:fixture]\nmax_sessions = 0\n')
    config = config.replace('perf.connection.max_clients = 128',
        'perf.connection.max_clients = 128\nperf.connection.new_session_rate_max = 1000')
    if mode['transport'] == 'udp':
        config = config.replace('perf.connection.idle_timeout_secs = 0', 'perf.connection.idle_timeout_secs = 120')
    (root / 'server.ini').write_text(config)
    (root / 'server.ini').chmod(0o600)
    (root / 'users.ini').write_text('')
    env = dict(os.environ, STATE_DIRECTORY=str(root / 'state'), QELI_CONTROL_SOCKET=str(root / 'control.sock'))
    peers, streams, server, sampler = [], [], None, None
    finished = threading.Event()
    samples = []
    errors = []
    row = dict(status='RUNNING', mode=mode_name, transport=transport, concurrency=concurrency, repeat=repeat, peers=[])
    def save(): (root / 'result.json').write_text(json.dumps(row, indent=2, allow_nan=False) + '\n')
    def sample():
        try:
            while not finished.wait(.05): samples.append(process_sample(server.pid))
        except Exception as error: errors.append(str(error))
    try:
        log = (root / 'server.log').open('w'); streams.append(log)
        subprocess.run([binary, 'check-config', '-c', str(root / 'server.ini')], env=env,
            stdout=log, stderr=subprocess.STDOUT, check=True)
        # _worker avoids a supervisor PID in the measured server process counters.
        server = subprocess.Popen([binary, '_worker', '-c', str(root / 'server.ini')], env=env,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        wait_for(lambda: (root / 'control.sock').exists() and (root / 'identity.key').exists(), 12)
        if control(root, 'list-clients')['clients']: raise RuntimeError('server not fresh')
        identity = subprocess.run([binary, 'show-identity', '-c', str(root / 'server.ini')],
            env=env, text=True, capture_output=True, check=True).stdout
        keys = re.findall(r'(?m)^auth-contracts\s+\S+\s+([0-9a-f]{64})$', identity)
        if len(keys) != 1: raise RuntimeError('expected exactly one pinned identity')
        row['server_public_key'] = keys[0]
        for index in range(concurrency):
            _, client = configs(mode, keys[0])
            client = client.replace('server = 10.255.42.1:' + str(mode['port']), 'server = 127.0.0.1:24943')
            client = client.replace('user = bench', 'user = fixture').replace('pass = testpass123', 'pass = fixture-password')
            client = client.replace('dev = qbench0', 'dev = qauth' + str(index)).replace('timeout = 5', 'timeout = 30')
            client = client.replace('[qeli]\n', '[qeli]\nbind_static = true\nkill_switch = false\n')
            client_path = root / f'client-{index}.ini'
            client_path.write_text(client); client_path.chmod(0o600)
            peer_state = root / f'peer-state-{index}'; peer_state.mkdir(mode=0o700)
            log = (root / f'peer-{index}.log').open('w'); streams.append(log)
            peers.append(subprocess.Popen([peer, 'client', '-c', str(client_path)],
                env=dict(env, STATE_DIRECTORY=str(peer_state), QELI_AUTH_BARRIER=str(barrier), QELI_AUTH_MODE=mode_name,
                    QELI_DEVICE_ID_FILE=str(peer_state / 'device-id'), QELI_CLIENT_PROFILE='auth-' + str(index),
                    QELI_CLIENT_STATUS=str(peer_state / 'client-status.json')),
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True))
        row['pids'] = dict(server=server.pid, peers=[process.pid for process in peers]); save()
        def ready():
            if any(process.poll() is not None for process in peers): raise RuntimeError('peer exited before release')
            return {path.name for path in barrier.glob('ready-*')} == {f'ready-{process.pid}' for process in peers}
        wait_for(ready, 20)
        samples.append(process_sample(server.pid))
        sampler = threading.Thread(target=sample); sampler.start()
        (barrier / 'go').write_text('release prepared peers')
        def complete():
            if server.poll() is not None or any(process.poll() is not None for process in peers):
                raise RuntimeError('fixture process exited during admission')
            return all((barrier / f'result-{process.pid}.json').exists() for process in peers)
        wait_for(complete, 20)
        samples.append(process_sample(server.pid)); finished.set(); sampler.join(2)
        if sampler.is_alive() or errors: raise RuntimeError('server sampler failed: ' + str(errors))
        row['peers'] = [json.loads((barrier / f'result-{process.pid}.json').read_text()) for process in peers]
        row['metrics'] = admit_native_burst(row['peers'], mode, concurrency, row['pids']['peers'])
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
        # Parked AUTH-only peers do not run the management-event reader/ACK loop.
        # Kick would measure its timeout path, which is outside the AUTH interval.
        # Observe every admitted session first, then release peers and shut down
        # this private server; require an actual clean exit rather than a kill.
        (barrier / 'release').write_text('release observed peers')
        for process in peers:
            if process.wait(timeout=3) != 0: raise RuntimeError('accepted peer failed after measurement')
        stop(server)
        row['cleanup'] = dict(peers_exit_zero=True, server_exit_code=server.returncode,
            method='release observed AUTH-only peers, then SIGTERM private server; management ACK path not run')
        if server.returncode != 0: raise RuntimeError('private server did not shut down cleanly')
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
    args = parser.parse_args()
    validate_instrumented_peer(args.peer)
    args.output.mkdir(mode=0o700)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    result = dict(status='RUNNING', runs=[], errors=[], topology='native server and prepared native CLI peers on private loopback on one VM',
        phc=dict(algorithm='argon2id', version=19, memory_kib=19456, iterations=2, parallelism=1),
        scope='finite prepared native inner-handshake/proof/AUTH bursts; process startup, key generation and TCP outer wrapper establishment excluded; UDP AWG junk included; no client NetworkPlan applied; not sustained server capacity')
    target = None
    try:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=www.cloudflare.com', '-keyout', str(args.output / 'target.key'),
            '-out', str(args.output / 'target.crt')], check=True, capture_output=True)
        target_log = (args.output / 'target.log').open('w')
        target = subprocess.Popen(['openssl', 's_server', '-4', '-accept', '127.0.0.1:9443',
            '-cert', str(args.output / 'target.crt'), '-key', str(args.output / 'target.key'), '-www', '-quiet'],
            stdout=target_log, stderr=subprocess.STDOUT, start_new_session=True)
        time.sleep(.2)
        if target.poll() is not None: raise RuntimeError('private REALITY target exited')
        for repeat in (1, 2, 3):
            order = MODES if repeat != 2 else list(reversed(MODES))
            for mode in order:
                for concurrency in ((1, 4, 16) if repeat != 2 else (16, 4, 1)):
                    # Short physical path keeps the control AF_UNIX address below SUN_LEN.
                    label = f"r{repeat}-m{MODES.index(mode):02d}-c{concurrency}"
                    row = scenario(args.qeli, args.peer, args.output / label, mode['name'], concurrency, repeat)
                    row['label'] = label; result['runs'].append(row)
                    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
                    print('COMPLETED', label, round(row['metrics']['burst_admissions_per_second'], 2), flush=True)
        result['status'] = 'MEASUREMENTS_COMPLETE'
    except BaseException as error: result.update(status='FAIL', errors=[str(error)]); raise
    finally:
        stop(target)
        if target: target_log.close()
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__': main()
