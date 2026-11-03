#!/usr/bin/env python3
"""Exercise Linux client INI bootstrap through both real CLI entry points.

Requires a fresh NET/mount/PID namespace. All configs, sinks and process groups
belong to the caller's private case directory. Never changes host networking.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

LIMIT = 256 * 1024
SENTINEL = b'owned-fixture-sentinel\n'


def run(command):
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, env={**os.environ, 'RUST_LOG': 'debug'})
    timed_out = False
    try:
        output, _ = process.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            output, _ = process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate(timeout=2)
    return dict(command=command, exit_code=process.returncode, timed_out=timed_out,
                elapsed_seconds=round(time.monotonic()-started, 4),
                output=output.decode('utf8', errors='replace'),
                output_sha256=hashlib.sha256(output).hexdigest())


def profile(sink):
    return ('[qeli]\nserver = 127.0.0.1:1\nproto = tcp\nuser = fixture\n'
            'pass = fixture-only\nkey = '+ '11'*32 + '\nmode = plain\n'
            'reconnect = false\ntimeout = 1\ngateway = false\n'
            '[logging]\nlevel = debug\nfile = '+str(sink)+'\ntime_format = none\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--daemon', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--expect', required=True, choices=('baseline', 'fixed'))
    for name in ('net', 'mnt', 'pid'):
        parser.add_argument('--parent-'+name, required=True)
    args = parser.parse_args()
    isolation = {name: os.readlink('/proc/self/ns/'+name) for name in ('net', 'mnt', 'pid')}
    if any(isolation[name] == getattr(args, 'parent_'+name) for name in isolation):
        parser.error('fresh NET/mount/PID namespaces required before fixture writes')
    root = args.output.resolve(strict=True)
    if args.output.is_symlink() or root != args.output or list(root.iterdir()):
        parser.error('empty owned absolute output directory required')
    for binary in (args.client, args.daemon):
        if not binary.is_file() or binary.is_symlink():
            parser.error('regular private executable required')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    def network():
        return {name: subprocess.check_output(command, text=True) for name, command in {
            'links': ['ip', '-o', 'link'], 'routes4': ['ip', '-4', 'route', 'show', 'table', 'all'],
            'routes6': ['ip', '-6', 'route', 'show', 'table', 'all'],
            'firewall4': ['iptables-save'], 'firewall6': ['ip6tables-save'],
        }.items()}
    before = network()
    results = []
    def invoke(name, command, config, sink=None, sink_rule=None, valid=False):
        result = run([str(x) for x in command]+['--config', str(config)])
        result['name'] = name
        result['checks'] = {'bounded_completion': not result['timed_out']}
        if sink is not None:
            result['sink_exists'] = sink.exists()
            if sink.exists() and sink.is_file():
                result['sink_sha256'] = hashlib.sha256(sink.read_bytes()).hexdigest()
            result['checks']['sink_policy'] = (
                sink.exists() and not sink.is_file() if sink_rule == 'fifo' else
                sink.exists() if sink_rule == 'created' else
                sink.exists() and sink.read_bytes() == SENTINEL if sink_rule == 'unchanged' else
                not sink.exists())
        if 'check' in name:
            result['checks']['validation_exit'] = (result['exit_code'] == 0) == valid
        else:
            result['checks']['startup_exit'] = result['exit_code'] > 0
        result['pass'] = all(result['checks'].values())
        (root/(name+'.log')).write_text(result['output'], encoding='utf8')
        results.append(result)
    for flavor, command in [('standalone', [args.client]), ('daemon', [args.daemon, 'client'])]:
        for kind in ('trusted', 'mixed-case', 'untrusted', 'symlink', 'malformed', 'oversized', 'exact-limit', 'fifo-sink'):
            case = root/(flavor+'-'+kind)
            case.mkdir(mode=0o700)
            config, sink = case/'client.ini', case/'sink.log'
            text = profile(sink)
            if kind == 'fifo-sink':
                os.mkfifo(sink, 0o600)
            if kind == 'mixed-case':
                text = '\n'.join(line.upper() if line.startswith('[') else
                                 line.split('=', 1)[0].upper()+'='+line.split('=', 1)[1]
                                 if '=' in line else line for line in text.split('\n'))
            if kind == 'malformed':
                text = text.replace('mode = plain', 'mode = invalid-fixture-mode')
            if kind in ('oversized', 'exact-limit'):
                text += '#'
                text += 'x' * (LIMIT+(kind == 'oversized')-len(text.encode()))
            config.write_text(text, encoding='utf8')
            config.chmod(0o666 if kind == 'untrusted' else 0o600)
            if kind in ('untrusted', 'symlink'):
                sink.write_bytes(SENTINEL)
                sink.chmod(0o600)
            if kind == 'symlink':
                linked = case/'linked.ini'
                linked.symlink_to(config)
                config = linked
            rule = ('fifo' if kind == 'fifo-sink' else 'created' if kind in ('trusted', 'mixed-case', 'exact-limit') else
                    'unchanged' if kind in ('untrusted', 'symlink') else 'absent')
            invoke(flavor+'-'+kind, command, config, sink, rule)
        fifo = root/(flavor+'-fifo.ini')
        os.mkfifo(fifo, 0o600)
        invoke(flavor+'-fifo', command, fifo)
    check = [args.daemon, 'check-config', '--client']
    for kind in ('trusted', 'mixed-case', 'malformed', 'oversized', 'exact-limit'):
        invoke('check-'+kind, check, root/('daemon-'+kind)/'client.ini', valid=kind in ('trusted', 'mixed-case', 'exact-limit'))
    fifo = root/'check-fifo.ini'
    os.mkfifo(fifo, 0o600)
    invoke('check-fifo', check, fifo)
    invoke('check-missing', check, root/'missing.ini')
    invoke('check-directory', check, root)
    after = network()
    def comparable(state):
        return {name: '\n'.join(line for line in value.splitlines() if not line.startswith('#'))
                if name.startswith('firewall') else value for name, value in state.items()}
    restored = comparable(before) == comparable(after)
    # Empty private namespaces have no counters or foreign rules. Keep exact dumps.
    failed = {r['name'] for r in results if not r['pass']}
    reproduced = {'standalone-fifo', 'check-fifo', 'standalone-untrusted',
                  'standalone-symlink', 'standalone-oversized', 'daemon-oversized',
                  'standalone-malformed', 'daemon-malformed', 'standalone-mixed-case', 'daemon-mixed-case',
                  'standalone-fifo-sink', 'daemon-fifo-sink'}
    accepted = not failed if args.expect == 'fixed' else reproduced <= failed
    data = dict(schema_version=1, kind='qeli-linux-cli-bootstrap', expectation=args.expect,
                isolation=isolation, artifact_sha256={str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                                     for p in (args.client, args.daemon)},
                results=results, network_before=before, network_after=after,
                network_restored=restored, failed_cases=sorted(failed),
                status='PASS' if accepted and restored else 'FAIL')
    (root/'results.json').write_text(json.dumps(data, indent=2)+'\n', encoding='utf8')
    print(json.dumps({k: data[k] for k in ('status', 'expectation', 'network_restored', 'failed_cases')}))
    raise SystemExit(0 if data['status'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
