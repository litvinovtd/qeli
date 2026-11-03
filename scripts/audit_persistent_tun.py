#!/usr/bin/env python3
"""Private ipv6_netns_case fixture only: refuse a live orphan, then remove it.

The initial queue was made persistent by audit_persistent_tun_shim.c. This helper
runs AFTER SIGKILL/wait. It proves refusal preserves evidence before performing an
explicit operator removal of the exact test interface. It is not a Qeli recovery
command. Subsequent ordinary restart/traffic/cleanup checks stay in the shell case.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--tun', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--owner-pid', type=int, required=True)
    parser.add_argument('--kind', choices=['tun', 'tap'], required=True)
    parser.add_argument('--resolver-pid', type=int)
    parser.add_argument('--dns-marker', type=Path)
    args = parser.parse_args()
    # Restrict deletion to the generated test fixture, never a supplied host link.
    tag = re.fullmatch(r'qv6c(\d+)', args.namespace)
    if not tag or args.tun != 'vpn' + tag[1] or args.work.is_symlink():
        parser.error('requires the generated ipv6_netns_case namespace and interface')
    work = args.work.resolve(strict=True)
    if not re.fullmatch(r'qeli-ipv6-[A-Za-z0-9]+', work.name):
        parser.error('requires an ipv6_netns_case work directory')
    marker = (work / 'persist.ready').read_text().split()
    if marker != [str(args.owner_pid), args.tun]:
        parser.error('initial exclusive-queue injection evidence does not match')
    try:
        os.kill(args.owner_pid, 0)
    except ProcessLookupError:
        pass
    else:
        parser.error('original client still exists; refusing operator removal')
    net = ['ip', 'netns', 'exec', args.namespace]
    context = (['nsenter', '-t', str(args.resolver_pid), '-m', '-n']
               if args.resolver_pid else net)
    env = os.environ.copy()
    env.pop('LD_PRELOAD', None)
    env.pop('QELI_TEST_PERSIST_NAME', None)
    env.pop('QELI_TEST_PERSIST_MARKER', None)
    env.update(QELI_KNOWN_HOSTS=str(work / 'known-hosts'),
               QELI_DEVICE_ID_FILE=str(work / 'device-id'),
               DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/qeli-matrix-bus')
    result = {'worker_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'namespace': args.namespace, 'interface': args.tun, 'checks': {}}

    def run(command):
        return subprocess.check_output(command, env=env, timeout=10, text=True)

    def check(name, success):
        result['checks'][name] = bool(success)
        print(f"  {'PASS' if success else 'FAIL'}  persistent: {name}", flush=True)
        (work / 'persistent-result.json').write_text(json.dumps(result, indent=2) + '\n')
        if not success:
            raise RuntimeError(name + '; test link and evidence retained until namespace cleanup')

    def snapshot(label):
        link = json.loads(run(net + ['ip', '-d', '-j', 'link', 'show', 'dev', args.tun]))[0]
        # No statistics or time-varying address lifetimes are requested.
        state = {'link': link,
                 'addresses': json.loads(run(net + ['ip', '-j', 'address', 'show', 'dev', args.tun])),
                 'routes4': json.loads(run(net + ['ip', '-4', '-j', 'route', 'show', 'table', 'all'])),
                 'routes6': json.loads(run(net + ['ip', '-6', '-j', 'route', 'show', 'table', 'all'])),
                 'journal': Path('/var/lib/qeli/client-routes.state').read_text()}
        if args.dns_marker:
            state['dns_marker'] = args.dns_marker.read_text()
            state['dns'] = run(context + ['resolvectl', 'dns', str(link['ifindex'])])
            state['domains'] = run(context + ['resolvectl', 'domain', str(link['ifindex'])])
            for tool in ['iptables', 'ip6tables']:
                state[tool] = run(net + [tool, '-S'])
        (work / f'persistent-{label}.json').write_text(json.dumps(state, indent=2) + '\n')
        return state

    before = snapshot('before-refusal')
    info = before['link'].get('linkinfo', {})
    check('SIGKILL left the original persistent interface',
          before['link']['ifindex'] == int((work / 'persist.ifindex').read_text())
          and info.get('info_kind') == 'tun' and info.get('info_data', {}).get('persist') is True)
    check('durable journal still identifies the original interface',
          any(g['interface'] == args.tun for g in json.loads(before['journal'])['groups']))
    if args.dns_marker:
        check('persistent link retains tunnel DNS and catch-all domain',
              '10.86.0.1 fd86::1' in before['dns'] and '~.' in before['domains'])
    start = time.monotonic()
    with (work / 'client-persistent-refusal.log').open('w') as log:
        # The worker must exit on its own. A timeout is a failure, never a refusal.
        try:
            proc = subprocess.run(context + [str(args.binary), 'client', '-c', str(work / 'client.conf')],
                                  env=env, stdout=log, stderr=subprocess.STDOUT, timeout=8)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code = None
    result['refusal_seconds'] = time.monotonic() - start
    result['refusal_exit_code'] = code
    check('fresh managed client refuses promptly without timeout', code is not None and code > 0)
    check('diagnostic identifies live or persistent TUN',
          f'client route recovery refuses a live or persistent TUN {args.tun}' in
          (work / 'client-persistent-refusal.log').read_text())
    after = snapshot('after-refusal')
    for key in before:
        check(key + ' unchanged by refused restart', before[key] == after[key])
    # Revalidate immediately before the explicit operator step. No queue was
    # borrowed and no interface was automatically deleted by the refused worker.
    current = json.loads(run(net + ['ip', '-d', '-j', 'link', 'show', 'dev', args.tun]))[0]
    check('operator removal targets the original interface and kind',
          current['ifindex'] == before['link']['ifindex'] and
          current['linkinfo']['info_data']['type'] == args.kind)
    run(net + ['ip', 'tuntap', 'del', 'dev', args.tun, 'mode', args.kind])
    remaining = json.loads(run(net + ['ip', '-j', 'link', 'show']))
    check('explicit operator removal released the test interface',
          all(link['ifname'] != args.tun for link in remaining))


if __name__ == '__main__':
    main()
