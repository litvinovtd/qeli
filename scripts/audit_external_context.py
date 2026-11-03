#!/usr/bin/env python3
"""Run D06 existing context regressions with real independently selected backends.

Requires audit_release_matrix_lab.ISOLATED. No firewalld service is started.
Native tests mutate only disposable threads' network namespaces. Packet tests
prove actual DROP counters, not delivery to an external receiver.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from audit_firewalld_profiles import MixedFirewall

DYNAMIC = [
    'client::killswitch::native_tests::native_late_ipv4_route_stays_behind_existing_kill_switch',
    'client::killswitch::native_tests::native_late_ipv6_address_stays_behind_existing_kill_switch',
    'client::killswitch::native_tests::native_kill_switch_namespace_change_preserves_foreign_rules',
]
COMMON_FILTERS = [
    'client::gateway::wan::tests::',
    'client::gateway::rollback_tests::exit_tests::',
    'client::dns::resolver_context::tests::',
    'tun::open::attach_tests::',
    'client_tasks::tests::',
    'client_tasks::admission_tests::',
    'network_interface::tests::',
]
COMMON_NATIVE = [
    'network_interface::tests::native_interface_queries_ignore_inherited_sysfs',
    'client::network_view_tests::native_tap_mac_and_hook_index_use_calling_namespace',
    'client::dns::resolver_context::tests::native_resolver_context_refuses_other_service_network',
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'sha256', 'artifacts', 'package', 'parent-net', 'parent-mnt', 'parent-pid'):
        ap.add_argument('--' + name, required=True)
    ap.add_argument('--ipv4', choices=('nft', 'legacy'), required=True)
    ap.add_argument('--ipv6', choices=('nft', 'legacy'), required=True)
    ap.add_argument('--common', action='store_true')
    args = ap.parse_args()
    for kind in ('net', 'mnt', 'pid'):
        assert os.readlink('/proc/self/ns/' + kind) != getattr(args, 'parent_' + kind)
    binary = Path(args.binary).resolve(strict=True)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == args.sha256
    root = Path(args.artifacts)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = dict(status='FAIL', binary_sha256=args.sha256, backends=[args.ipv4, args.ipv6],
                  commands=[], setup_checks=[], tests=[], common=args.common)

    def save():
        (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    def run(argv, check=True, env=None, executable=None):
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env, executable=executable)
        result['commands'].append(dict(argv=argv, executable=executable, exit_code=p.returncode, output=p.stdout+p.stderr))
        save()
        if check:
            assert p.returncode == 0, (argv, p.stdout, p.stderr)
        return p

    def record(name, ok, detail=None):
        result['setup_checks'].append(dict(name=name, passed=bool(ok), detail=detail)); save()
        assert ok, (name, detail)

    def test(selector, ignored=False, exact=False, expected=None):
        names = [n for n in listed if (n == selector if exact else selector in n)]
        assert names, selector
        argv = [str(binary), selector, '--test-threads=1']
        if ignored: argv.append('--ignored')
        if exact: argv.append('--exact')
        p = run(argv)
        (root / ('test-' + str(len(result['tests'])) + '.log')).write_text(p.stdout+p.stderr)
        counts = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', p.stdout)
        assert len(counts) == 1, p.stdout
        passed, failed, skipped = map(int, counts[0])
        assert passed > 0 and failed == 0, (selector, counts)
        if ignored: assert skipped == 0 and passed == len(names), (selector, names, counts)
        else: assert passed + skipped == len(names), (selector, names, counts)
        if expected is not None: assert passed == expected, (selector, counts)
        result['tests'].append(dict(selector=selector, selected=names, passed=passed, failed=failed,
                                    ignored=skipped, privileged=ignored, exact=exact)); save()
        print('PASS', selector, passed, 'executed;', skipped, 'ignored', flush=True)

    try:
        # Constructor installs real multicall dispatch in this private mount.
        # prepare() is deliberately not called: this batch starts no policy daemon.
        MixedFirewall(root, args.package, args.ipv4, args.ipv6, run, record)
        listing = run([str(binary), '--list']).stdout
        (root / 'test-list.log').write_text(listing)
        listed = [x.removesuffix(': test') for x in listing.splitlines() if x.endswith(': test')]
        for name in DYNAMIC: test(name, ignored=True, exact=True, expected=1)
        if args.common:
            for selector in COMMON_FILTERS: test(selector)
            test('tun::iface::linux_tests::', ignored=True, expected=8)
            for name in COMMON_NATIVE: test(name, ignored=True, exact=True, expected=1)
        result['passed'] = sum(t['passed'] for t in result['tests'])
        result['portable_passed'] = sum(t['passed'] for t in result['tests'] if not t['privileged'])
        result['privileged_passed'] = sum(t['passed'] for t in result['tests'] if t['privileged'])
        result['status'] = 'PASS'
    finally:
        save()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
