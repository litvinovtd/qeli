#!/usr/bin/env python3
"""Run the existing Linux release cases through SSH in fresh NET/mount/PID namespaces."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import time

from native_lab import connect_lab
from native_repro import source_digest
from run_ipv6_release_matrix import MATRIX_CASES, SPECIAL_CASES

FILES = ('ipv6_netns_case.sh', 'ipv6_dns_pair.sh', 'ipv6_mtu_pair.sh',
         'ipv6_legacy_pair.sh', 'dns_test_server.py', 'tap_ipv6_control_probe.py',
         'audit_outer_udp_capture.py')
CASES = {name: ('ipv6_netns_case.sh', parameters, 180)
         for name, parameters in MATRIX_CASES + SPECIAL_CASES}
CASES.update({'linux.dns.ipv4-ipv6': ('ipv6_dns_pair.sh', (), 360),
              'linux.mtu.1280-pmtu-ptb': ('ipv6_mtu_pair.sh', (), 360),
              'linux.legacy-peer': ('ipv6_legacy_pair.sh', (), 360)})
ISOLATED = r'''
set -eu
case_root=$1; parent_net=$2; parent_mnt=$3; parent_pid=$4; shift 4
[ "$(readlink /proc/self/ns/net)" != "$parent_net" ]
[ "$(readlink /proc/self/ns/mnt)" != "$parent_mnt" ]
[ "$(readlink /proc/self/ns/pid)" != "$parent_pid" ]
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /var/lib
mount -t tmpfs tmpfs /var/log
mkdir -p /var/lib/qeli /var/log/qeli "$case_root/etc" "$case_root/tmp"
mount --bind "$case_root/etc" /etc/qeli
mount --bind "$case_root/tmp" /tmp
export QELI_KEEP_WORK=1 TMPDIR=/tmp LC_ALL=C
exec bash "$@"
'''


def normalize_listener(output):
    # ss aligns columns using every current listener, including temporary emulator
    # ports. Preserve all six fields (and quoted process metadata) while removing
    # only inter-column padding; malformed rows must fail instead of disappearing.
    rows = []
    for line in output.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise ValueError('invalid listener snapshot row')
        rows.append(' '.join(fields[:5]) + ' ' + fields[5].strip())
    return '\n'.join(rows)


def snapshot(lab):
    result = {name: lab.checked(command, name, timeout=30) for name, command in {
        'addresses4': 'ip -br -4 addr', 'addresses6': 'ip -br -6 addr',
        'routes4': 'ip -4 route show table all', 'routes6': 'ip -6 route show table all',
        'firewall4': 'iptables-save', 'firewall6': 'ip6tables-save',
        'firewall4_legacy': 'iptables-legacy-save', 'firewall6_legacy': 'ip6tables-legacy-save',
        # nft emits successful iptables ownership warnings on stderr. SSH merges
        # stderr/stdout at arbitrary chunk boundaries, corrupting otherwise equal
        # snapshots. Suppress only successful diagnostics; retain fatal stderr/rc.
        'nft': "python3 -c 'import subprocess,sys; p=subprocess.run([\"nft\",\"list\",\"ruleset\"],capture_output=True); sys.stdout.buffer.write(p.stdout); sys.stderr.buffer.write(p.stderr if p.returncode else b\"\"); sys.exit(p.returncode)'",
        'listener': "ss -lntp | grep ':443'", 'resolver_sha256': 'sha256sum /etc/resolv.conf',
        'named_namespaces': 'ip netns list',
    }.items()}
    for key in ('firewall4', 'firewall6', 'firewall4_legacy', 'firewall6_legacy'):
        result[key] = re.sub(r'\[\d+:\d+\]', '[COUNTERS]', '\n'.join(
            line for line in result[key].splitlines() if not line.startswith('#')))
    result['nft'] = re.sub(r'counter packets \d+ bytes \d+', 'counter packets COUNTER bytes COUNTER', result['nft'])
    result['listener'] = normalize_listener(result['listener'])
    return result


def put(sftp, path, data):
    with sftp.open(path, 'wb') as output:
        output.write(data)
    sftp.chmod(path, 0o600)


def pull_logs(sftp, remote, local):
    for item in sftp.listdir_attr(remote):
        if '/' in item.filename or item.filename in ('.', '..'):
            raise RuntimeError('unsafe remote filename')
        src = remote + '/' + item.filename
        dst = local / item.filename
        if stat.S_ISDIR(item.st_mode):
            dst.mkdir(exist_ok=True)
            pull_logs(sftp, src, dst)
        elif stat.S_ISREG(item.st_mode) and item.filename.endswith(('.log', '.pcap')):
            sftp.get(src, str(dst))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='10.66.116.11')
    parser.add_argument('--qeli', default='/root/qeli-src/target/release/qeli')
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--legacy-deb', default='/opt/qeli-src/debian/qeli_0.7.16_amd64.deb')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cases', nargs='+', choices=tuple(CASES))
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.sha256):
        parser.error('full binary SHA256 required')
    for path in (args.qeli, args.legacy_deb):
        if not re.fullmatch('/[A-Za-z0-9_./-]+', path) or '..' in path.split('/'):
            parser.error('binary/package paths must be absolute safe shell paths')
    password = os.environ.get('QELI_LAB_PASS')
    if not password:
        parser.error('QELI_LAB_PASS required')
    root = Path(__file__).resolve().parent.parent
    # The CLI release and executable fixtures must come from committed inputs.
    # Independent native builds update provenance while this matrix runs; those
    # records and prose do not compile into the SHA-verified Linux executable.
    if subprocess.check_output(
        ['git', 'status', '--porcelain', '--untracked-files=no', '--',
         'qeli', 'conformance', 'scripts'], cwd=root
    ).strip():
        parser.error('commit compilation and fixture inputs before executing the release matrix')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    lab = connect_lab(args.host, 'root', password)
    stamp = dt.datetime.now(dt.timezone.utc)
    remote = '/var/tmp/qeli-release-matrix-' + stamp.strftime('%Y%m%dT%H%M%S%fZ')
    data = dict(schema_version=1, kind='qeli-release-matrix-isolated-lab',
                executed_at=stamp.isoformat(), host=args.host, artifact_sha256=args.sha256,
                source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                native_source_digest=source_digest(root), fixture_sha256={}, remote=remote, results=[])
    def save():
        (args.output/'results.json').write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
    before = None
    try:
        before = snapshot(lab)
        data['host_before'] = before
        if lab.checked('sha256sum '+args.qeli, 'binary SHA').split()[0] != args.sha256:
            raise RuntimeError('binary SHA mismatch')
        data['environment'] = lab.checked('uname -srmo', 'kernel')
        data['version'] = lab.checked(args.qeli+' --version', 'version')
        lab.checked('mkdir -m 700 '+remote+'; mkdir -m 700 '+remote+'/scripts', 'unique remote root')
        sftp = lab.open_sftp()
        try:
            for name in FILES:
                original = (root/'scripts'/name).read_bytes()
                runtime = original.replace(b'\r\n', b'\n')
                put(sftp, remote+'/scripts/'+name, runtime)
                actual = lab.checked('sha256sum '+remote+'/scripts/'+name, 'fixture SHA').split()[0]
                if actual != hashlib.sha256(runtime).hexdigest():
                    raise RuntimeError('uploaded fixture mismatch')
                data['fixture_sha256'][name] = dict(source=hashlib.sha256(original).hexdigest(), runtime=actual)
            put(sftp, remote+'/isolated.sh', ISOLATED.encode())
            data['isolation_sha256'] = hashlib.sha256(ISOLATED.encode()).hexdigest()
        finally:
            sftp.close()
        parent_net = lab.checked('readlink /proc/self/ns/net', 'parent network namespace')
        parent_mnt = lab.checked('readlink /proc/self/ns/mnt', 'parent mount namespace')
        parent_pid = lab.checked('readlink /proc/self/ns/pid', 'parent PID namespace')
        selected = args.cases or list(CASES)
        legacy = remote+'/legacy/usr/bin/qeli'
        if 'linux.legacy-peer' in selected:
            data['legacy_deb_sha256'] = lab.checked('sha256sum '+args.legacy_deb, 'legacy package SHA').split()[0]
            lab.checked('mkdir -m 700 '+remote+'/legacy; dpkg-deb -x '+args.legacy_deb+' '+remote+'/legacy', 'extract legacy without installing')
            possible = lab.checked('find '+remote+'/legacy -type f -name qeli', 'legacy binary inventory').splitlines()
            if len(possible) != 1 or not possible[0].startswith(remote+'/legacy/'):
                raise RuntimeError('expected one extracted legacy binary')
            legacy = possible[0]
            data['legacy_version'] = lab.checked(shlex.quote(legacy)+' --version', 'legacy version')
            if data['legacy_version'] != 'qeli 0.7.16':
                raise RuntimeError('wrong legacy version')
            data['legacy_artifact_sha256'] = lab.checked('sha256sum '+shlex.quote(legacy), 'legacy binary SHA').split()[0]
        for index, name in enumerate(selected, 1):
            script, parameters, budget = CASES[name]
            cell = remote+'/'+name
            lab.checked('mkdir -m 700 '+cell, 'case directory')
            command = ['timeout', '--signal=TERM', '--kill-after=10', str(budget+30),
                       'unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                       'bash', remote+'/isolated.sh', cell, parent_net, parent_mnt, parent_pid,
                       remote+'/scripts/'+script, args.qeli, *parameters]
            if name == 'linux.legacy-peer':
                command.append(legacy)
            command_text = shlex.join(command)
            print(f'[{index}/{len(selected)}] START {name}', flush=True)
            start = time.monotonic()
            output, code = lab.run(command_text, timeout=budget+60)
            (args.output/(name+'.log')).write_text(output+'\n', encoding='utf-8')
            checks = re.findall(r'=== RESULT .*?: (\d+) passed, (\d+) failed ===', output)
            row = dict(id=name, status='passed' if code == 0 and checks and all(int(f)==0 for p,f in checks) else 'failed',
                       exit_code=code, duration_seconds=round(time.monotonic()-start,3),
                       checks_passed=sum(int(p) for p,f in checks) if checks else len(re.findall(r'^\s*PASS  ', output, re.M)),
                       checks_failed=sum(int(f) for p,f in checks) if checks else len(re.findall(r'^\s*FAIL  ', output, re.M)),
                       command=command_text, log=name+'.log')
            data['results'].append(row); save()
            print(row['status'].upper(), name, row['checks_passed'], row['checks_failed'], flush=True)
            local = args.output/name; local.mkdir()
            sftp = lab.open_sftp()
            try:
                pull_logs(sftp, cell, local)
            finally:
                sftp.close()
            if row['status'] != 'passed':
                data['stopped_on_failure'] = name
                break
        data['aggregate_leak_passed'] = set(name for name, _ in MATRIX_CASES).issubset(
            {row['id'] for row in data['results'] if row['status']=='passed'})
    finally:
        if before is not None:
            data['host_after'] = snapshot(lab)
            data['host_restored'] = data['host_after']==before
        save(); lab.close()
    if not data.get('host_restored'):
        raise RuntimeError('host state changed after isolated release matrix')
    return 0 if all(row['status']=='passed' for row in data['results']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
