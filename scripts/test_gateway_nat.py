#!/usr/bin/env python3
"""Qualify gateway NAT and forward_private in fresh NET/mount/PID namespaces.
Requires a SHA-pinned candidate and a read-only extracted firewalld package directory.
Does not replace executables, restart services, or clean host rules by matching tags.
"""
# Manual lab scenario: importing for test discovery must not execute it.
if __name__ == "__main__":
    import argparse
    import datetime as dt
    import hashlib
    import json
    import os
    from pathlib import Path
    import re
    import shlex
    import stat
    from native_lab import connect_lab
    from audit_release_matrix_lab import ISOLATED, snapshot, put


    def main():
        ap = argparse.ArgumentParser(description=__doc__)
        ap.add_argument('--host', default='10.66.116.11')
        ap.add_argument('--qeli', required=True)
        ap.add_argument('--sha256', required=True)
        ap.add_argument('--output', required=True, type=Path)
        ap.add_argument('--package', required=True, help='Read-only extracted package directory on the lab')
        ap.add_argument('--ipv4', choices=('nft', 'legacy'), default='nft')
        ap.add_argument('--ipv6', choices=('nft', 'legacy'), default='legacy')
        a = ap.parse_args()
        if not re.fullmatch('[0-9a-f]{64}', a.sha256):
            ap.error('full binary SHA256 required')
        for p in (a.qeli, a.package):
            if not re.fullmatch('/[A-Za-z0-9_./-]+', p) or '..' in p.split('/'):
                ap.error('absolute safe binary/package paths required')
        password = os.environ.get('QELI_LAB_PASS')
        if not password:
            ap.error('QELI_LAB_PASS required')
        a.output.mkdir(parents=True, exist_ok=False)
        source = Path(__file__).resolve().parent
        remote = '/var/tmp/qeli-gateway-audit-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        result = dict(status='FAIL', executed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                      artifact_sha256=a.sha256, remote=remote, fixture_sha256={}, backends=[a.ipv4, a.ipv6])
        lab = connect_lab(a.host, 'root', password)
        def pull(sftp, src, dst):
            dst.mkdir(exist_ok=True)
            for entry in sftp.listdir_attr(src):
                if '/' in entry.filename or entry.filename in ('.', '..'):
                    raise RuntimeError('unsafe remote filename')
                target = dst / entry.filename
                if stat.S_ISDIR(entry.st_mode):
                    pull(sftp, src+'/'+entry.filename, target)
                elif stat.S_ISREG(entry.st_mode):
                    sftp.get(src+'/'+entry.filename, str(target))
        try:
            result['host_before'] = snapshot(lab)
            if lab.checked('sha256sum '+a.qeli, 'candidate SHA', 30).split()[0] != a.sha256:
                raise RuntimeError('candidate SHA mismatch')
            lab.checked('test -d '+a.package+' && test ! -e '+remote+' && mkdir -m 700 '+remote, 'private root', 30)
            sftp = lab.open_sftp()
            try:
                for name in ('audit_server_route_policy.py', 'audit_firewalld_profiles.py'):
                    data = (source/name).read_bytes().replace(b'\r\n', b'\n')
                    put(sftp, remote+'/'+name, data)
                    h = hashlib.sha256(data).hexdigest()
                    if lab.checked('sha256sum '+remote+'/'+name, 'fixture SHA', 30).split()[0] != h:
                        raise RuntimeError('fixture upload SHA mismatch')
                    result['fixture_sha256'][name] = h
                put(sftp, remote+'/isolated.sh', ISOLATED.encode())
                parents = [lab.checked('readlink /proc/self/ns/'+k, k, 30) for k in ('net', 'mnt', 'pid')]
                argv = ['python3', remote+'/audit_server_route_policy.py', 'run', '--qeli', a.qeli,
                        '--sha256', a.sha256, '--artifacts', remote+'/case', '--package', a.package,
                        '--ipv4', a.ipv4, '--ipv6', a.ipv6, '--ipv4-gateway']
                for k, value in zip(('net', 'mnt', 'pid'), parents):
                    argv += ['--parent-'+k, value]
                put(sftp, remote+'/run.sh', ('set -eu\nexec '+shlex.join(argv)+'\n').encode())
            finally:
                sftp.close()
            command = shlex.join(['timeout', '--signal=TERM', '--kill-after=10', '200',
                                 'unshare', '--net', '--mount', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                                 'bash', remote+'/isolated.sh', remote+'/private', *parents, remote+'/run.sh'])
            result['command'] = command
            print('START isolated gateway', a.ipv4, a.ipv6, flush=True)
            log, code = lab.run(command, 230)
            (a.output/'runtime.log').write_text(log, encoding='utf8', newline='\n')
            result['exit_code'] = code
            sftp = lab.open_sftp()
            try:
                pull(sftp, remote+'/case', a.output/'case')
            finally:
                sftp.close()
            case = json.loads((a.output/'case/result.json').read_text(encoding='utf8'))
            result['case'] = case
            if code != 0 or case['status'] != 'PASS':
                raise RuntimeError('gateway fixture failed; inspect runtime.log')
            result['status'] = 'PASS'
        finally:
            if 'host_before' in result:
                result['host_after'] = snapshot(lab)
                result['host_restored'] = result['host_before'] == result['host_after']
                if not result['host_restored']:
                    result['status'] = 'FAIL_HOST_CHANGED'
            lab.close()
            (a.output/'checks.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf8', newline='\n')
        if result['status'] != 'PASS':
            raise RuntimeError(result['status'])
        print('PASS isolated gateway', case['check_count'], 'checks; host unchanged', flush=True)


    if __name__ == '__main__':
        main()
