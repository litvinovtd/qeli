"""Linux socket-memory evidence, shared by controller, guest and report.

ss rb/tb are kernel-accounted bytes, NOT a payload capacity. Linux doubles an
explicit SO_RCVBUF request; a socket using rmem_default is not doubled again.
"""
import re

VERSION = 'linux-udp-buffers-v1'
LIMIT = 4 * 1024 * 1024
KEYS = ('net.core.rmem_max', 'net.core.rmem_default')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def policy(value):
    require(isinstance(value, dict) and set(value) == {'apply', 'qeli_receive_bytes', 'iperf_receive_rb_bytes'},
            'explicit udp_buffers policy required (apply, qeli_receive_bytes, iperf_receive_rb_bytes)')
    require(type(value['apply']) is bool, 'buffer apply must be boolean')
    require(value['qeli_receive_bytes'] == LIMIT and value['iperf_receive_rb_bytes'] == LIMIT,
            'buffer policy v1 requires Qeli 4MiB and iperf rb 4MiB; use a new method for other limits')
    return dict(value, version=VERSION)


def sockets(text):
    rows = []
    for block in re.split(r'\n(?=\S)', text.strip()):
        if not block:
            continue
        memory = re.search(r'skmem:\(([^)]+)\)', block)
        inode = re.search(r'\bino:(\d+)', block)
        if not memory or not inode:
            continue
        fields = block.splitlines()[0].split()
        # ss -a includes the state column (UNCONN/ESTAB/LISTEN).
        require(len(fields) >= 5, 'malformed socket metadata')
        row = dict(state=fields[0], local=fields[3], peer=fields[4], inode=int(inode[1]),
                   pids=sorted(set(map(int, re.findall(r'pid=(\d+)', block)))))
        for key in ('rb', 'tb', 'd'):
            match = re.search(r'(?:^|,)' + key + r'(\d+)(?:,|$)', memory[1])
            require(match is not None, 'missing socket memory field ' + key)
            row[key] = int(match[1])
        rows.append(row)
    return rows


def owned(rows, processes):
    ids = set(map(int, processes))
    return [r for r in rows if set(r['pids']) & ids]


def qeli_check(evidence, udp, expected):
    rows = owned(sockets(evidence['ss']), evidence['processes'])
    require(rows, 'no live owned Qeli carrier socket memory evidence')
    if udp:
        require(all(r['rb'] >= 2 * expected for r in rows),
                'Qeli actual UDP receive buffer below requested floor (ss rb must be >= 2*request)')
    return dict(transport='UDP' if udp else 'TCP', sockets=rows,
                receive_floor_bytes=expected if udp else None,
                accounting='Linux ss kernel bytes; UDP explicit request normalized as rb/2')


def iperf_check(observations, direction, expected):
    receiver = 'server' if direction == 'upload' else 'client'
    result = {}
    for role, observation in observations.items():
        samples = [s['udp_memory'] for s in observation['samples'] if 'udp_memory' in s]
        require(len(samples) == 1, 'missing/duplicate live iperf UDP buffer snapshot: ' + role)
        evidence = samples[0]
        rows = owned(sockets(evidence['ss']), evidence['processes'])
        require(rows, 'no owned iperf UDP socket: ' + role)
        require(all(r['rb'] >= expected for r in rows) if role == receiver else True,
                'actual iperf receiver rb below configured floor: ' + role)
        result[role] = dict(receiver=role == receiver, sockets=rows,
                            captured_monotonic=evidence['t'])
    require(set(result) == {'server', 'client'}, 'both iperf endpoints required')
    return result
