#!/usr/bin/env python3
"""Bounded two-guest release benchmark. No hypervisor API, installs or builds."""
import argparse
import configparser
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import statistics
import time
import traceback
import release_short_buffers as buffers

CORE = ('tcp-faketls', 'tcp-reality-tls', 'udp-faketls', 'udp-quic')
MODES = ('tcp-plain-raw', 'tcp-faketls', 'tcp-padding', 'tcp-frag', 'tcp-obfs',
         'tcp-reality', 'tcp-reality-tls', 'udp-faketls', 'udp-padding', 'udp-quic',
         'tcp-obfs-awg', 'udp-faketls-awg')
LOCK = '/run/qeli-release-short.lock'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    for attempt in range(100):
        try:
            tmp.replace(path)
            return
        except PermissionError:
            if attempt == 99:
                raise
            time.sleep(.1)


def configure(server, client, mode, outer, root, policy='required', client_queue=True):
    """Derive isolated configs from operator-supplied credential/identity fixtures."""
    def read(text):
        p = configparser.RawConfigParser()
        p.read_string(text)
        return p
    s, c = read(server), read(client)
    profiles = [section for section in s.sections() if section.startswith('profile:')]
    require(len(profiles) == 1, 'exactly one server profile required')
    p = s[profiles[0]]
    udp = mode.startswith('udp-')
    reality = mode in ('tcp-reality', 'tcp-reality-tls')
    real_tls = mode == 'tcp-reality-tls'
    obfs = mode.startswith('tcp-obfs')
    wire_mode = 'plain' if mode == 'tcp-plain-raw' else 'obfs' if obfs else 'reality-tls' if real_tls else 'fake-tls'
    values = {'bind.address': outer, 'bind.port': '4443' if udp else '443',
              'bind.transport': 'udp' if udp else 'tcp', 'tun.name': 'qelitcp0',
              'tun.tx_queue_len': '1000', 'tun.mtu': '1400', 'obf.mode': wire_mode,
              'obf.recordizer.policy': policy, 'obf.tls.reality_proxy.enabled': str(reality).lower(),
              'obf.tls.reality_proxy.real_tls': str(real_tls).lower(),
              'obf.tls.reality_proxy.handrolled': 'true',
              'obf.padding.enabled': str(mode in ('tcp-padding', 'tcp-frag', 'tcp-obfs', 'udp-padding')).lower(),
              'obf.fragmentation.enabled': str(mode == 'tcp-frag').lower(),
              'obf.traffic_shaping.enabled': str(real_tls).lower(), 'obf.traffic_shaping.stealth': 'false',
              'obf.heartbeat.enabled': 'false', 'obf.quic.enabled': str(mode == 'udp-quic').lower(),
              'obf.awg.enabled': str(mode.endswith('-awg')).lower(),
              'perf.connection.idle_timeout_secs': '300'}
    p.update(values)
    # This is a public test obfuscation key, not the server identity or a production credential.
    if obfs:
        p['obf.obfs_key'] = 'release-short-fixture-only'
    else:
        p.pop('obf.obfs_key', None)
    s['logging']['file'] = root+'/server-runtime.log'
    q = c['qeli']
    q.update(server=('['+outer+']' if ':' in outer else outer)+(':'+values['bind.port']),
             proto=values['bind.transport'], mode=wire_mode, quic=str(mode == 'udp-quic').lower(),
             gateway='false', dns='off', ipv6='required', reconnect='false', dev='vpn0', mtu='1400',
             awg=str(mode.endswith('-awg')).lower())
    if client_queue:
        q['tun.tx_queue_len'] = '1000'
    else:
        q.pop('tun.tx_queue_len', None)
    if obfs:
        q['obfs_key'] = p['obf.obfs_key']
    else:
        q.pop('obfs_key', None)
    if mode.endswith('-awg'):
        q.update(jc='4', jmin='40', jmax='200')
    else:
        for key in ('jc', 'jmin', 'jmax'):
            q.pop(key, None)
    def write(parser):
        out = io.StringIO()
        parser.write(out)
        return out.getvalue()
    return write(s), write(c)


def plan():
    sessions = []
    for policy in ('required', 'off'):
        sessions += [dict(stage='smoke', mode=m, policy=policy, outer=4) for m in MODES]
    sessions += [dict(stage='smoke', mode=m, policy='prefer', outer=4) for m in CORE]
    sessions += [dict(stage='smoke', mode=m, policy='required', outer=6) for m in CORE]
    for side in ('server', 'client'):
        sessions += [dict(stage='compat', mode=m, policy='required', outer=4, previous_side=side) for m in CORE]
    for rep in range(1, 4):
        order = CORE if rep == 1 else tuple(reversed(CORE)) if rep == 2 else CORE[2:]+CORE[:2]
        sessions += [dict(stage='perf', mode=m, policy='required', outer=4, rep=rep) for m in order]
    sessions += [dict(stage='stability', mode=m, policy='required', outer=4) for m in CORE]
    return sessions


def selected_plan(smoke_only=False, mixed_only=False, buffer_pilot=False, buffer_reference=False):
    if buffer_reference:
        return [dict(stage='perf',mode=m,policy='required',outer=4,rep=rep,scope='p4-udp600')
                for rep in range(1,4)
                for m in (CORE if rep==1 else tuple(reversed(CORE)) if rep==2 else CORE[2:]+CORE[:2])]
    if buffer_pilot:
        return [dict(stage='buffer_pilot', mode=m, policy='required', outer=4, rep=1) for m in CORE]
    if mixed_only:
        return [dict(stage='mixed',mode=m,policy='required',outer=4) for m in CORE]
    return [dict(stage='smoke',mode=m,policy='required',outer=4) for m in CORE] if smoke_only else plan()


def tasks(session, rates):
    if session['stage'] == 'buffer_pilot' or session.get('scope') == 'p4-udp600':
        return [dict(family=f, protocol=p, direction=d, streams=4 if p=='TCP' else 1,
                     seconds=10, omit=2, rate_mbps=600 if p=='UDP' else None)
                for f in (4,6) for d in ('upload','download') for p in ('TCP','UDP')]
    if session['stage']=='mixed':
        return [dict(family=f,protocol='MIXED',direction='concurrent',streams=4,seconds=30,omit=2,
                     rate_mbps=rates[session['mode']][0]) for f in (4,6)]
    if session['stage'] in ('smoke', 'compat'):
        return [dict(family=f, protocol=p, direction=d, streams=1, seconds=2, omit=0,
                     rate_mbps=10 if p == 'UDP' else None)
                for f,p,d in ((4,'TCP','upload'),(4,'UDP','download'),
                              (6,'TCP','download'),(6,'UDP','upload'))]
    result = []
    if session['stage'] == 'stability':
        return [dict(family=f, protocol='TCP', direction=d, streams=4, seconds=20, omit=2, rate_mbps=None)
                for f,d in ((4,'upload'),(6,'download'))]
    for f in (4, 6):
        for d in ('upload', 'download'):
            result += [dict(family=f, protocol='TCP', direction=d, streams=p, seconds=10, omit=2,
                            rate_mbps=None) for p in (1, 4)]
            result += [dict(family=f, protocol='UDP', direction=d, streams=1, seconds=10, omit=2,
                            rate_mbps=rate) for rate in rates[session['mode']]]
    return result


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k,v in value.items() if k not in ('valid_life_time','preferred_life_time','expires')}
    if isinstance(value, list):
        return sorted((stable(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def restoration(before, after):
    checks = {k: before[k] == after[k] for k in ('boot_id','protected_files','sysctls','hostname','kernel','cpus')}
    checks['processes'] = not after['processes']
    for k in ('links','addresses','routes4','routes6','rules4','rules6','qdiscs'):
        checks[k] = stable(json.loads(before[k])) == stable(json.loads(after[k]))
    for k in ('iptables','ip6tables'):
        clean = lambda s: '\n'.join(l for l in s.splitlines() if not l.startswith('#'))
        checks[k] = clean(before[k]) == clean(after[k])
    return checks


class Guest:
    def __init__(self, cfg, role, root):
        import paramiko
        self.c = paramiko.SSHClient()
        self.c.load_host_keys(cfg['known_hosts'])
        self.c.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.c.connect(cfg['hosts'][role], username=cfg.get('user','root'),
                       key_filename=cfg['ssh_key'], look_for_keys=False, allow_agent=False, timeout=15)
        self.root, self.role = root, role

    def cmd(self, command, timeout=60):
        _, out, err = self.c.exec_command(command, timeout=timeout)
        text, error = out.read().decode(errors='replace'), err.read().decode(errors='replace')
        require(out.channel.recv_exit_status() == 0, 'guest command failed; inspect retained raw: '+error[-600:])
        return text.strip()

    def get(self, path):
        with self.c.open_sftp() as sf, sf.open(path,'rb') as f:
            return f.read()

    def put(self, path, data, executable=False):
        with self.c.open_sftp() as sf, sf.open(path,'wb') as f:
            f.write(data.encode() if isinstance(data,str) else data)
            sf.chmod(path, 0o700 if executable else 0o600)

    def helper(self, action, *args, timeout=60):
        command = shlex.join(['python3',self.root+'/guest.py',self.root,action,*map(str,args)])
        return json.loads(self.cmd(command, timeout))


def aggregate(rows):
    groups = {}
    for row in rows:
        if row['stage'] != 'perf':
            continue
        key = '/'.join(map(str,(row['mode'],row['family'],row['direction'],row['protocol'],row['streams'],row['rate_mbps'])))
        groups.setdefault(key,[]).append(row)
    result = {}
    for key, values in groups.items():
        speeds = [r['mbps'] for r in values]
        result[key] = dict(n=len(values), median_mbps=statistics.median(speeds), min_mbps=min(speeds),
                           max_mbps=max(speeds), cv_percent=100*statistics.stdev(speeds)/statistics.mean(speeds) if len(speeds)>1 else None,
                           max_loss_percent=max((r['loss_percent'] or 0) for r in values),
                           retransmits=[r['retransmits'] for r in values])
    return result


def execute(cfg, tag, output, smoke_only=False, mixed_only=False, buffer_pilot=False, buffer_reference=False):
    require(sum((smoke_only,mixed_only,buffer_pilot,buffer_reference))<=1,'choose one partial scope')
    require(re.fullmatch(r'[a-z0-9-]{1,55}',tag), 'unsafe tag')
    require(not output.exists(), 'refuse to overwrite results or blindly resume')
    require(set(cfg['hosts']) == {'server','client'} and len(set(cfg['hosts'].values())) == 2, 'two distinct guests required')
    require(set(cfg['udp_rates']) == set(CORE), 'fixed rates for each core profile required')
    for rates in cfg['udp_rates'].values():
        require(len(rates)==2 and all(type(v) is int and v>0 for v in rates) and rates[0]<rates[1], 'two increasing fixed UDP rates required')
    buffer_policy = buffers.policy(cfg.get('udp_buffers'))
    root = '/opt/qeli-release-short-'+tag
    guests, before, locked, created = {}, {}, [], set()
    payload = dict(schema=1, status='running', started_utc=utc(), raw=root, tag=tag,
                   method='qeli-release-short-mixed-v1' if mixed_only else 'qeli-release-short-smoke-v1' if smoke_only else 'qeli-release-short-v1',
                   rates=cfg['udp_rates'], sessions=[], windows=[],
                   plan=selected_plan(smoke_only,mixed_only,buffer_pilot,buffer_reference),
                   buffer_policy=buffer_policy,
                   binary_sha256=cfg['candidate_sha256'], previous_sha256=cfg['previous_sha256'],
                   qualification='MIXED_ONLY' if mixed_only else 'SMOKE_ONLY' if smoke_only else 'PILOT_NO_REGRESSION_BASELINE')
    if buffer_reference:
        payload.update(method='qeli-release-short-buffer-reference-v2', qualification='PERFORMANCE_REFERENCE_CANDIDATE')
    elif buffer_pilot:
        payload.update(method='qeli-release-short-buffer-pilot-v2', qualification='BUFFER_PILOT_ONLY')
    elif not smoke_only and not mixed_only:
        payload['method'] = 'qeli-release-short-v2'
    else:
        payload['method'] = payload['method'].replace('-v1', '-v2')
    atomic(output,payload)
    helper_bytes = Path(__file__).with_name('release_short_guest.py').read_bytes()
    buffer_bytes = Path(__file__).with_name('release_short_buffers.py').read_bytes()
    payload['buffers_sha256'] = digest(buffer_bytes)
    payload['helper_sha256'] = digest(helper_bytes)
    controller_bytes = Path(__file__).read_bytes()
    payload['controller_sha256'] = digest(controller_bytes)
    def checkpoint(current):
        payload['current'] = current
        atomic(output,payload)
        print(json.dumps(dict(current=current, windows=len(payload['windows']), utc=utc())),flush=True)
    def both(action,*args):
        with ThreadPoolExecutor(max_workers=2) as pool:
            return dict(zip(guests,pool.map(lambda g:g.helper(action,*args),guests.values())))
    def stop():
        both('halt')
        # Link deletion is owned by Qeli rollback; never delete an arbitrary interface here.
        for g in guests.values():
            require(g.cmd('ip -j link show type tun') == '[]','TUN remained after owned stop')
    def start(session, label):
        both('buffer-guard')
        stop()
        outer = cfg['outer_server'][str(session['outer'])]
        previous_side = session.get('previous_side')
        server, client = configure(base['server'],base['client'],session['mode'],outer,root,
                                   session['policy'],client_queue=previous_side!='client')
        configs = {'server':server,'client':client}
        logs = {}
        for role,g in guests.items():
            configs_path = root+'/configs/'+label+'-'+role+'.conf'
            g.put(configs_path,configs[role])
            g.put(root+'/'+role+'.conf',configs[role])
            binary = cfg['previous_binary'][role] if role == previous_side else root+'/qeli-'+role
            # Launch helper uses fixed private path. Swap only our private copy for compatibility.
            if role == previous_side:
                g.cmd('cp -- '+shlex.quote(binary)+' '+root+'/qeli-'+role)
            else:
                g.cmd('cp -- '+root+'/candidate '+root+'/qeli-'+role)
            g.cmd(root+'/qeli-'+role+' check-config --config '+root+'/'+role+'.conf') if role=='server' else None
            logs[role] = label+'-'+role
        guests['server'].helper('launch','server',logs['server'])
        # Supervisor startup includes config/identity work; never race a fixed sleep.
        for _ in range(120):
            listener = guests['server'].cmd('ss -H -lnut sport = :'+('4443' if session['mode'].startswith('udp-') else '443'))
            if listener:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('server listener did not become ready: '+label)
        guests['client'].helper('launch','client',logs['client'])
        for _ in range(120):
            c_log = guests['client'].get(root+'/'+logs['client']+'.log').decode(errors='replace')
            try:
                links = json.loads(guests['client'].cmd('ip -j link show dev vpn0'))
                if links and 'UP' in links[0]['flags']:
                    break
            except RuntimeError:
                pass
            time.sleep(.25)
        else:
            raise RuntimeError('TUN startup failed: '+label+'; inspect session log, not previous logs')
        active = 'PACKET_MUX_V1 active' in c_log
        require(active if session['policy'] != 'off' else ('legacy packet-per-record' in c_log and not active), 'datapath marker mismatch '+label)
        if session['mode']=='tcp-reality-tls':
            require('genuine HTTP/2 stream' in c_log,'genuine H2 absent')
        for family,target in ((4,cfg['inner_server']['4']),(6,cfg['inner_server']['6'])):
            guests['client'].cmd(f'ping -{family} -c 1 -W 3 '+shlex.quote(target))
        # Peer/socket address proves outer family independently of inner ping.
        socket_text = guests['client'].cmd('ss -H -ntup')
        require(outer in socket_text,'configured outer peer not found in socket evidence')
        slinks = json.loads(guests['server'].cmd('ip -j link show dev qelitcp0'))
        require(slinks[0]['txqlen']==1000,'server queue changed')
        if previous_side!='client':
            require(links[0]['txqlen']==1000,'client queue not 1000')
        payload['sessions'].append(dict(**session,label=label, recordizer_active=active,
                                         client_qlen=links[0]['txqlen'],server_qlen=slinks[0]['txqlen'],
                                         config_sha256={r:digest(t.encode()) for r,t in configs.items()},outer_peer_verified=True))
        memory = both('socket-memory', 'UDP' if session['mode'].startswith('udp-') else 'TCP')
        for role, value in memory.items():
            guests[role].put(root+'/configs/'+label+'-'+role+'-sockets.json', json.dumps(value,indent=2))
        payload['sessions'][-1]['buffers'] = {r:buffers.qeli_check(v,session['mode'].startswith('udp-'),
            buffer_policy['qeli_receive_bytes']) for r,v in memory.items()}
    def window(spec, label, meta, direct=False):
        both('buffer-guard')
        checkpoint(label)
        f = spec['family']
        spec = dict(spec,label=label,target=(cfg['outer_server'] if direct else cfg['inner_server'])[str(f)],port=5201 if f==4 else 5202)
        for g in guests.values():
            g.cmd('mkdir -m 700 '+root+'/windows/'+label)
            if spec['protocol'] in ('UDP','MIXED'):
                g.put(root+'/windows/'+label+'/udp-buffer-check','1')
        ports=(5201,5202) if spec['protocol']=='MIXED' else (spec['port'],)
        for port in ports:
            guests['server'].helper('listen','iperf-'+label+'-'+str(port),f,spec['target'],port)
            for _ in range(40):
                if guests['server'].cmd('ss -H -lnt sport = :'+str(port)):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('iperf listener not ready')
        for role,g in guests.items():
            iface = cfg['outer_iface'][role] if direct else 'vpn0' if role=='client' else 'qelitcp0'
            g.helper('watch-start',label,iface,spec['seconds']+spec['omit']+40)
        try:
            for g in guests.values():
                for _ in range(50):
                    if g.cmd('test -e '+root+'/windows/'+label+'/ready && echo ready || true'):
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('observer not ready')
            row = guests['client'].helper('measure-mixed' if spec['protocol']=='MIXED' else 'measure',json.dumps(spec),timeout=spec['seconds']+spec['omit']+35)
            payload['windows'].append(dict(**row,**meta))
            if meta['stage'] in ('smoke','compat') and spec['protocol']=='UDP':
                require(row['loss_percent'] is not None and row['loss_percent']<=1,'functional UDP loss exceeds budget')
        finally:
            both('watch-stop',label)
        if spec['protocol'] in ('UDP','MIXED'):
            observations = {r:json.loads(g.get(root+'/windows/'+label+'/observations.json')) for r,g in guests.items()}
            check = buffers.iperf_check(observations, 'upload' if spec['protocol']=='MIXED' else spec['direction'],
                                        buffer_policy['iperf_receive_rb_bytes'])
            row['iperf_buffers'] = check
            payload['windows'][-1]['iperf_buffers'] = check
        if not direct:
            session = next(s for s in payload['sessions'] if s['label']==meta['session'])
            memory = both('socket-memory', 'UDP' if session['mode'].startswith('udp-') else 'TCP')
            for role, value in memory.items():
                guests[role].put(root+'/windows/'+label+'/'+role+'-qeli-sockets.json', json.dumps(value,indent=2))
            payload['windows'][-1]['qeli_buffers'] = {r:buffers.qeli_check(v,session['mode'].startswith('udp-'),
                buffer_policy['qeli_receive_bytes']) for r,v in memory.items()}
        # Reap only registered iperf/observers, not the two VPN groups.
        # Finished children have receipts until session halt; labels are globally unique.
        return row
    def baseline(phase):
        stop()
        for rep in range(1,2 if buffer_pilot else 4):
            for f in (4,6):
                for d in ('upload','download'):
                    window(dict(family=f,protocol='TCP',direction=d,streams=1,seconds=10,omit=2,rate_mbps=None),
                           f'baseline-{phase}-{rep}-{f}-{d}',dict(stage='baseline',phase=phase,rep=rep),True)
        stop()
    try:
        for role in ('server','client'):
            g = guests[role] = Guest(cfg,role,root)
            g.cmd('mkdir -m 700 '+LOCK)
            locked.append(role)
            g.cmd('test ! -e '+root+' && mkdir -m 700 '+root+' '+root+'/owned '+root+'/state '+root+'/configs '+root+'/windows')
            created.add(role)
            g.put(root+'/guest.py',helper_bytes)
            g.put(root+'/release_short_buffers.py',buffer_bytes)
            g.put(root+'/controller.py',controller_bytes)
            # Old raw is deliberately retained. Hashing that archive can take
            # minutes; this is outside traffic and before the mutation lease.
            snap = before[role] = g.helper('snapshot', timeout=900)
            require(not snap['processes'],'guest has VPN/iperf/build/emulator processes; refuse to disturb')
            require(g.cmd('ip -j link show type tun')=='[]','existing TUN; refuse to disturb')
            require(snap['hostname']==cfg['hostnames'][role],'wrong guest identity')
            require('netem' not in snap['qdiscs'],'netem not allowed')
            require(int(g.cmd("df --output=avail -B1 /opt | tail -1"))>1024**3,'low guest disk space')
            g.put(root+'/before.json',json.dumps(snap,indent=2))
            require(g.cmd('sha256sum '+shlex.quote(cfg['previous_binary'][role])).split()[0]==cfg['previous_sha256'],'previous SHA mismatch')
        source = guests['client'].get(cfg['candidate_source'])
        require(digest(source)==cfg['candidate_sha256'],'candidate SHA mismatch')
        for role,g in guests.items():
            g.put(root+'/candidate',source,True)
            g.put(root+'/qeli-'+role,source,True)
        base = {r:guests[r].get(cfg['fixture'][r]).decode() for r in guests}
        payload['fixture_sha256'] = {r:digest(t.encode()) for r,t in base.items()}
        both('lease-start')
        payload['buffer_setup'] = both('buffer-prepare', json.dumps(cfg['udp_buffers']))
        checkpoint('prepared')
        if buffer_pilot:
            baseline('before')
        for index,session in enumerate(payload['plan']):
            if session['stage']=='perf' and session['rep']==1 and session['mode']==CORE[0]:
                baseline('before')
            label = f's{index:02d}-{session["stage"]}-{session["mode"]}-{session["policy"]}'
            checkpoint(label)
            start(session,label)
            for j,spec in enumerate(tasks(session,cfg['udp_rates'])):
                window(spec,label+f'-w{j:02d}',dict(stage=session['stage'],mode=session['mode'],
                        rep=session.get('rep'),session=label))
            stop()
        if not smoke_only and not mixed_only:
            baseline('after')
        payload['aggregates'] = aggregate(payload['windows'])
        require(len(payload['sessions'])==len(payload['plan']),'missing session')
        require(len(payload['aggregates'])==(0 if smoke_only or mixed_only or buffer_pilot else 32 if buffer_reference else 64) and all(g['n']==3 for g in payload['aggregates'].values()),'incomplete performance coverage')
        if buffer_reference:
            require(len(payload['windows'])==120, 'incomplete buffer reference')
        if buffer_pilot:
            require(len(payload['windows'])==40, 'incomplete buffer pilot')
        flat=[r for w in payload['windows'] for r in w.get('results',[w])]
        require(len({r['cookie'] for r in flat})==len(flat),'duplicate iperf cookie')
        udp_failed = [k for k,v in payload['aggregates'].items() if '/UDP/' in k and v['max_loss_percent']>1]
        if buffer_pilot:
            udp_failed = [w['label'] for w in payload['windows'] if w['protocol']=='UDP' and w['loss_percent']>1]
        payload['udp_failed_groups']=udp_failed
        if mixed_only:
            payload['mixed_loss_warnings']=[r['label'] for r in flat if r['protocol']=='UDP' and r['loss_percent']>1]
        payload['status']='complete' if not udp_failed else 'measurements_complete_udp_failed'
    except BaseException as exc:
        payload.update(status='failed',error=str(exc),traceback=traceback.format_exc())
        raise
    finally:
        payload['restoration'] = {}
        # Roll back BOTH guests before expensive protected-file hashing. The
        # lease is a fallback for controller death, not a replacement for finally.
        for role,g in guests.items():
            if role in created:
                for action in ('halt','buffer-restore','lease-stop'):
                    try:
                        g.helper(action)
                    except BaseException as exc:
                        payload.setdefault('cleanup_errors',{}).setdefault(role,{})[action]=str(exc)
        for role,g in guests.items():
            try:
                # Never invoke a helper or write a result in a pre-existing run root.
                if role in created:
                    g.helper('halt')
                    time.sleep(.5)
                if role in before and role in created:
                    g.helper('restore-empty-ip6')
                    after = g.helper('snapshot', timeout=900)
                    g.put(root+'/after.json',json.dumps(after,indent=2))
                    payload['restoration'][role]=restoration(before[role],after)
                    require(all(payload['restoration'][role].values()),'state restoration mismatch')
            except BaseException as exc:
                payload['restoration'][role] = dict(error=str(exc))
                payload['status']='restoration_failed'
        payload['finished_utc']=utc()
        if payload.get('cleanup_errors'):
            payload['status']='restoration_failed'
        atomic(output,payload)
        for g in guests.values():
            try:
                if g.role in created:
                    g.put(root+'/result.json',json.dumps(payload,indent=2))
                if g.role in locked:
                    g.cmd('rmdir '+LOCK)
            finally:
                g.c.close()
        print(json.dumps(dict(status=payload['status'],windows=len(payload['windows']),restoration=payload['restoration'])),flush=True)
    require(payload['status']=='complete','measurements or restoration failed; inspect preserved receipt')


def main():
    def terminate(signum, frame):
        raise KeyboardInterrupt('controller termination requested')
    signal.signal(signal.SIGTERM,terminate)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True,help='private local JSON; credentials never included in public result')
    p.add_argument('--tag',required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--plan-only',action='store_true')
    p.add_argument('--smoke-only',action='store_true',help='four functional core profiles only; cannot qualify a release')
    p.add_argument('--mixed-only',action='store_true',help='separate short simultaneous TCP/UDP check after full-plan cleanup')
    p.add_argument('--buffer-pilot',action='store_true',help='40 windows, four required profiles n=1; harness validation, NOT release qualification')
    p.add_argument('--buffer-reference',action='store_true',help='120 windows: four required profiles, TCP P4/UDP600 n=3 plus n=3 baseline; performance reference only')
    a=p.parse_args()
    cfg=json.loads(a.config.read_text(encoding='utf-8'))
    require(sum((a.smoke_only,a.mixed_only,a.buffer_pilot,a.buffer_reference))<=1,'choose one partial scope')
    if a.plan_only:
        buffers.policy(cfg.get('udp_buffers'))
        sessions=selected_plan(a.smoke_only,a.mixed_only,a.buffer_pilot,a.buffer_reference)
        count=sum(len(tasks(s,cfg['udp_rates'])) for s in sessions)+(0 if a.smoke_only or a.mixed_only else 8 if a.buffer_pilot else 24)
        print(json.dumps(dict(sessions=sessions,windows=count,iperf_measurements=count*(2 if a.mixed_only else 1)),indent=2))
    else:
        execute(cfg,a.tag,a.output,a.smoke_only,a.mixed_only,a.buffer_pilot,a.buffer_reference)


if __name__=='__main__':
    main()
