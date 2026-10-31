#!/usr/bin/env python3
"""Fetch only test metadata from the guests; raw remains in the private run roots."""
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics as st

from release_short_test import Guest, aggregate, atomic, require
import release_short_buffers as buffers


def distribution(values):
    values=sorted(values)
    if not values:
        return None
    return dict(n=len(values),median=st.median(values),p95=values[math.ceil(.95*len(values))-1],
                min=min(values),max=max(values))


def sockets(text):
    rows=[]
    row=None
    for line in text.splitlines():
        m=re.match(r'^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)',line)
        if m:
            local,lp=m[3].rsplit(':',1)
            peer,pp=m[4].rsplit(':',1)
            local,peer=local.strip('[]'),peer.strip('[]')
            ipaddress.ip_address(local)
            ipaddress.ip_address(peer)
            row=dict(recvq=int(m[1]),sendq=int(m[2]),local=local,peer=peer,
                     local_port=int(lp),peer_port=int(pp),body='')
            rows.append(row)
        elif row is not None:
            row['body']+=' '+line.strip()
    for row in rows:
        for key in ('rtt','cwnd','bytes_sent','bytes_received','bytes_retrans','snd_wnd','unacked','notsent'):
            match=re.search(r'(?:^|\s)'+key+r':(\d+(?:\.\d+)?)',row['body'])
            if match:
                row[key]=float(match[1])
        memory=re.search(r'skmem:\(([^)]+)\)',row['body'])
        if memory:
            for key in ('rb','tb'):
                match=re.search(r'(?:^|,)'+key+r'(\d+)(?:,|$)',memory[1])
                if match:row[key]=int(match[1])
        row.pop('body')
    return rows


def metrics(observation, row, role):
    require(observation['status']=='complete','incomplete observation')
    samples=observation['samples']
    require(len(samples)>=2,'too few observation samples')
    first,last=samples[0],samples[-1]
    a,b=first['link'],last['link']
    require(a['ifindex']==b['ifindex'] and a['txqlen']==b['txqlen'],'interface changed inside window')
    stats='stats64' if 'stats64' in a else 'stats'
    count=lambda link,key: link[stats]['tx'][key]
    packets=count(b,'packets')-count(a,'packets')
    drops=count(b,'dropped')-count(a,'dropped')
    require(packets>=0 and drops>=0,'counter reset')
    elapsed=last['t']-first['t']
    require(elapsed>0,'zero observation duration')
    require(set(first['processes'])==set(last['processes']),'VPN process group changed')
    ticks=0
    for pid,p in first['processes'].items():
        end=last['processes'][pid]
        require(end['start']==p['start'],'PID reuse in observation')
        ticks+=end['ticks']-p['ticks']
    cpu=[b-a for a,b in zip(first['cpu'],last['cpu'])]
    total=sum(cpu)
    qdrops=lambda sample:sum(q.get('drops',0) for q in sample['qdisc'])
    inner,outer,receiver_sockets=[],[],[]
    sender='client' if row['direction']=='upload' else 'server'
    for sample in samples:
        # TCP_INFO samples during measurement, excluding most warm-up and tail.
        if sample['t']<first['t']+row['omit']+.3 or sample['t']>last['t']-.2:
            continue
        for sock in sockets(sample['ss']):
            if sock['local_port'] in (5201,5202) or sock['peer_port'] in (5201,5202):
                if role==sender and sock.get('bytes_sent',0)>1e6:
                    inner.append(sock)
                if role!=sender and sock.get('bytes_received',0)>1e6:
                    receiver_sockets.append(sock)
            else:
                outer.append(sock)
    dist=lambda rows,key:distribution([s[key] for s in rows if key in s])
    def udp4(text):
        lines=[l.split()[1:] for l in text.splitlines() if l.startswith('Udp:')]
        require(len(lines)==2,'missing IPv4 UDP counters')
        return {k:int(v) for k,v in zip(*lines)}
    udp_before,udp_after=udp4(first['snmp']),udp4(last['snmp'])
    udp6_delta=None
    if 'snmp6' in first and 'snmp6' in last:
        parse6=lambda text:{l.split()[0]:int(l.split()[1]) for l in text.splitlines() if l.startswith('Udp6')}
        a6,b6=parse6(first['snmp6']),parse6(last['snmp6'])
        udp6_delta={k:b6[k]-a6[k] for k in a6}
    return dict(tun_qlen=a['txqlen'],mtu=a['mtu'],tun_tx_packets=packets,tun_tx_drops=drops,
                tun_drop_ppm=1e6*drops/max(1,packets+drops),qdisc_drops=qdrops(last)-qdrops(first),
                cpu_one_core_percent=100*ticks/observation['clock_ticks']/elapsed,
                vm_cpu_percent=100*(total-cpu[3]-cpu[4]-cpu[7])/max(1,total),
                vm_steal_percent=100*cpu[7]/max(1,total),
                rss_peak_kib=max(sum(p['rss_kib'] for p in s['processes'].values()) for s in samples),
                sampled_seconds=elapsed,inner_rtt_ms=dist(inner,'rtt'),inner_cwnd_mss=dist(inner,'cwnd'),
                inner_sendq_bytes=dist(inner,'sendq'),outer_rtt_ms=dist(outer,'rtt'),
                iperf_tcp_receiver_rb_bytes=dist(receiver_sockets,'rb'),
                iperf_tcp_receiver_tb_bytes=dist(receiver_sockets,'tb'),
                outer_sendq_bytes=dist(outer,'sendq'),full_ring=None,
                kernel_udp4_delta={k:udp_after[k]-udp_before[k] for k in udp_before},kernel_udp6_delta=udp6_delta)


def baseline(rows):
    values={}
    for family in (4,6):
        for direction in ('upload','download'):
            data={}
            for phase in ('before','after'):
                speeds=[r['mbps'] for r in rows if r['stage']=='baseline' and r['phase']==phase
                        and r['family']==family and r['direction']==direction]
                require(len(speeds)==3,'incomplete baseline')
                data[phase]=dict(median_mbps=st.median(speeds),cv_percent=100*st.stdev(speeds)/st.mean(speeds))
            data['drift_percent']=100*(data['after']['median_mbps']/data['before']['median_mbps']-1)
            values[str(family)+'/'+direction]=data
    return values


def compare(candidate, reference):
    require(candidate['method']==reference['method'] and candidate['rates']==reference['rates'],'reference method/rates differ')
    require(candidate['environment']==reference['environment'],'reference kernel/resources/hostnames differ')
    require(candidate['source_hashes']==reference['source_hashes'],'measurement harness changed; establish a fresh reference')
    require(candidate.get('buffer_policy')==reference.get('buffer_policy'),'reference socket buffer policy differs')
    require(candidate['performance_fixture_sha256']==reference['performance_fixture_sha256'],'reference performance config differs')
    require(reference['measurement_status']=='VALID','reference not valid')
    require(not reference['udp_failed_groups'] and not reference['unstable_groups'],'reference has failed/unstable cells')
    require(not candidate['udp_failed_groups'] or candidate['measurement_status']=='VALID','candidate baseline invalid')
    out={}
    for key,current in candidate['aggregates'].items():
        previous=reference['aggregates'][key]
        require(current['n']==previous['n']==3,'three repeats required')
        out[key]=dict(throughput_delta_percent=100*(current['median_mbps']/previous['median_mbps']-1),
                      candidate_cv=current['cv_percent'],reference_cv=previous['cv_percent'],
                      udp_max_loss_percent=current['max_loss_percent'])
    return out


def aggregate_metrics(rows):
    groups={}
    for row in rows:
        if row['stage']!='perf':
            continue
        key='/'.join(map(str,(row['mode'],row['family'],row['direction'],row['protocol'],row['streams'],row['rate_mbps'])))
        groups.setdefault(key,[]).append(row)
    results={}
    for key,values in groups.items():
        result={}
        for role in ('server','client'):
            ms=[r['metrics'][role] for r in values]
            result[role]={field:st.median(m[field] for m in ms) for field in
                          ('cpu_one_core_percent','vm_cpu_percent','rss_peak_kib','tun_drop_ppm','tun_tx_drops','qdisc_drops')}
            result[role]['cpu_percent_per_mbps']=st.median(r['metrics'][role]['cpu_one_core_percent']/r['mbps'] for r in values)
        sender='client' if values[0]['direction']=='upload' else 'server'
        for field in ('inner_rtt_ms','inner_cwnd_mss','outer_rtt_ms'):
            present=[r['metrics'][sender][field] for r in values if r['metrics'][sender][field]]
            result[field]={name:st.median(m[name] for m in present) for name in ('median','p95')} if present else None
        results[key]=result
    return results


def review_warnings(candidate, reference):
    """Warnings request human review, never assert a cause from counter correlation."""
    warnings=[]
    for key,current in candidate['metric_aggregates'].items():
        previous=reference['metric_aggregates'][key]
        if current['inner_rtt_ms'] and previous['inner_rtt_ms']:
            old,new=previous['inner_rtt_ms']['p95'],current['inner_rtt_ms']['p95']
            if new-old>max(2,.2*old):
                warnings.append(dict(cell=key,metric='sampled_inner_rtt_p95_ms',previous=old,candidate=new))
        for role in ('server','client'):
            for field,factor,absolute in (('cpu_percent_per_mbps',1.15,0),('rss_peak_kib',1.2,10*1024),
                                          ('tun_drop_ppm',2,1000)):
                old,new=previous[role][field],current[role][field]
                if new>factor*old and new-old>absolute:
                    warnings.append(dict(cell=key,role=role,metric=field,previous=old,candidate=new))
    return warnings


def validate_mixed(value, main):
    version='v2' if main.get('method')=='qeli-release-short-v2' else 'v1'
    require(value['method']=='qeli-release-short-mixed-'+version and value['status']=='complete','mixed run incomplete')
    require(value.get('buffer_policy')==main.get('buffer_policy'),'mixed buffer policy differs')
    if version=='v2':
        require(all(value[k]==main[k] for k in ('helper_sha256','controller_sha256','buffers_sha256')),
                'mixed measurement/checker source differs')
    require(value['binary_sha256']==main['binary_sha256'] and value['rates']==main['rates'],'mixed artifact/rates mismatch')
    require(value['started_utc']>=main['finished_utc'],'mixed run overlapped full controller')
    require(len(value['sessions'])==4 and len(value['windows'])==8,'mixed coverage incomplete')
    require(set(value['restoration'])=={'server','client'} and all(all(v is True for v in c.values()) for c in value['restoration'].values()),'mixed restoration failed')
    cells=set()
    warnings=[]
    cookies=[]
    for w in value['windows']:
        require(w['stage']=='mixed' and w['overlap_seconds']>=27,'not a concurrent mixed window')
        cells.add((w['mode'],w['family']))
        require(len(w['results'])==2,'missing mixed stream')
        require({(r['protocol'],r['direction'],r['streams']) for r in w['results']}=={('TCP','download',4),('UDP','upload',1)},'wrong mixed workload')
        for row in w['results']:
            require(row['seconds']==30 and row['omit']==2 and row['mbps']>0 and math.isfinite(row['mbps']),'bad mixed measurement')
            cookies.append(row['cookie'])
            if row['protocol']=='UDP':
                require(row['rate_mbps']==main['rates'][w['mode']][0] and math.isfinite(row['loss_percent']),'mixed UDP rate/loss mismatch')
                if row['loss_percent']>1:
                    warnings.append(row['label'])
    from release_short_test import CORE
    require(cells=={(m,f) for m in CORE for f in (4,6)} and len(set(cookies))==16,'mixed coverage/cookie mismatch')
    return warnings


def reference_qualification(evidence):
    """A limited performance reference must never become full release admission."""
    from release_short_test import CORE
    expected={(m,f,d,p,4 if p=='TCP' else 1,None if p=='TCP' else 600,r)
              for m in CORE for f in (4,6) for d in ('upload','download')
              for p in ('TCP','UDP') for r in (1,2,3)}
    rows=[w for w in evidence['windows'] if w['stage']=='perf']
    actual=[(w['mode'],w['family'],w['direction'],w['protocol'],w['streams'],w['rate_mbps'],w['rep']) for w in rows]
    require(len(actual)==len(set(actual))==96 and set(actual)==expected,
            'reference cells/repetition identities incomplete')
    require(all(w['seconds']==10 and w['omit']==2 for w in rows),'reference workload changed')
    baselines=[w for w in evidence['windows'] if w['stage']=='baseline']
    identity=lambda w:(w['family'],w['direction'],w['phase'],w['rep'])
    expected_baseline={(f,d,p,r) for f in (4,6) for d in ('upload','download')
                       for p in ('before','after') for r in (1,2,3)}
    require(len(baselines)==24 and {identity(w) for w in baselines}==expected_baseline,
            'reference baseline identities incomplete')
    require(all(w['protocol']=='TCP' and w['streams']==1 and w['seconds']==10 and w['omit']==2
                for w in baselines),'reference baseline workload changed')
    sessions=evidence['sessions']
    require(len(sessions)==12 and {(s['mode'],s['rep']) for s in sessions}=={(m,r) for m in CORE for r in (1,2,3)},
            'reference session coverage incomplete')
    require(all(s['policy']=='required' and s['recordizer_active'] and s['outer']==4 for s in sessions),
            'reference requires actual Recordizer and outer IPv4')
    require(len(evidence['aggregates'])==32 and all(v['n']==3 for v in evidence['aggregates'].values()),
            'incomplete repeated reference coverage')
    baseline_values=baseline(evidence['windows'])
    invalid=any(abs(b['drift_percent'])>5 or any(b[p]['cv_percent']>5 for p in ('before','after')) for b in baseline_values.values())
    if invalid or evidence['measurement_status']!='VALID':
        return 'INVALID_BASELINE'
    unstable=any(v['cv_percent'] is None or not math.isfinite(v['cv_percent']) or v['cv_percent']>5 for v in evidence['aggregates'].values())
    lost=any(w['protocol']=='UDP' and w['loss_percent']>1 for w in rows)
    return 'PERFORMANCE_REFERENCE_REVIEW_REQUIRED' if unstable or lost or evidence['udp_failed_groups'] or evidence['unstable_groups'] else 'PERFORMANCE_REFERENCE_ACCEPTED'


def collect(cfg, result, output, reference=None, mixed_result=None):
    require(not output.exists(),'refuse to overwrite analysis')
    raw_bytes=result.read_bytes()
    raw=json.loads(raw_bytes)
    reference_scope=raw['method']=='qeli-release-short-buffer-reference-v2'
    require(raw['method'] in ('qeli-release-short-v1','qeli-release-short-v2','qeli-release-short-buffer-reference-v2'),'smoke/debug/buffer-pilot runs cannot qualify the full plan')
    if reference_scope:
        require(reference is None and mixed_result is None,'performance reference scope is standalone; not a full release comparison')
    checked_buffers=raw['method']!='qeli-release-short-v1'
    if checked_buffers:
        buffers.policy({k:v for k,v in raw['buffer_policy'].items() if k!='version'})
        require(raw['buffer_policy']['version']==buffers.VERSION,'unsupported buffer policy version')
    require(raw['status'] in ('complete','measurements_complete_udp_failed'),'run incomplete; retain FAIL')
    require(set(raw['restoration'])=={'server','client'} and all(all(v is True for v in c.values()) for c in raw['restoration'].values()),'restoration incomplete')
    require(len(raw['windows'])==(120 if reference_scope else 384) and len(raw['sessions'])==(12 if reference_scope else 56),'coverage mismatch')
    guests={r:Guest(cfg,r,raw['raw']) for r in ('server','client')}
    evidence=dict(schema=1,method=raw['method'],rates=raw['rates'],raw=raw['raw'],
                  binary_sha256=raw['binary_sha256'],run_receipt_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                  analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  started_utc=raw['started_utc'],finished_utc=raw['finished_utc'],
                  windows=[],sessions=raw['sessions'],restoration=raw['restoration'],
                  environment={},performance_fixture_sha256={})
    evidence['source_hashes']={}
    evidence['buffer_status']='VERIFIED' if checked_buffers else 'NOT_MEASURED_LEGACY'
    evidence['buffer_policy']=raw.get('buffer_policy')
    try:
        for role,g in guests.items():
            require(g.cmd('sha256sum '+raw['raw']+'/candidate').split()[0]==raw['binary_sha256'],'private candidate changed')
            require(g.cmd('sha256sum '+raw['raw']+'/qeli-'+role).split()[0]==raw['binary_sha256'],'final active copy changed')
            require(g.cmd('sha256sum '+cfg['previous_binary'][role]).split()[0]==raw['previous_sha256'],'old artifact changed')
            helper=g.get(raw['raw']+'/guest.py')
            require(hashlib.sha256(helper).hexdigest()==raw['helper_sha256'],'measured helper changed')
            controller=g.get(raw['raw']+('/controller.py' if raw.get('controller_sha256') else '/release_short_test.py'))
            if raw.get('controller_sha256'):
                require(hashlib.sha256(controller).hexdigest()==raw['controller_sha256'],'measured controller changed')
            evidence['source_hashes'][role]=dict(measured_helper_sha256=raw['helper_sha256'],
                                                 measured_controller_sha256=hashlib.sha256(controller).hexdigest())
            if checked_buffers:
                require(hashlib.sha256(g.get(raw['raw']+'/release_short_buffers.py')).hexdigest()==raw['buffers_sha256'], 'buffer checker changed')
                evidence['source_hashes'][role]['buffers_sha256']=raw['buffers_sha256']
                for session in raw['sessions']:
                    value=json.loads(g.get(raw['raw']+'/configs/'+session['label']+'-'+role+'-sockets.json'))
                    actual=buffers.qeli_check(value,session['mode'].startswith('udp-'),raw['buffer_policy']['qeli_receive_bytes'])
                    require(actual==session['buffers'][role], 'Qeli buffer receipt differs from raw')
            before=json.loads(g.get(raw['raw']+'/before.json'))
            evidence['environment'][role]={k:before[k] for k in ('hostname','kernel','cpus')}
            cpuinfo=g.cmd('cat /proc/cpuinfo')
            evidence['environment'][role].update(
                cpu_models=sorted({l.split(':',1)[1].strip() for l in cpuinfo.splitlines() if l.startswith('model name')}),
                memory_kib=int(g.cmd("awk '/MemTotal/{print $2}' /proc/meminfo")),
                iperf_version=g.cmd('iperf3 --version').splitlines()[0],
                qdiscs=json.loads(before['qdiscs']),sysctls=before['sysctls'],
                links=[{k:l[k] for k in ('ifname','mtu','qdisc','txqlen') if k in l} for l in json.loads(before['links'])])
            # Root-dependent log paths are not a semantic fixture difference.
            signatures={}
            for session in raw['sessions']:
                if session['stage']=='perf':
                    text=g.get(raw['raw']+'/configs/'+session['label']+'-'+role+'.conf').decode()
                    signature=hashlib.sha256(text.replace(raw['raw'],'/RUN').encode()).hexdigest()
                    require(session['mode'] not in signatures or signatures[session['mode']]==signature,
                            'performance configuration changed between repetitions')
                    signatures[session['mode']]=signature
            evidence['performance_fixture_sha256'][role]=signatures
        for index,row in enumerate(raw['windows']):
            require(math.isfinite(row['mbps']) and row['mbps']>0,'invalid saved goodput')
            if row['protocol']=='UDP':
                require(row['loss_percent'] is not None and math.isfinite(row['loss_percent'])
                        and 0<=row['loss_percent']<=100,'invalid saved UDP loss')
                if row['stage'] in ('smoke','compat'):
                    require(row['loss_percent']<=1,'functional UDP budget failed')
            observations={}
            socket_observations={}
            for role,g in guests.items():
                content=g.get(raw['raw']+'/windows/'+row['label']+'/observations.json')
                socket_observations[role]=json.loads(content)
                observations[role]=metrics(socket_observations[role],row,role)
                if checked_buffers and row['protocol']=='TCP' and role==('server' if row['direction']=='upload' else 'client'):
                    require(all(observations[role][key] is not None for key in ('iperf_tcp_receiver_rb_bytes','iperf_tcp_receiver_tb_bytes')),
                            'missing live TCP receiver buffer evidence')
                if checked_buffers and row['stage']!='baseline':
                    session=next(s for s in raw['sessions'] if s['label']==row['session'])
                    value=json.loads(g.get(raw['raw']+'/windows/'+row['label']+'/'+role+'-qeli-sockets.json'))
                    require(buffers.qeli_check(value,session['mode'].startswith('udp-'),raw['buffer_policy']['qeli_receive_bytes'])==row['qeli_buffers'][role], 'window Qeli buffer receipt differs from raw')
                if row['stage']=='perf':
                    require(observations[role]['tun_qlen']==1000 and observations[role]['mtu']==1400,
                            'performance queue/MTU mismatch')
            if checked_buffers and row['protocol']=='UDP':
                require(buffers.iperf_check(socket_observations,row['direction'],raw['buffer_policy']['iperf_receive_rb_bytes'])==row['iperf_buffers'], 'iperf buffer receipt differs from raw')
            evidence['windows'].append(dict(**row,metrics=observations))
            if index%48==0:
                print('metadata',index,'/',len(raw['windows']),flush=True)
    finally:
        for g in guests.values():
            g.c.close()
    evidence['aggregates']=aggregate(evidence['windows'])
    evidence['metric_aggregates']=aggregate_metrics(evidence['windows'])
    evidence['baseline']=baseline(evidence['windows'])
    invalid=any(abs(b['drift_percent'])>5 or any(b[p]['cv_percent']>5 for p in ('before','after')) for b in evidence['baseline'].values())
    evidence['measurement_status']='INVALID_BASELINE' if invalid else 'VALID'
    evidence['udp_failed_groups']=[k for k,v in evidence['aggregates'].items() if '/UDP/' in k and v['max_loss_percent']>1]
    evidence['unstable_groups']=[k for k,v in evidence['aggregates'].items() if v['cv_percent']>5]
    evidence['qualification']='PILOT_NO_REGRESSION_BASELINE'
    evidence['mixed_status']='NOT_RUN'
    if mixed_result:
        mixed_bytes=mixed_result.read_bytes()
        mix=json.loads(mixed_bytes)
        evidence['mixed_warnings']=validate_mixed(mix,raw)
        evidence['mixed_status']='NEEDS_REVIEW' if evidence['mixed_warnings'] else 'VALID'
        evidence['mixed']=dict(raw=mix['raw'],receipt_sha256=hashlib.sha256(mixed_bytes).hexdigest(),
                               windows=mix['windows'],sessions=mix['sessions'],restoration=mix['restoration'])
        mixed_guests={r:Guest(cfg,r,mix['raw']) for r in ('server','client')}
        try:
            for role,g in mixed_guests.items():
                if checked_buffers:
                    require(hashlib.sha256(g.get(mix['raw']+'/release_short_buffers.py')).hexdigest()==mix['buffers_sha256'], 'mixed buffer checker changed')
                for session in mix['sessions']:
                    text=g.get(mix['raw']+'/configs/'+session['label']+'-'+role+'.conf').decode()
                    signature=hashlib.sha256(text.replace(mix['raw'],'/RUN').encode()).hexdigest()
                    require(signature==evidence['performance_fixture_sha256'][role][session['mode']],
                            'mixed performance fixture mismatch')
                    if checked_buffers:
                        value=json.loads(g.get(mix['raw']+'/configs/'+session['label']+'-'+role+'-sockets.json'))
                        require(buffers.qeli_check(value,session['mode'].startswith('udp-'),mix['buffer_policy']['qeli_receive_bytes'])==session['buffers'][role], 'mixed session buffer receipt differs from raw')
            for row in evidence['mixed']['windows']:
                row['metrics']={}
                observations={}
                for role,g in mixed_guests.items():
                    observations[role]=json.loads(g.get(mix['raw']+'/windows/'+row['label']+'/observations.json'))
                    row['metrics'][role]=metrics(observations[role],row,role)
                    if checked_buffers and role=='client':
                        require(all(row['metrics'][role][key] is not None for key in ('iperf_tcp_receiver_rb_bytes','iperf_tcp_receiver_tb_bytes')), 'mixed TCP receiver buffer evidence missing')
                    if checked_buffers:
                        value=json.loads(g.get(mix['raw']+'/windows/'+row['label']+'/'+role+'-qeli-sockets.json'))
                        require(buffers.qeli_check(value,row['mode'].startswith('udp-'),mix['buffer_policy']['qeli_receive_bytes'])==row['qeli_buffers'][role], 'mixed window buffer receipt differs from raw')
                if checked_buffers:
                    require(buffers.iperf_check(observations,'upload',mix['buffer_policy']['iperf_receive_rb_bytes'])==row['iperf_buffers'], 'mixed iperf buffer receipt differs from raw')
        finally:
            for g in mixed_guests.values():
                g.c.close()
    if not reference and (evidence['udp_failed_groups'] or evidence['unstable_groups'] or evidence['mixed_status']=='NEEDS_REVIEW'):
        evidence['qualification']='PILOT_REVIEW_REQUIRED'
    if reference:
        ref=json.loads(reference.read_text())
        require(ref.get('mixed_status')=='VALID','reference has no valid mixed check')
        evidence['comparison']=compare(evidence,ref)
        evidence['review_warnings']=review_warnings(evidence,ref)
        suspected=any(v['throughput_delta_percent'] < -10 for v in evidence['comparison'].values())
        evidence['qualification']='NEEDS_CONFIRMATION' if suspected or evidence['unstable_groups'] or evidence['udp_failed_groups'] or evidence['review_warnings'] or evidence['mixed_status']!='VALID' else 'LAB_COMPARISON_PASS'
    if invalid:
        evidence['qualification']='INVALID'
    if not checked_buffers:
        evidence['qualification']='LEGACY_NO_BUFFER_QUALIFICATION'
    if reference_scope:
        evidence['qualification']=reference_qualification(evidence)
        evidence['scope']='Four required profiles; TCP P4/UDP600 n=3; NOT full release qualification'
    atomic(output,evidence)
    print(json.dumps(dict(qualification=evidence['qualification'],windows=len(evidence['windows']),
                          udp_failed=evidence['udp_failed_groups'],unstable=len(evidence['unstable_groups']),
                          baseline=evidence['baseline'])),flush=True)
    return evidence


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--result',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--reference',type=Path)
    p.add_argument('--mixed-result',type=Path,help='separate sequential --mixed-only receipt')
    p.add_argument('--require-pass',action='store_true',help='exit nonzero unless a valid reference comparison passes')
    a=p.parse_args()
    evidence=collect(json.loads(a.config.read_text()),a.result,a.output,a.reference,a.mixed_result)
    if a.require_pass:
        raise SystemExit(0 if evidence['qualification']=='LAB_COMPARISON_PASS' else 1)
