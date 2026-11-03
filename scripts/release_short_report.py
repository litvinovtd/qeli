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
        for key in ('rtt','cwnd','bytes_sent','bytes_retrans','snd_wnd','unacked','notsent'):
            match=re.search(r'(?:^|\s)'+key+r':(\d+(?:\.\d+)?)',row['body'])
            if match:
                row[key]=float(match[1])
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
    inner,outer=[],[]
    sender='client' if row['direction']=='upload' else 'server'
    for sample in samples:
        # TCP_INFO samples during measurement, excluding most warm-up and tail.
        if sample['t']<first['t']+row['omit']+.3 or sample['t']>last['t']-.2:
            continue
        for sock in sockets(sample['ss']):
            if sock['local_port'] in (5201,5202) or sock['peer_port'] in (5201,5202):
                if role==sender and sock.get('bytes_sent',0)>1e6:
                    inner.append(sock)
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
    require(value['method']=='qeli-release-short-mixed-v1' and value['status']=='complete','mixed run incomplete')
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


def collect(cfg, result, output, reference=None, mixed_result=None):
    require(not output.exists(),'refuse to overwrite analysis')
    raw_bytes=result.read_bytes()
    raw=json.loads(raw_bytes)
    require(raw['method']=='qeli-release-short-v1','smoke/debug runs cannot qualify the full plan')
    require(raw['status'] in ('complete','measurements_complete_udp_failed'),'run incomplete; retain FAIL')
    require(set(raw['restoration'])=={'server','client'} and all(all(v is True for v in c.values()) for c in raw['restoration'].values()),'restoration incomplete')
    require(len(raw['windows'])==384 and len(raw['sessions'])==56,'coverage mismatch')
    guests={r:Guest(cfg,r,raw['raw']) for r in ('server','client')}
    evidence=dict(schema=1,method=raw['method'],rates=raw['rates'],raw=raw['raw'],
                  binary_sha256=raw['binary_sha256'],run_receipt_sha256=hashlib.sha256(raw_bytes).hexdigest(),
                  started_utc=raw['started_utc'],finished_utc=raw['finished_utc'],
                  windows=[],sessions=raw['sessions'],restoration=raw['restoration'],
                  environment={},performance_fixture_sha256={})
    evidence['source_hashes']={}
    try:
        for role,g in guests.items():
            require(g.cmd('sha256sum '+raw['raw']+'/candidate').split()[0]==raw['binary_sha256'],'private candidate changed')
            require(g.cmd('sha256sum '+raw['raw']+'/qeli-'+role).split()[0]==raw['binary_sha256'],'final active copy changed')
            require(g.cmd('sha256sum '+cfg['previous_binary'][role]).split()[0]==raw['previous_sha256'],'old artifact changed')
            helper=g.get(raw['raw']+'/guest.py')
            require(hashlib.sha256(helper).hexdigest()==raw['helper_sha256'],'measured helper changed')
            controller=g.get(raw['raw']+('/controller.py' if raw.get('controller_sha256') else '/release_short_test.py'))
            evidence['source_hashes'][role]=dict(measured_helper_sha256=raw['helper_sha256'],
                                                 measured_controller_sha256=hashlib.sha256(controller).hexdigest())
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
            for role,g in guests.items():
                content=g.get(raw['raw']+'/windows/'+row['label']+'/observations.json')
                observations[role]=metrics(json.loads(content),row,role)
                if row['stage']=='perf':
                    require(observations[role]['tun_qlen']==1000 and observations[role]['mtu']==1400,
                            'performance queue/MTU mismatch')
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
                for session in mix['sessions']:
                    text=g.get(mix['raw']+'/configs/'+session['label']+'-'+role+'.conf').decode()
                    signature=hashlib.sha256(text.replace(mix['raw'],'/RUN').encode()).hexdigest()
                    require(signature==evidence['performance_fixture_sha256'][role][session['mode']],
                            'mixed performance fixture mismatch')
            for row in evidence['mixed']['windows']:
                row['metrics']={}
                for role,g in mixed_guests.items():
                    row['metrics'][role]=metrics(json.loads(g.get(mix['raw']+'/windows/'+row['label']+'/observations.json')),row,role)
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
