"""Reproduce the 29 October Recordizer masking pilot from sanitized feature windows.

Run python scripts/analyze_recordizer_masking_pilot.py --check (stdlib only).
Math/model choices match the frozen lab analyzer; only input/output wiring differs.
No guest, capture, secret or packet-body access is needed.
"""
from pathlib import Path
import json, math, statistics

import argparse
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--data',type=Path,default=ROOT/'docs/data/benchmarks/recordizer_masking_pilot_2026-10-29.json')
parser.add_argument('--check',action='store_true')
args=parser.parse_args()
data=json.loads(args.data.read_text(encoding='utf-8'))
spec=data['analysis']['spec']
rows=[r for r in data['feature_windows'] if not r['preflight']]
assert len(rows)==120 and len({r['session'] for r in rows})==30
assert all(r['capture']['kernel_drops']==0 for r in rows)
assert all(r['sent']>0 for r in rows)

def sigmoid(value):return 1/(1+math.exp(-max(-40,min(40,value))))
def fit(train,keys,label):
    x=[[math.log1p(max(0,r['features'][k])) for k in keys] for r in train]
    means=[statistics.mean(c) for c in zip(*x)];std=[statistics.pstdev(c) or 1 for c in zip(*x)]
    x=[[1]+[(v-m)/s for v,m,s in zip(a,means,std)] for a in x];y=[label(r) for r in train]
    weights=[1/(2*y.count(v)) for v in y];w=[0.]*(len(keys)+1)
    for _ in range(1000):
        gradient=[0.]*len(w)
        for a,b,weight in zip(x,y,weights):
            error=(sigmoid(sum(i*j for i,j in zip(w,a)))-b)*weight
            for j,value in enumerate(a):gradient[j]+=error*value
        for j in range(len(w)):w[j]-=.2*(gradient[j]+(.1*w[j] if j else 0))
    def score(row):
        values=[1]+[(math.log1p(max(0,row['features'][k]))-m)/s for k,m,s in zip(keys,means,std)]
        return sigmoid(sum(i*j for i,j in zip(w,values)))
    return score
def auc(positive,negative):
    return sum((a>b)+.5*(a==b) for a in positive for b in negative)/(len(positive)*len(negative))
def wilson(hits,n):
    z=1.95996398454;p=hits/n;den=1+z*z/n
    mid=(p+z*z/(2*n))/den;half=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [max(0,mid-half),min(1,mid+half)]
def metrics(scores):
    result={}
    for kind in sorted({r['kind'] for r in scores}):
        values=[r['score'] for r in scores if r['kind']==kind];hits=sum(v>=.5 for v in values)
        result[kind]=dict(n_flows=len(values),predicted_positive=hits,rate=hits/len(values),wilson_95=wilson(hits,len(values)),
                          median_score=statistics.median(values))
    return result
models={}
for task in ('mode-separation','qeli-vs-h2'):
    selected=[r for r in rows if task=='qeli-vs-h2' or r['kind']!='control-h2']
    label=(lambda r: int(r['kind']!='control-h2')) if task=='qeli-vs-h2' else (lambda r: int(r['kind']=='opportunistic'))
    for variant,keys in (('full',spec['passive_features']),('timing-only',spec['timing_only'])):
        predictions=[]
        for block in range(1,11):
            train=[r for r in selected if r['block']!=block];test=[r for r in selected if r['block']==block]
            assert not ({r['session'] for r in train}&{r['session'] for r in test})
            score=fit(train,keys,label)
            for row in test:predictions.append(dict(block=block,kind=row['kind'],session=row['session'],pattern=row['pattern'],truth=label(row),score=score(row)))
        flows=[]
        for session in sorted({r['session'] for r in predictions}):
            group=[r for r in predictions if r['session']==session];assert len(group)==4
            flows.append(dict(session=session,block=group[0]['block'],kind=group[0]['kind'],truth=group[0]['truth'],score=statistics.mean(r['score'] for r in group),max_window_score=max(r['score'] for r in group)))
        positive=[r['score'] for r in flows if r['truth']];negative=[r['score'] for r in flows if not r['truth']]
        sensitivity=[dict(r,score=r['max_window_score']) for r in flows]
        models[task+'/'+variant]=dict(auc=auc(positive,negative),fixed_threshold=.5,metrics=metrics(flows),flows=flows,window_scores=predictions,
                                      maximum_window_sensitivity=dict(metrics=metrics(sensitivity),auc=auc([r['score'] for r in sensitivity if r['truth']],[r['score'] for r in sensitivity if not r['truth']])))

summary=[]
for pattern in ('voip','game','burst','bulk'):
    for kind in ('timed','opportunistic','control-h2'):
        group=[r for r in rows if r['pattern']==pattern and r['kind']==kind]
        fields=('rtt_p50_ms','rtt_p99_ms','input_lateness_p99_ms','input_lateness_max_ms','payload_packets_per_useful_message')
        summary.append(dict(pattern=pattern,kind=kind,n=10,median={k:statistics.median(r[k] for r in group) for k in fields},
                            loss_count=sum(r['loss_count'] for r in group),sent=sum(r['sent'] for r in group),
                            capture_cpu_median=statistics.median(r['capture']['capture_cpu_percent'] for r in group),
                            passive_features_median={k:statistics.median(r['features'][k] for r in group) for k in spec['passive_features']},
                            correlation_peak_median=statistics.median(r['inner_outer_correlation']['peak'] for r in group if r['inner_outer_correlation']) if any(r['inner_outer_correlation'] for r in group) else None))

paired=[]
for pattern in ('voip','game','burst','bulk'):
    deltas=[]
    for block in range(1,11):
        group={r['kind']:r for r in rows if r['pattern']==pattern and r['block']==block}
        deltas.append({k:group['opportunistic'][k]-group['timed'][k] for k in ('rtt_p50_ms','rtt_p99_ms','input_lateness_p99_ms')})
    paired.append(dict(pattern=pattern,median_delta={k:statistics.median(r[k] for r in deltas) for k in deltas[0]},pairs=deltas))
output=dict(status='ANALYZED_PILOT_NOT_DPI_CERTIFICATION',spec=spec,models=models,summary=summary,paired=paired,
            caveats=['10 independent flows per class; no reliable 1%/0.1% FPR claim',
                     'Matched synthetic H2 stream is not a browser or broad Internet negative corpus',
                     'Cross-validated scores are not probabilities of detection by a real censor',
                     'Headers/data phase only; handshake and active probing intentionally outside this comparison',
                     'Existing synchronous usage writes and VM scheduling may contribute tails; retain pacing and loss data',
                     'Wilson intervals do not include model-selection/domain-shift uncertainty'])
if args.check:
    assert output==data['analysis'], 'Recomputed pilot analysis differs from frozen evidence'
    print('PASS: blocked classifiers and summaries reproduce frozen pilot data')
else:
    print(json.dumps(output,indent=2))
