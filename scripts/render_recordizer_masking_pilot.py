"""Render masking-pilot plots from sanitized evidence, stdlib only.

Run python scripts/render_recordizer_masking_pilot.py [--check].
Labels explicitly limit interpretation to the measured synthetic H2 pilot.
"""
from pathlib import Path
import html,json,math

import argparse
ROOT=Path(__file__).resolve().parents[1]
H=ROOT/'docs/data/benchmarks'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check',action='store_true')
args=parser.parse_args()
analysis=json.loads((H/'recordizer_masking_pilot_2026-10-29.json').read_text(encoding='utf-8'))['analysis']
def emit(name,content):
    path=H/('recordizer_masking_pilot_2026-10-29_'+name+'.svg')
    if args.check:
        assert path.read_text(encoding='utf-8')==content, str(path)+' is stale'
    else:
        path.write_text(content,encoding='utf-8')
colors={'timed':'#2563eb','opportunistic':'#d97706','control-h2':'#059669'}
def text(x,y,s,size=14,anchor='start'):
    return f'<text x="{x}" y="{y}" font-family="Arial, sans-serif" font-size="{size}" text-anchor="{anchor}" fill="#172033">{html.escape(str(s))}</text>'
def canvas(title,subtitle,height=700):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="{height}" viewBox="0 0 1120 {height}" role="img">',
            '<title>'+html.escape(title)+'</title>','<desc>'+html.escape(subtitle)+'</desc>',
            '<rect width="100%" height="100%" fill="white"/>',text(32,35,title,22),text(32,61,subtitle,13)]
def legend(parts,y,include_control=True):
    for i,kind in enumerate(('timed','opportunistic','control-h2') if include_control else ('timed','opportunistic')):
        x=32+i*290;parts.append(f'<rect x="{x}" y="{y-11}" width="12" height="12" fill="{colors[kind]}"/>')
        parts.append(text(x+20,y,kind,14))

parts=canvas('Reality-TLS: timing transfer and RTT pilot','10 fresh sessions per arm; fixed useful load; IPv4; test NIC offloads disabled. Not a secrecy percentage.')
legend(parts,94)
summaries={(r['pattern'],r['kind']):r for r in analysis['summary']}
for panel,(metric,title,patterns,ceiling) in enumerate((
    ('correlation_peak_median','Peak inner-to-outer timing correlation',('voip','game','burst'),1),
    ('rtt_p50_ms','Median echo RTT / ms',('voip','game','burst','bulk'),None))):
    top=145+panel*270;left=230;right=1020;height=170
    parts.append(text(32,top-18,title,17))
    if ceiling is None:ceiling=max(5,5*math.ceil(max(r['median']['rtt_p50_ms'] for r in analysis['summary'])/5))
    for i in range(5):
        value=i*ceiling/4;x=left+(right-left)*i/4
        parts.append(f'<path d="M{x} {top}v{height}" stroke="#dbe1e8"/>');parts.append(text(x,top+height+22,f'{value:g}',12,'middle'))
    for i,pattern in enumerate(patterns):
        y=top+i*height/len(patterns);parts.append(text(left-12,y+23,pattern,14,'end'))
        for j,kind in enumerate(colors):
            row=summaries[(pattern,kind)]
            value=row[metric] if metric=='correlation_peak_median' else row['median'][metric]
            assert value is not None and 0<=value<=ceiling
            width=value/ceiling*(right-left);yy=y+j*10
            parts.append(f'<rect x="{left}" y="{yy}" width="{width}" height="8" fill="{colors[kind]}"/>')
            parts.append(text(left+width+5,yy+8,f'{value:.3f}',11))
parts.append(text(32,660,'Correlation: 1 ms bins, search 0..40 ms; periodic aliases possible. Bulk omitted from correlation plot.',13))
parts.append(text(32,682,'Correlation uses known test send times; it is descriptive ground truth, NOT a passive-classifier feature.',13))
emit('timing','\n'.join(parts+['</svg>'])+'\n')

parts=canvas('Qeli versus synthetic H2: held-out session ROC','10 negative H2 sessions only; FPR steps are 10 percentage points. No 1%/0.1% FPR qualification.',660)
legend(parts,94,False)
for panel,variant in enumerate(('full','timing-only')):
    model=analysis['models']['qeli-vs-h2/'+variant]
    left=80+panel*545;right=left+420;top=150;bottom=520
    parts.append(text(left,130,variant+' passive features',17))
    for tick in (0,.25,.5,.75,1):
        x=left+tick*(right-left);y=bottom-tick*(bottom-top)
        parts.append(f'<path d="M{x} {top}V{bottom} M{left} {y}H{right}" stroke="#e2e8f0"/>')
        parts.append(text(x,bottom+22,f'{tick:.2g}',12,'middle'));parts.append(text(left-12,y+4,f'{tick:.2g}',12,'end'))
    parts.append(f'<path d="M{left} {bottom}L{right} {top}" stroke="#94a3b8" stroke-dasharray="5 5"/>')
    negatives=[r['score'] for r in model['flows'] if r['kind']=='control-h2']
    for j,kind in enumerate(('timed','opportunistic')):
        positives=[r['score'] for r in model['flows'] if r['kind']==kind]
        thresholds=[float('inf')]+sorted(set(positives+negatives),reverse=True)+[float('-inf')]
        points=[]
        for cutoff in thresholds:
            fpr=sum(v>=cutoff for v in negatives)/len(negatives);tpr=sum(v>=cutoff for v in positives)/len(positives)
            points.append((left+fpr*(right-left),bottom-tpr*(bottom-top)))
        path=' '.join(('M' if i==0 else 'L')+f'{x},{y}' for i,(x,y) in enumerate(points))
        dash=' stroke-dasharray="7 4"' if kind=='opportunistic' else ''
        parts.append(f'<path d="{path}" stroke="{colors[kind]}" stroke-width="2" fill="none"{dash}/>')
        auc=sum((a>b)+.5*(a==b) for a in positives for b in negatives)/(len(positives)*len(negatives))
        parts.append(text(left,bottom+56+j*22,f'{kind}: AUROC {auc:.3f}',13))
    parts.append(text((left+right)/2,bottom+100,'False positive rate',13,'middle'))
parts.append(text(32,642,'Primary score: mean of four workload-window scores; grouped leave-one-block-out; no real-browser corpus.',13))
emit('classifier','\n'.join(parts+['</svg>'])+'\n')
print('PASS: both masking-pilot SVGs match frozen data' if args.check else 'Rendered both masking-pilot SVGs')
