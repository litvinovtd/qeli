#!/usr/bin/env python3
"""Reproduce documentation SVGs from compact measured data (stdlib only).

Run python scripts/render_recordizer_latency.py [--check]. No lab access required.
Different-run comparisons are labelled; the renderer never pools their packets.
"""
from pathlib import Path
import argparse
import html
import json

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'docs/data/benchmarks/recordizer_latency_2026-10-29.json'
PREFIX = DATA.with_suffix('')
MODES = ['tcp-faketls', 'tcp-reality-tls', 'udp-faketls', 'udp-quic', 'udp-obfs']
COLORS = ['#2563eb', '#d97706', '#059669']

def text(x, y, value, size=14, anchor='start', fill='#172033'):
    return f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" text-anchor="{anchor}" fill="{fill}">{html.escape(str(value))}</text>'

def canvas(title, subtitle, height=670):
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="{height}" viewBox="0 0 1120 {height}" role="img">',
            f'<title>{html.escape(title)}</title>', f'<desc>{html.escape(subtitle)}</desc>',
            '<rect width="100%" height="100%" fill="white"/>', '<g font-family="Arial, sans-serif">',
            text(32, 34, title, 22), text(32, 58, subtitle, 13)]

def bars(parts, y0, title, series, labels, maximum, ticks, ranges=None):
    left, right, height = 250, 1000, 170
    parts.append(text(32, y0 - 18, title, 17))
    for tick in ticks:
        x = left + tick / maximum * (right - left)
        parts.append(f'<path d="M{x} {y0}v{height}" stroke="#dbe1e8"/>')
        parts.append(text(x, y0 + height + 20, f'{tick:g}', 12, 'middle'))
    group = height / len(labels)
    for i, label in enumerate(labels):
        parts.append(text(left - 14, y0 + i * group + 19, label, 13, 'end'))
        for j, values in enumerate(series):
            value = values[i]
            y = y0 + i * group + j * 8
            width = value / maximum * (right - left)
            label_x = left + width + 5
            parts.append(f'<rect x="{left}" y="{y:.1f}" width="{width:.2f}" height="7" fill="{COLORS[j]}"/>')
            if ranges is not None:
                lo, hi = ranges[j][i]
                assert 0 <= lo <= value <= hi <= maximum
                xlo = left + lo / maximum * (right - left)
                xhi = left + hi / maximum * (right - left)
                label_x = max(label_x, xhi + 5)
                parts.append(f'<path d="M{xlo} {y+3.5}H{xhi} M{xlo} {y+1}v5 M{xhi} {y+1}v5" stroke="#172033" stroke-width="1"/>')
            parts.append(text(label_x, y + 7, f'{value:.2f}', 10, fill=COLORS[j]))

def legend(parts, y):
    for x, color, label in zip((32, 330, 655), COLORS, ('off / archived build', 'required timed / archived', 'required opportunistic / candidate')):
        parts.append(f'<rect x="{x}" y="{y-11}" width="12" height="12" fill="{color}"/>')
        parts.append(text(x + 20, y, label, 13))

def latency_values(data, metric, condition='idle', pattern='voip'):
    old = {(r['mode'], r['family'], r['pattern'], r['condition']): r for r in data['off_required']['comparisons']}
    new = {(r['mode'], r['family'], r['pattern'], r['condition']): r for r in data['timed_opportunistic']['comparisons']}
    result = [[], [], []]
    for mode in MODES:
        key = mode, 4, pattern, condition
        if metric == 'jitter':
            result[0].append(old[key]['policy_median_of_window_quantiles']['off']['ipdv_rtt_p99_ms'])
            result[1].append(new[key]['arms']['A']['jitter_p99_ms'])
            result[2].append(new[key]['arms']['B']['jitter_p99_ms'])
        else:
            result[0].append(old[key]['policy_median_of_window_quantiles']['off'][metric])
            result[1].append(new[key]['arms']['A']['rtt'][metric])
            result[2].append(new[key]['arms']['B']['rtt'][metric])
    return result

def latency_ranges(data, metric, condition='idle', pattern='voip'):
    ranges = [[], [], []]
    for i, (key, arm_name, arm) in enumerate((('off_required', 'policy', 'off'), ('timed_opportunistic', 'arm', 'A'), ('timed_opportunistic', 'arm', 'B'))):
        for mode in MODES:
            windows = [w for w in data[key]['windows'] if w.get('mode') == mode and w.get('family') == 4 and w.get('pattern') == pattern and w.get('condition') == condition and w.get(arm_name) == arm]
            assert len(windows) == 3, (mode, arm, len(windows))
            values = [w['latency']['absolute_ipdv']['rtt']['p99_ms'] if metric == 'jitter' else w['latency']['rtt'][metric] for w in windows]
            ranges[i].append((min(values), max(values)))
    return ranges

def render(data):
    outputs = {}
    note = 'IPv4; n=3 paired windows; medians of window quantiles. Off is a separate archived experiment.'
    parts = canvas('Recordizer: sparse VoIP RTT / ms', note)
    legend(parts, 90)
    bars(parts, 135, 'p50 RTT', latency_values(data, 'p50_ms'), MODES, 30, (0, 5, 10, 15, 20, 25, 30), latency_ranges(data, 'p50_ms'))
    bars(parts, 400, 'p99 RTT', latency_values(data, 'p99_ms'), MODES, 40, (0, 10, 20, 30, 40), latency_ranges(data, 'p99_ms'))
    parts.append(text(32, 650, '60 s, 172 B / 20 ms, idle. Whiskers: min/max of 3 windows, not confidence intervals. IPv6/p95 in report.', 13))
    outputs['rtt'] = '\n'.join(parts + ['</g></svg>']) + '\n'
    parts = canvas('Recordizer: sparse VoIP jitter / ms', note, 400)
    legend(parts, 90)
    bars(parts, 140, 'p99 absolute RTT IPDV (not RTP jitter)', latency_values(data, 'jitter'), MODES, 20, (0, 5, 10, 15, 20), latency_ranges(data, 'jitter'))
    parts.append(text(32, 375, 'Whiskers: min/max of 3 windows. Not one-way delay or maximum; rare stalls may lie outside p99.', 13))
    outputs['jitter'] = '\n'.join(parts + ['</g></svg>']) + '\n'
    parts = canvas('Recordizer: game-pattern p99 RTT / ms', note)
    legend(parts, 90)
    idle = latency_values(data, 'p99_ms', pattern='game')
    loaded = latency_values(data, 'p99_ms', condition='bidir100', pattern='game')
    ceiling = max(40, int(max(max(x) for x in idle + loaded) / 20 + 1) * 20)
    ticks = [i * ceiling / 4 for i in range(5)]
    bars(parts, 135, 'Idle', idle, MODES, ceiling, ticks, latency_ranges(data, 'p99_ms', pattern='game'))
    bars(parts, 400, 'UDP background: 100 Mbit/s in each direction', loaded, MODES, ceiling, ticks, latency_ranges(data, 'p99_ms', condition='bidir100', pattern='game'))
    parts.append(text(32, 650, '60 s, 128-byte packets every 7.8125 ms. Background is not a saturation test or a real game.', 13))
    outputs['loaded'] = '\n'.join(parts + ['</g></svg>']) + '\n'
    parts = canvas('TCP P4 throughput: opportunistic minus timed / %',
                   'Same required policy; n=3 paired changes. Point = median; whisker = min/max, not confidence interval.', 850)
    selected = [r for r in data['timed_opportunistic']['speed_comparisons'] if r['protocol'] == 'TCP' and r['streams'] == 4 and r['n'] == 3]
    for panel, direction in enumerate(('upload', 'download')):
        top, left, right = 120 + panel * 350, 265, 990
        parts.append(text(32, top - 24, direction.upper(), 17))
        def xx(value): return left + (value + 15) / 55 * (right - left)
        for tick in (-15, -10, -5, 0, 10, 20, 30, 40):
            x = xx(tick)
            parts.append(f'<path d="M{x} {top-10}v280" stroke="{"#64748b" if tick == 0 else "#dbe1e8"}"/>')
            parts.append(text(x, top + 293, f'{tick:+g}', 12, 'middle'))
        for i, (mode, family) in enumerate((m, f) for m in MODES for f in (4, 6)):
            row = next(r for r in selected if r['mode'] == mode and r['family'] == family and r['direction'] == direction)
            delta = row['candidate_delta_percent']; y = top + i * 27
            assert -15 <= delta['min'] <= delta['median'] <= delta['max'] <= 40
            parts.append(text(left - 15, y + 5, f'{mode} IPv{family}', 13, 'end'))
            parts.append(f'<path d="M{xx(delta["min"])} {y}H{xx(delta["max"])}" stroke="#2563eb" stroke-width="2"/>')
            for value in (delta['min'], delta['max']):
                parts.append(f'<path d="M{xx(value)} {y-4}v8" stroke="#2563eb"/>')
            parts.append(f'<circle cx="{xx(delta["median"])}" cy="{y}" r="4" fill="#2563eb"/>')
            parts.append(text(right + 12, y + 4, f'{delta["median"]:+.2f}%', 12))
    parts.append(text(32, 824, '15 s with -O 3. Around 8-9% loss is specific to FakeTLS upload, not a universal Recordizer penalty.', 13))
    outputs['speed'] = '\n'.join(parts + ['</g></svg>']) + '\n'
    return outputs

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    outputs = render(json.loads(DATA.read_text(encoding='utf-8')))
    for name, content in outputs.items():
        path = PREFIX.with_name(PREFIX.name + '_' + name + '.svg')
        if args.check:
            assert path.read_text(encoding='utf-8') == content, str(path) + ' is stale'
        else:
            path.write_text(content, encoding='utf-8')
    print('PASS: four Recordizer charts match compact measured data' if args.check else 'Rendered four Recordizer SVG charts')

if __name__ == '__main__':
    main()
