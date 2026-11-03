#!/usr/bin/env python3
"""Recompute a comparable >=3-run benchmark report from retained raw files.

This reports the whole population without discarding failed runs or outliers.
AGGREGATED is a measurement report, not a performance or source-provenance PASS.
"""

import argparse
import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import re

from benchmark_evidence import bidir_counter_deltas, counter_deltas, measurement_phases, parse_iperf_bidir, parse_iperf_result
from benchmark_host_state import SCHEMA, structural_host_snapshot
from native_repro import atomic_write_bytes


def number(value, label, positive=False):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError('invalid ' + label)
    return value


def population(values):
    ordered = sorted(number(value, 'sample') for value in values)
    if len(ordered) < 3:
        raise ValueError('at least three samples required')
    middle = len(ordered) // 2
    median = ordered[middle] if len(ordered) % 2 else ordered[middle - 1] + (ordered[middle] - ordered[middle - 1]) / 2
    low, high = ordered[0], ordered[-1]
    return dict(n=len(ordered), min=low, max=high, median=median,
                range=high - low, spread_pct=(1 - low / high) * 100 if high else 0)


def read_json(path, root, hashes):
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise ValueError('raw evidence escapes run directory: ' + str(path))
    data = resolved.read_bytes()
    if len(data) > 16 * 1024 * 1024:
        raise ValueError('oversized benchmark evidence')
    hashes[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    def refuse_constant(value):
        raise ValueError('nonfinite JSON ' + value)
    return json.loads(data, parse_constant=refuse_constant)


def sample_policy(sample):
    rows = sample['samples']
    if len(rows) < 2 or type(sample['clock_ticks']) is not int or sample['clock_ticks'] <= 0:
        raise ValueError('process sampler incomplete')
    first, last = rows[0], rows[-1]
    policy = (first['start'], first['cpu_affinity'], first['nice'])
    if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*', first['cpu_affinity']) or type(first['nice']) is not int:
        raise ValueError('process CPU policy missing')
    for index, row in enumerate(rows):
        if (row['start'], row['cpu_affinity'], row['nice']) != policy:
            raise ValueError('process identity or CPU policy changed')
        for key in ('ticks', 'rss_kib', 'host_total', 'host_steal'):
            if type(row[key]) is not int or row[key] < 0:
                raise ValueError('invalid sampler counter ' + key)
        if row['host_steal'] > row['host_total']:
            raise ValueError('host steal exceeds total CPU ticks')
        if len(row['host_load']) != 3:
            raise ValueError('host load samples missing')
        for load in row['host_load']:
            number(load, 'host load')
        number(row['t'], 'sample time')
        if index and (row['t'] <= rows[index - 1]['t'] or any(row[key] < rows[index - 1][key] for key in ('ticks', 'host_total', 'host_steal'))):
            raise ValueError('sampler counters or clock went backwards')
    elapsed = number(last['t'] - first['t'], 'sample interval', positive=True)
    derived = dict(elapsed=elapsed,
        cpu_avg_pct=100 * (last['ticks'] - first['ticks']) / sample['clock_ticks'] / elapsed,
        rss_peak_kib=max(row['rss_kib'] for row in rows),
        host_steal_pct=100 * (last['host_steal'] - first['host_steal']) / max(1, last['host_total'] - first['host_total']))
    for key, value in derived.items():
        if not math.isclose(number(sample[key], key), value, rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError('sampler summary disagrees with raw ' + key)
    return dict(cpu_affinity=policy[1], nice=policy[2])


def validate_run(directory, *, measurements_only=False):
    root = Path(directory).resolve(strict=True)
    hashes = {}
    run = read_json(root / 'results.json', root, hashes)
    if not isinstance(run, dict) or run.get('schema_version') != 2:
        raise ValueError('run incomplete, failed, or host restoration unverified')
    before, after = run.get('host_before'), run.get('host_after')
    if not isinstance(before, list) or len(before) != 2 or not isinstance(after, list) or len(after) != 2:
        raise ValueError('host state snapshots incomplete')
    for row in before + after:
        if isinstance(row, dict) and 'snapshot_schema' not in row and (set(row) != {'addresses', 'routes', 'qeli_listener'} or any(not isinstance(value, str) or not value.strip() for value in row.values())):
            raise ValueError('archived host core snapshot incomplete')
    restored = [structural_host_snapshot(row) for row in before] == [structural_host_snapshot(row) for row in after]
    if type(run.get('host_restored')) is not bool or run['host_restored'] != restored:
        raise ValueError('host state restoration disagrees with raw snapshots')
    completed = run.get('status') == 'COMPLETED' and run.get('errors') == [] and restored
    host_failure = run.get('status') == 'FAIL' and run.get('errors') == ['host state changed after benchmark'] and not restored
    if not completed and not (measurements_only and host_failure):
        raise ValueError('run incomplete, failed, or host restoration unverified')
    meta = run['meta']
    for key in ('binary_sha256', 'harness_sha256', 'configuration_builder_sha256', 'admission_sha256', 'local_native_source_digest'):
        if not re.fullmatch('[0-9a-f]{64}', meta[key]):
            raise ValueError('invalid identity ' + key)
    if not re.fullmatch('[0-9a-f-]{36}', meta['run_id']):
        raise ValueError('missing run identity')
    if meta['binary_source_provenance'] != 'UNVERIFIED':
        raise ValueError('unsupported binary source provenance assertion')
    if type(meta['seconds']) is not int or not 5 <= meta['seconds'] <= 30 or type(meta['tcp_parallel']) is not int or meta['tcp_parallel'] not in (1, 4):
        raise ValueError('invalid run interval or TCP parallelism')
    if not isinstance(meta['hosts'], list) or len(meta['hosts']) != 2 or any(not isinstance(host, str) or not host for host in meta['hosts']) or meta['hosts'][0] == meta['hosts'][1]:
        raise ValueError('invalid benchmark hosts')
    selected = meta['selected_modes']
    if not selected or len(set(selected)) != len(selected) or set(run['modes']) != set(selected):
        raise ValueError('mode population missing or duplicated')
    started, ended = dt.datetime.fromisoformat(meta['date']), dt.datetime.fromisoformat(meta['finished_at'])
    if started.tzinfo is None or ended.tzinfo is None or ended <= started:
        raise ValueError('invalid run window')
    number(meta['elapsed_seconds'], 'monotonic run duration', positive=True)
    comparison = {key: meta[key] for key in ('binary_sha256', 'harness_sha256', 'configuration_builder_sha256',
        'admission_sha256', 'seconds', 'tcp_parallel', 'recordizer', 'topology', 'hosts', 'selected_modes')}
    profile = meta.get('measurement', 'standard')
    comparison['measurement'] = profile
    role_policy = meta.get('tcp_bidir_stream_roles_required', False)
    if type(role_policy) is not bool:
        raise ValueError('invalid TCP bidir role evidence policy')
    comparison['tcp_bidir_stream_roles_required'] = role_policy
    coverage = [row.get('snapshot_schema', 'archived-core-only') for row in run['host_before']]
    if coverage[0] != coverage[1]:
        raise ValueError('host snapshot coverage differs across hosts')
    comparison['host_snapshot_coverage'] = coverage[0]
    comparison['host_state_sha256'] = meta.get('host_state_sha256')
    if coverage[0] == SCHEMA and not re.fullmatch('[0-9a-f]{64}', meta.get('host_state_sha256', '')):
        raise ValueError('full host snapshot helper identity missing')
    for host in ('server', 'client'):
        comparison[host] = {key: meta[host][key] for key in ('kernel', 'cpu', 'iperf', 'version', 'boot_id', 'cpu_governor')}
        governor = meta[host]['cpu_governor']
        if not isinstance(governor, dict) or governor.get('availability') not in ('AVAILABLE', 'UNAVAILABLE') or not isinstance(governor.get('policies'), dict):
            raise ValueError('CPU governor availability missing')
    comparison['modes'] = {}
    phase_metrics = {}
    groups = [('direct', run['baseline'], measurement_phases(profile, 'direct'))]
    for name in selected:
        if not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', name):
            raise ValueError('invalid mode name')
        mode = run['modes'][name]
        if mode.get('status') != 'COMPLETED' or mode.get('transport') not in ('tcp', 'udp'):
            raise ValueError('mode incomplete')
        if not re.fullmatch('[0-9a-f]{64}', mode['configuration_template_sha256']):
            raise ValueError('configuration identity missing')
        for host in ('server', 'client'):
            mtus = mode['mtus'][host]
            if set(mtus) != {'qbench0', 'qd14v'} or any(type(value) is not int or value <= 0 for value in mtus.values()):
                raise ValueError('interface MTUs missing')
        comparison['modes'][name] = {key: mode[key] for key in ('transport', 'configuration_template_sha256', 'mtus',
            'qeli-bench-s_rmem_max', 'qeli-bench-c_rmem_max')}
        phases = measurement_phases(profile, mode['transport'])
        groups.append((name, mode, phases))
    for name, summary, phases in groups:
        actual_phases = {key for key in summary if key.startswith(('tcp_', 'udp_'))}
        if actual_phases != set(phases):
            raise ValueError('phase population missing or unexpected: ' + name)
        for phase in phases:
            raw = read_json(root / name / (phase + '-iperf.json'), root, hashes)
            metrics = parse_iperf_bidir(raw, 5 if phase == 'udp_bidir' else meta['seconds'], meta['tcp_parallel'], expected_bitrate=100000000 if phase == 'udp_bidir' else 0, protocol='udp' if phase == 'udp_bidir' else 'tcp', require_tcp_roles=meta.get('tcp_bidir_stream_roles_required', False)) if phase.endswith('_bidir') else parse_iperf_result(raw, 'udp' if phase.startswith('udp_') else 'tcp', 5 if phase.startswith('udp_') else meta['seconds'])
            expected = summary[phase]
            keys = tuple(metrics) if phase.endswith('_bidir') else ('mbps', 'retransmits', 'lost_percent') + (() if name == 'direct' else ('jitter_ms',))
            for key in keys:
                if metrics[key] is None:
                    equal = expected[key] is None
                else:
                    equal = math.isclose(number(expected[key], key), metrics[key], rel_tol=1e-12, abs_tol=1e-12)
                if not equal:
                    raise ValueError('summary disagrees with raw iperf: ' + name + '/' + phase + '/' + key)
            values = {key: value for key, value in metrics.items() if value is not None}
            if name != 'direct':
                samples = read_json(root / name / (phase + '-processes.json'), root, hashes)
                if len(samples) != 2:
                    raise ValueError('both process samples required')
                for index, host in enumerate(('server', 'client')):
                    sample = samples[index]
                    if sample != expected[host] or sample['pid'] != summary['pids'][host]:
                        raise ValueError('process summary disagrees with raw sampler')
                    policy = sample_policy(sample)
                    if sample['elapsed'] < (5 if phase.startswith('udp_') else meta['seconds']) * .9:
                        raise ValueError('process sampler interval truncated')
                    comparison['modes'][name][phase + '_' + host + '_policy'] = policy
                    for key in ('cpu_avg_pct', 'rss_peak_kib', 'host_steal_pct'):
                        values[host + '_' + key] = sample[key]
                    values[host + '_load1_max'] = max(row['host_load'][0] for row in sample['samples'])
                counters = read_json(root / name / (phase + '-counters.json'), root, hashes)
                deltas = (bidir_counter_deltas if phase.endswith('_bidir') else counter_deltas)(counters['before'], counters['after'])
                for key in deltas:
                    if type(expected[key]) is not int or expected[key] != deltas[key]:
                        raise ValueError('drop summary disagrees with raw counters')
                    values[key] = expected[key]
            phase_metrics[name + '/' + phase] = values
    phase_seconds = sum(5 if phase.startswith('udp_') else meta['seconds'] for _, _, phases in groups for phase in phases)
    if meta['elapsed_seconds'] < phase_seconds or (ended - started).total_seconds() < phase_seconds * .9:
        raise ValueError('run window shorter than mandatory sequential phases')
    return dict(directory=str(root), run_id=meta['run_id'], started=started, ended=ended,
                comparison=comparison, metrics=phase_metrics, hashes=hashes,
                run_status=run['status'], host_restored=restored, host_gate_errors=run['errors'])


def aggregate(directories, *, measurements_only=False):
    if len(directories) < 3:
        raise ValueError('at least three independent run directories required')
    runs = [validate_run(directory, measurements_only=measurements_only) for directory in directories]
    if len({run['directory'] for run in runs}) != len(runs) or len({run['run_id'] for run in runs}) != len(runs):
        raise ValueError('duplicate run directory or identity')
    if any(run['comparison'] != runs[0]['comparison'] for run in runs[1:]):
        raise ValueError('runs differ in artifact, harness, topology, CPU policy, MTU or measurement settings')
    ordered = sorted(runs, key=lambda run: run['started'])
    if any(current['started'] < previous['ended'] for previous, current in zip(ordered, ordered[1:])):
        raise ValueError('overlapping runs are not independent benchmark windows')
    raw_phases = {}
    for run in runs:
        for path, sha in run['hashes'].items():
            if not path.endswith('-iperf.json'):
                continue
            seen = raw_phases.setdefault(path, set())
            if sha in seen:
                raise ValueError('duplicated raw iperf phase: ' + path)
            seen.add(sha)
    metrics = {phase: {key: population([run['metrics'][phase][key] for run in runs])
               for key in values} for phase, values in runs[0]['metrics'].items()}
    scope = 'Same binary artifact and comparable measurement settings; binary source provenance UNVERIFIED; no performance PASS'
    if measurements_only:
        scope += '; MEASUREMENTS ONLY: host restoration is not admitted by this report; original per-run host gate results retained'
    return dict(schema_version=1, status='MEASUREMENTS_ONLY' if measurements_only else 'AGGREGATED', runs=len(runs),
        scope=scope,
        comparison=runs[0]['comparison'], statistics=metrics,
        inputs=[{key: run[key] for key in ('directory', 'run_id', 'hashes', 'run_status', 'host_restored', 'host_gate_errors')} for run in runs])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--measurements-only', action='store_true',
                        help='Retain failed host restoration explicitly; never emit AGGREGATED in this mode')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists')
    try:
        report = aggregate(args.runs, measurements_only=args.measurements_only)
        atomic_write_bytes(args.output, (json.dumps(report, indent=2, allow_nan=False) + '\n').encode())
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(report['status'], report['runs'], 'runs; raw evidence revalidated')


if __name__ == '__main__':
    main()
