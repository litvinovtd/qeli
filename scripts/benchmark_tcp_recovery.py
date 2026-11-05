"""Measure receiver recovery after writer admission, independently of carrier swap.

Input timestamps share one clock/origin. Bytes are cumulative useful receiver
bytes. Windows use observed endpoints only: no interpolation over stalls and no
claim that an averaged confirmation endpoint is the onset of recovery.
"""
import argparse
from bisect import bisect_right
import json
import math
from pathlib import Path


def number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError('expected a finite number')
    return value


def recovery_windows(samples, ready_s, threshold_mbps, windows_s=(1, 5)):
    ready_s, threshold_mbps = number(ready_s), number(threshold_mbps)
    windows_s = tuple(number(v) for v in windows_s)
    if threshold_mbps <= 0 or not windows_s or any(v <= 0 for v in windows_s):
        raise ValueError('threshold and windows must be positive')
    if len(set(windows_s)) != len(windows_s):
        raise ValueError('duplicate confirmation windows')
    if not isinstance(samples, list) or len(samples) < 2:
        raise ValueError('at least two observed receiver samples required')
    times, counts = [], []
    for sample in samples:
        at, count = number(sample['seconds']), sample['bytes']
        if type(count) is not int or count < 0:
            raise ValueError('receiver bytes must be nonnegative integers')
        if times and (at <= times[-1] or count < counts[-1]):
            raise ValueError('receiver time must increase and bytes cannot decrease')
        times.append(at)
        counts.append(count)
    if not times[0] <= ready_s < times[-1]:
        raise ValueError('receiver samples do not bracket writer admission')
    confirmations = []
    for window in windows_s:
        found = None
        for end in range(1, len(times)):
            start = bisect_right(times, times[end] - window) - 1
            if start < 0 or times[start] < ready_s:
                continue
            duration = times[end] - times[start]
            mbps = (counts[end] - counts[start]) * 8 / duration / 1_000_000
            if mbps < threshold_mbps:
                continue
            found = dict(start_s=times[start], end_s=times[end], duration_s=duration,
                         mbps=mbps, confirmed_after_ready_s=times[end] - ready_s,
                         largest_sample_gap_s=max(times[i] - times[i-1]
                                                  for i in range(start+1, end+1)))
            break
        confirmations.append(dict(requested_window_s=window, observation=found))
    return dict(writer_ready_s=ready_s, threshold_mbps=threshold_mbps,
                definition='first complete observed receiver interval of at least the requested duration; endpoint confirms average delivery and is not recovery onset',
                confirmations=confirmations)


def analyze(evidence):
    if evidence.get('schema') != 'qeli.tcp-recovery.v1':
        raise ValueError('unsupported recovery evidence schema')
    receiver = evidence['receiver']
    for key in ('expected_bytes', 'received_bytes', 'sequence_errors', 'exit_status'):
        if type(receiver[key]) is not int or receiver[key] < 0:
            raise ValueError('invalid receiver integrity evidence')
    if (receiver['expected_bytes'] <= 0 or receiver['received_bytes'] != receiver['expected_bytes']
            or receiver['sequence_errors'] != 0 or receiver['exit_status'] != 0):
        raise ValueError('incomplete or corrupt receiver stream')
    events = evidence['events']
    fault, ready, swapped = (number(events[k]) for k in
                             ('fault_s', 'downlink_ready_s', 'carrier_replaced_s'))
    # ss polling can observe carrier retirement after writer admission; do not
    # impose an invented ordering between those two independent observations.
    if min(ready, swapped) < fault:
        raise ValueError('recovery event predates the fault')
    result = recovery_windows(receiver['samples'], ready, evidence['threshold_mbps'])
    result.update(carrier_replaced_after_fault_s=swapped-fault,
                  writer_ready_after_fault_s=ready-fault, integrity_verified=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    evidence = json.loads(args.evidence.read_text(encoding='utf-8'))
    if evidence.get('schema') == 'qeli.tcp-recovery-experiment.v1':
        result = {case['name']: analyze(case) for case in evidence['cases']}
    else:
        result = analyze(evidence)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
