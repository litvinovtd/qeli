"""Two real receiver directions and both kernel counters are mandatory."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_evidence import bidir_counter_deltas, measurement_phases, parse_iperf_bidir
from benchmark_isolated_lab import phase_flags
from benchmark_report import aggregate
from test_benchmark_report import fixture, write


def raw_result(up=100, down=200, unique=0):
    end = {}
    for rate, suffix, sender in ((up, '', True), (down, '_bidir_reverse', False)):
        received = dict(seconds=8.01, bytes=int(rate * 1e6), bits_per_second=rate * 1e6, sender=sender)
        end['sum_received' + suffix] = received
        end['sum_sent' + suffix] = dict(received, retransmits=3)
    return dict(start=dict(timestamp=dict(timesecs=unique), target_bitrate=0,
                          test_start=dict(protocol='TCP', bidir=1, reverse=0, num_streams=1, duration=8, target_bitrate=0)), end=end)


def bidir_fixture(root, index):
    fixture(root, index, 100 + index)
    run = json.loads((root / 'results.json').read_text())
    run['meta']['measurement'] = 'tcp-bidir'
    for name, summary in [('direct', run['baseline']), *run['modes'].items()]:
        processes = json.loads((root / name / 'tcp_up-processes.json').read_text()) if name != 'direct' else None
        counters = json.loads((root / name / 'tcp_up-counters.json').read_text()) if name != 'direct' else None
        for key in list(summary):
            if key.startswith(('tcp_', 'udp_')):
                del summary[key]
        raw = raw_result(100 + index, 200 + index, index)
        summary['tcp_bidir'] = parse_iperf_bidir(raw, 8, 1)
        write(root / name / 'tcp_bidir-iperf.json', raw)
        if name != 'direct':
            for snapshot in counters.values():
                snapshot['client_kernel'] = dict(RcvbufErrors=0)
            write(root / name / 'tcp_bidir-counters.json', counters)
            write(root / name / 'tcp_bidir-processes.json', processes)
            summary['tcp_bidir'].update(server=processes[0], client=processes[1], **bidir_counter_deltas(counters['before'], counters['after']))
    write(root / 'results.json', run)
    return root


class BidirTests(unittest.TestCase):
    def test_paced_results_require_explicit_matching_bitrate(self):
        raw = raw_result()
        for settings in (raw['start'], raw['start']['test_start']):
            settings['target_bitrate'] = 100000000
        with self.assertRaisesRegex(ValueError, 'bitrate'):
            parse_iperf_bidir(raw, 8, 1)
        self.assertEqual(parse_iperf_bidir(raw, 8, 1, expected_bitrate=100000000)['up_mbps'], 100)
        for field in ('start', 'test_start'):
            for value in (None, True, -1, 0, 100000000.0):
                changed = copy.deepcopy(raw)
                (changed['start'] if field == 'start' else changed['start']['test_start'])['target_bitrate'] = value
                with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, 'bitrate'):
                    parse_iperf_bidir(changed, 8, 1, expected_bitrate=100000000)

    def test_report_refuses_paced_input_in_unlimited_population(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            path = runs[1] / 'udp-fixture/tcp_bidir-iperf.json'
            raw = json.loads(path.read_text())
            for settings in (raw['start'], raw['start']['test_start']):
                settings['target_bitrate'] = 100000000
            write(path, raw)
            with self.assertRaisesRegex(ValueError, 'bitrate'):
                aggregate(runs)

    def test_two_receiver_directions_not_sender_goodput(self):
        raw = raw_result()
        raw['end']['sum_sent']['bits_per_second'] = 900e6
        self.assertEqual(parse_iperf_bidir(raw, 8, 1), dict(up_mbps=100, down_mbps=200, up_retransmits=3, down_retransmits=3))

    def test_missing_truncated_swapped_or_zero_reverse_refuses(self):
        for field, value in (('seconds', 1), ('sender', True), ('bits_per_second', 0), ('bytes', 0)):
            raw = raw_result()
            raw['end']['sum_received_bidir_reverse'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse_iperf_bidir(raw, 8, 1)
        raw = raw_result()
        del raw['end']['sum_received_bidir_reverse']
        with self.assertRaises(ValueError):
            parse_iperf_bidir(raw, 8, 1)

    def test_wrong_requested_settings_or_one_way_refuses(self):
        for field, value in (('bidir', 0), ('bidir', True), ('protocol', 'UDP'), ('reverse', 1), ('num_streams', 4), ('duration', 5)):
            raw = raw_result()
            raw['start']['test_start'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse_iperf_bidir(raw, 8, 1)

    def test_malformed_start_or_end_refuses_with_admission_error(self):
        for field, value in (('start', None), ('start', []), ('start', dict(test_start=None)), ('end', None)):
            raw = raw_result()
            raw[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                parse_iperf_bidir(raw, 8, 1)

    def test_both_kernel_drop_deltas_and_resets_are_checked(self):
        before = dict(kernel=dict(RcvbufErrors=4), client_kernel=dict(RcvbufErrors=9),
                      application=dict(dropped=2, bytes_sent=3, bytes_recv=4, connected_secs=5, ip='client', peer='peer'))
        after = copy.deepcopy(before)
        after['kernel']['RcvbufErrors'] = 6
        after['client_kernel']['RcvbufErrors'] = 12
        self.assertEqual(bidir_counter_deltas(before, after), dict(server_session_drops=0, server_kernel_rcvbuf_drops=2, client_kernel_rcvbuf_drops=3))
        after['client_kernel']['RcvbufErrors'] = 0
        with self.assertRaisesRegex(ValueError, 'reset'):
            bidir_counter_deltas(before, after)

    def test_profile_makes_bidir_mandatory_for_all_carriers_and_baseline(self):
        for transport in ('direct', 'tcp', 'udp'):
            self.assertEqual(measurement_phases('tcp-bidir', transport), ('tcp_bidir',))
        self.assertEqual(phase_flags('tcp_bidir', 4), '-P 4 --bidir')
        with self.assertRaises(ValueError):
            measurement_phases('unsupported', 'tcp')

    def test_report_revalidates_both_directions_and_counters(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            stats = aggregate(runs)['statistics']['udp-fixture/tcp_bidir']
            self.assertEqual(stats['down_mbps']['median'], 201)
            self.assertEqual(stats['client_kernel_rcvbuf_drops']['max'], 0)
            path = runs[1] / 'udp-fixture/tcp_bidir-counters.json'
            counters = json.loads(path.read_text())
            counters['after']['client_kernel']['RcvbufErrors'] = 10
            write(path, counters)
            with self.assertRaisesRegex(ValueError, 'drop summary disagrees'):
                aggregate(runs)

    def test_report_cannot_mix_profiles_or_omit_reverse(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            path = runs[1] / 'tcp-fixture/tcp_bidir-iperf.json'
            raw = json.loads(path.read_text())
            del raw['end']['sum_received_bidir_reverse']
            write(path, raw)
            with self.assertRaisesRegex(ValueError, 'receiver summary missing'):
                aggregate(runs)
            bidir_fixture(Path(temporary) / 'standard', 4)
            standard = fixture(Path(temporary) / 'actual-standard', 5, 100)
            with self.assertRaisesRegex(ValueError, 'runs differ'):
                aggregate([runs[0], runs[2], standard])

    def test_explicit_measurement_report_keeps_failed_host_gate(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            path = runs[0] / 'results.json'
            run = json.loads(path.read_text())
            run.update(status='FAIL', host_restored=False, errors=['host state changed after benchmark'])
            run['host_after'][0]['routes'] = 'changed route'
            write(path, run)
            with self.assertRaisesRegex(ValueError, 'run incomplete'):
                aggregate(runs)
            report = aggregate(runs, measurements_only=True)
            self.assertEqual(report['status'], 'MEASUREMENTS_ONLY')
            self.assertEqual(report['inputs'][0]['run_status'], 'FAIL')
            self.assertFalse(report['inputs'][0]['host_restored'])
            self.assertEqual(report['statistics']['tcp-fixture/tcp_bidir']['up_mbps']['n'], 3)

    def test_measurements_only_does_not_admit_other_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            path = runs[0] / 'results.json'
            run = json.loads(path.read_text())
            run.update(status='FAIL', errors=['iperf failed'])
            write(path, run)
            with self.assertRaisesRegex(ValueError, 'run incomplete'):
                aggregate(runs, measurements_only=True)

    def test_measurements_only_requires_real_complete_host_snapshots(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            path = runs[0] / 'results.json'
            run = json.loads(path.read_text())
            run.update(status='FAIL', host_restored=False, errors=['host state changed after benchmark'])
            write(path, run)
            with self.assertRaisesRegex(ValueError, 'disagrees with raw snapshots'):
                aggregate(runs, measurements_only=True)
            run['host_after'] = None
            write(path, run)
            with self.assertRaisesRegex(ValueError, 'snapshots incomplete'):
                aggregate(runs, measurements_only=True)

    def test_measurements_only_cannot_omit_or_falsify_measured_phase(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs = [bidir_fixture(Path(temporary) / str(i), i) for i in range(3)]
            path = runs[0] / 'results.json'
            run = json.loads(path.read_text())
            run['modes']['tcp-fixture']['tcp_bidir']['down_mbps'] = 999
            write(path, run)
            with self.assertRaisesRegex(ValueError, 'summary disagrees with raw iperf'):
                aggregate(runs, measurements_only=True)


if __name__ == '__main__':
    unittest.main()
