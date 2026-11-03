"""Fail-closed checks for iperf results admitted by the isolated benchmark."""

import copy
import contextlib
import io
import json
import math
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import benchmark_isolated_lab as benchmark
from benchmark_evidence import counter_deltas, parse_iperf_result


def result(protocol='tcp'):
    received = dict(seconds=8.01 if protocol == 'tcp' else 5.01,
                    bytes=8_000_000, bits_per_second=8_000_000)
    if protocol == 'udp':
        received.update(lost_percent=2.5, jitter_ms=0.4)
    return dict(end=dict(sum_received=received, sum_sent=dict(retransmits=3),
                         sum=dict(received)))


class IperfAdmissionTests(unittest.TestCase):
    def test_tcp_and_udp_receiver_metrics(self):
        self.assertEqual(parse_iperf_result(result(), 'tcp', 8),
                         dict(mbps=8.0, retransmits=3, lost_percent=None, jitter_ms=None))
        self.assertEqual(parse_iperf_result(result('udp'), 'udp', 5),
                         dict(mbps=8.0, retransmits=None, lost_percent=2.5, jitter_ms=0.4))

    def test_sender_only_summary_cannot_replace_missing_receiver(self):
        raw = result()
        del raw['end']['sum_received']
        with self.assertRaisesRegex(ValueError, 'receiver summary missing'):
            parse_iperf_result(raw, 'tcp', 8)

    def test_truncated_receiver_interval_cannot_count_as_complete(self):
        raw = result()
        raw['end']['sum_received']['seconds'] = 1
        with self.assertRaisesRegex(ValueError, 'interval truncated'):
            parse_iperf_result(raw, 'tcp', 8)

    def test_invalid_metrics_cannot_count_as_complete(self):
        mutations = (
            ('tcp', ('sum_received', 'bits_per_second'), math.nan),
            ('tcp', ('sum_received', 'bytes'), -1),
            ('tcp', ('sum_sent', 'retransmits'), None),
            ('udp', ('sum_received', 'lost_percent'), 101),
            ('udp', ('sum_received', 'jitter_ms'), math.inf),
        )
        for protocol, (section, field), value in mutations:
            with self.subTest(protocol=protocol, field=field, value=value):
                raw = copy.deepcopy(result(protocol))
                raw['end'][section][field] = value
                with self.assertRaises(ValueError):
                    parse_iperf_result(raw, protocol, 8 if protocol == 'tcp' else 5)

    def test_iperf_error_is_rejected_even_with_summary(self):
        raw = result()
        raw['error'] = 'server terminated'
        with self.assertRaisesRegex(ValueError, 'iperf error'):
            parse_iperf_result(raw, 'tcp', 8)


class RunnerFailureTests(unittest.TestCase):
    def test_second_connection_failure_closes_first_and_publishes_failure(self):
        lab = mock.Mock()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'run'
            argv = ['benchmark_isolated_lab.py', '--sha256', 'a' * 64, '--output', str(output)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.dict(os.environ, {'QELI_LAB_PASS': 'fixture'}), \
                 mock.patch.object(benchmark, 'connect_lab', side_effect=[lab, RuntimeError('second connection refused')]), \
                 mock.patch.object(benchmark, 'source_digest', return_value='b' * 64), \
                 mock.patch.object(benchmark.subprocess, 'check_output', return_value=''), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(benchmark.main(), 1)
            saved = json.loads((output / 'results.json').read_text())
            lab.close.assert_called_once()
            lab.run.assert_not_called()
            self.assertEqual(saved['status'], 'FAIL')
            self.assertFalse(saved['host_restored'])
            self.assertEqual(saved['meta']['binary_source_provenance'], 'UNVERIFIED')
            self.assertNotIn('source_commit', saved['meta'])
            self.assertNotIn('native_source_digest', saved['meta'])
            self.assertIn('second connection refused', saved['errors'])

    def test_cleanup_attempts_every_fixture_after_failure(self):
        first, second = mock.Mock(), mock.Mock()
        first.close.side_effect = RuntimeError('first cleanup refused')
        with self.assertRaisesRegex(RuntimeError, 'first cleanup refused'):
            benchmark.cleanup_fixtures(first, second)
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_missing_tunnel_mtu_refuses(self):
        fixture = mock.Mock()
        fixture.checked.return_value = '[{"ifname":"qd14v","mtu":1500}]'
        with self.assertRaisesRegex(RuntimeError, 'MTUs missing'):
            benchmark.fixture_mtus(fixture)

    def test_governor_unavailability_is_recorded(self):
        lab = mock.Mock()
        lab.checked.side_effect = lambda command, label: '{"availability":"UNAVAILABLE","policies":{}}' if label == 'cpu_governor' else 'fixture'
        self.assertEqual(benchmark.host_metadata(lab, '/fixture/qeli')['cpu_governor'],
                         dict(availability='UNAVAILABLE', policies={}))

    def test_counter_reset_or_session_replacement_refuses(self):
        before = dict(kernel=dict(RcvbufErrors=10), application=dict(ip='10.9.0.2', peer='10.255.42.2:123',
                      connected_secs=10, dropped=20, bytes_sent=30, bytes_recv=40))
        after = copy.deepcopy(before)
        after['application']['dropped'] = 21
        self.assertEqual(counter_deltas(before, after)['server_session_drops'], 1)
        for area, key, value in (('application', 'bytes_recv', 0), ('kernel', 'RcvbufErrors', 0), ('application', 'peer', 'replacement')):
            with self.subTest(key=key):
                changed = copy.deepcopy(after)
                changed[area][key] = value
                with self.assertRaises(ValueError):
                    counter_deltas(before, changed)


if __name__ == '__main__':
    unittest.main()
