"""Rejected iperf windows retain both endpoint diagnostics without admission."""
import copy
import json
import shlex
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import benchmark_isolated_lab as lab
from test_benchmark_bidir import raw_result
from test_benchmark_udp_ipv6 import udp_result


class MeasureEvidenceTests(unittest.TestCase):
    def test_probe_limits_sends_without_iputils_reply_deadline(self):
        for ip in ('10.9.0.1', 'fd42:36:9::1'):
            command = shlex.split(lab.latency_probe_command(ip))
            ping = command[command.index('ping'):]
            self.assertEqual(ping[ping.index('-c')+1], '200')
            self.assertNotIn('-w', ping)
            self.assertEqual(command[:4], ['timeout', '--signal=INT', '--kill-after=2', '15'])
            self.assertEqual(command[-1], ip)
        for ip in ('host.example', '10.9.0.1; echo injected', '[fd42:36:9::1]'):
            with self.assertRaises(ValueError): lab.latency_probe_command(ip)

    def test_real_deadline_oversend_stays_rejected(self):
        from benchmark_evidence import parse_ping_latency
        raw = (Path(__file__).parent/'fixtures/benchmark_ping_deadline_oversend.txt').read_text()
        with self.assertRaisesRegex(ValueError, 'population truncated'):
            parse_ping_latency(raw, 200)

    def rejected_window(self, raw, flags, bitrate, target='10.9.0.1'):
        sample = {'pid': 123, 'elapsed': 6}
        checked = mock.Mock(side_effect=lambda command, *args: json.dumps(
            sample if '/sample.py ' in command else raw))
        server = SimpleNamespace(lab=SimpleNamespace(checked=checked), remote='/fixture/server')
        client = SimpleNamespace(lab=SimpleNamespace(checked=checked), remote='/fixture/client',
                                 run_in=lambda command: command)
        kernel = [dict(RcvbufErrors=x) for x in (1, 4, 3, 9)]
        before = dict(dropped=1, bytes_sent=2, bytes_recv=3, connected_secs=4,
                      ip='10.9.0.2', peer='10.255.42.2')
        after = dict(before, dropped=2, bytes_sent=12, bytes_recv=13, connected_secs=10)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(lab, 'udp_kernel_all', side_effect=kernel) as counters, \
                 mock.patch.object(lab, 'application_stats', side_effect=[before, after]):
                with self.assertRaises(ValueError):
                    lab.measure(server, client, 123, 124, target, 'load', flags, 5,
                                root, expected_bitrate=bitrate)
                self.assertEqual(counters.call_args_list,
                                 [mock.call(server), mock.call(client), mock.call(server), mock.call(client)])
            self.assertEqual(json.loads((root/'load-iperf.json').read_text()), raw)
            self.assertEqual(json.loads((root/'load-processes.json').read_text()), [sample, sample])
            self.assertEqual(json.loads((root/'load-counters.json').read_text()), dict(
                before=dict(kernel=kernel[0], client_kernel=kernel[1], application=before),
                after=dict(kernel=kernel[2], client_kernel=kernel[3], application=after)))
            command = next(call.args[0] for call in checked.call_args_list if 'iperf3 -c ' in call.args[0])
            arguments = shlex.split(command)
            self.assertEqual(arguments[arguments.index('-c')+1], target)
            self.assertEqual('--get-server-output' in arguments, '--bidir' in arguments and '-u' not in arguments)

    def test_scoped_ipv6_literal_stays_one_shell_argument(self):
        # ipaddress accepts arbitrary scope text; address validation alone does
        # not quote a shell argument. No command with this target is executed.
        target = 'fe80::1%eth0; echo injected'
        arguments = shlex.split(lab.latency_probe_command(target))
        self.assertEqual(arguments[-1], target)
        raw = udp_result()
        del raw['end']['sum_received_bidir_reverse']
        self.rejected_window(raw, '-u -P 1 --bidir -b 100000000 -l 1200', 100000000, target)

    def test_truncated_tcp_receiver_keeps_after_counters_and_rejects(self):
        raw = copy.deepcopy(raw_result())
        raw['start']['test_start']['duration'] = 5
        raw['end']['sum_received_bidir_reverse']['seconds'] = 1
        self.rejected_window(raw, '-P 1 --bidir', 0)

    def test_missing_udp_reverse_keeps_after_counters_and_rejects(self):
        raw = udp_result()
        del raw['end']['sum_received_bidir_reverse']
        self.rejected_window(raw, '-u -P 1 --bidir -b 100000000 -l 1200', 100000000)


if __name__ == '__main__':
    unittest.main()
