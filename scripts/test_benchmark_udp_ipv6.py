"""UDP-bidir receiver admission and independent inner/outer address families."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from benchmark_evidence import counter_deltas, measurement_phases, parse_iperf_bidir
from benchmark_isolated_lab import configs, phase_flags, udp_kernel, udp_kernel_all
from benchmark_report import aggregate
from test_benchmark_bidir import bidir_fixture
import benchmark as modes


def udp_result():
    end = {}
    for suffix, rate, lost in (('', 100, 1), ('_bidir_reverse', 50, 2)):
        end['sum_received'+suffix] = dict(seconds=5.01, bytes=10000, bits_per_second=rate*1e6,
            sender=False, packets=100, lost_packets=lost, lost_percent=lost, jitter_ms=.2)
        end['sum_sent'+suffix] = dict(seconds=5.01, bytes=12000, bits_per_second=900e6,
            sender=True, packets=100, lost_packets=0, lost_percent=0, jitter_ms=0)
    return dict(start=dict(target_bitrate=100000000, test_start=dict(protocol='UDP', duration=5,
        num_streams=1, reverse=0, bidir=1, target_bitrate=100000000, blksize=1200)), end=end)


class UdpIpv6Tests(unittest.TestCase):
    def test_udp_profile_is_mandatory_for_every_carrier_and_p4_is_per_stream(self):
        for transport in ('direct','tcp','udp'):
            self.assertEqual(measurement_phases('udp-bidir',transport),('udp_bidir',))
        self.assertEqual(phase_flags('udp_bidir',4),'-u -P 4 --bidir -b 100000000 -l 1200')

    def test_offline_udp_report_recomputes_both_receivers_and_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            runs=[]
            for i in range(3):
                root=bidir_fixture(Path(temporary)/str(i),i);runs.append(root)
                run=json.loads((root/'results.json').read_text());run['meta']['measurement']='udp-bidir'
                for name,summary in [('direct',run['baseline']),*run['modes'].items()]:
                    old=summary.pop('tcp_bidir');raw=udp_result()
                    raw['start']['timestamp']=dict(timesecs=i)
                    metric=parse_iperf_bidir(raw,5,1,protocol='udp',expected_bitrate=100000000)
                    summary['udp_bidir']=dict(old,**metric)
                    folder=root/name
                    (folder/'udp_bidir-iperf.json').write_text(json.dumps(raw))
                    if name!='direct':
                        for suffix in ('processes','counters'):
                            (folder/f'udp_bidir-{suffix}.json').write_bytes((folder/f'tcp_bidir-{suffix}.json').read_bytes())
                (root/'results.json').write_text(json.dumps(run))
            report=aggregate(runs)
            self.assertEqual(report['status'],'AGGREGATED')
            path=runs[1]/'udp-fixture/udp_bidir-iperf.json';raw=json.loads(path.read_text())
            raw['end']['sum_received_bidir_reverse']['jitter_ms']=10
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ValueError,'summary disagrees'):
                aggregate(runs)

    def test_two_udp_receivers_not_senders_and_all_loss_metrics(self):
        value = parse_iperf_bidir(udp_result(),5,1,expected_bitrate=100000000,protocol='udp')
        self.assertEqual((value['up_mbps'], value['down_mbps']), (100,50))
        self.assertEqual((value['up_lost_packets'],value['down_lost_percent'],value['down_jitter_ms']), (1,2,.2))

    def test_real_ipv4_and_ipv6_iperf318_fixtures(self):
        for family in (4,6):
            raw = json.loads((Path(__file__).parent/'fixtures'/f'benchmark_udp_bidir_ipv{family}.json').read_text())
            metric = parse_iperf_bidir(raw,5,1,expected_bitrate=100000000,protocol='udp')
            self.assertGreater(metric['up_mbps'],99)
            self.assertGreater(metric['down_mbps'],99)
            self.assertEqual((metric['up_lost_packets'],metric['down_lost_packets']),(0,0))

    def test_real_reverse_loss_uses_sender_population_not_receiver_packets(self):
        raw=json.loads((Path(__file__).parent/'fixtures/benchmark_udp_bidir_ipv6_p4_loss.json').read_text())
        metric=parse_iperf_bidir(raw,5,4,expected_bitrate=100000000,protocol='udp')
        self.assertEqual((metric['down_packets'],metric['down_sent_packets']),(204841,209056))
        self.assertAlmostEqual(metric['down_lost_percent'],100*28062/209056)
        self.assertGreater(metric['up_lost_percent'],19)
        raw['end']['sum_received_bidir_reverse']['lost_percent']=100*28062/204841
        with self.assertRaisesRegex(ValueError,'loss disagrees'):
            parse_iperf_bidir(raw,5,4,expected_bitrate=100000000,protocol='udp')

    def test_missing_swapped_truncated_or_invalid_reverse_refuses(self):
        for field,value in (('sender',True),('seconds',1),('packets',True),('packets',0),
                            ('lost_packets',-1),('lost_packets',101),('lost_percent',0),('jitter_ms',float('nan'))):
            raw=udp_result();raw['end']['sum_received_bidir_reverse'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                parse_iperf_bidir(raw,5,1,expected_bitrate=100000000,protocol='udp')
        raw=udp_result();del raw['end']['sum_received_bidir_reverse']
        with self.assertRaises(ValueError): parse_iperf_bidir(raw,5,1,expected_bitrate=100000000,protocol='udp')

    def test_protocol_parallel_size_duration_and_rate_are_bound(self):
        for field,value in (('protocol','TCP'),('num_streams',4),('blksize',1400),('duration',8),
                            ('bidir',0),('reverse',1),('target_bitrate',0)):
            raw=udp_result();raw['start']['test_start'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                parse_iperf_bidir(raw,5,1,expected_bitrate=100000000,protocol='udp')
        for parallel in (True,0,-1,1.0):
            with self.assertRaises(ValueError): parse_iperf_bidir(udp_result(),5,parallel,expected_bitrate=100000000,protocol='udp')
        raw=udp_result();raw['end']['sum_sent_bidir_reverse']['seconds']=1
        with self.assertRaisesRegex(ValueError,'sender interval'):
            parse_iperf_bidir(raw,5,1,expected_bitrate=100000000,protocol='udp')

    def test_kernel_ipv6_missing_duplicate_negative_and_unknown_family_refuse(self):
        fixture=mock.Mock();fixture.run_in.side_effect=lambda x:x
        fixture.checked.return_value='Ip6InReceives 10\nUdp6InDatagrams 7\nUdp6RcvbufErrors 2'
        self.assertEqual(udp_kernel(fixture,6),dict(InDatagrams=7,RcvbufErrors=2))
        for raw in ('Udp6InDatagrams 7','Udp6RcvbufErrors -1','Udp6RcvbufErrors 1\nUdp6RcvbufErrors 2','Udp6RcvbufErrors 1 2'):
            fixture.checked.return_value=raw
            with self.assertRaises(ValueError): udp_kernel(fixture,6)
        with self.assertRaises(ValueError): udp_kernel(fixture,True)

    def test_both_kernel_families_are_measured_and_one_reset_cannot_hide(self):
        with mock.patch('benchmark_isolated_lab.udp_kernel',side_effect=[dict(RcvbufErrors=4),dict(RcvbufErrors=7)]) as read:
            self.assertEqual(udp_kernel_all('fixture'),dict(ipv4=dict(RcvbufErrors=4),ipv6=dict(RcvbufErrors=7),RcvbufErrors=11))
            self.assertEqual(read.call_args_list,[mock.call('fixture',4),mock.call('fixture',6)])
        before=dict(kernel=dict(ipv4=dict(RcvbufErrors=4),ipv6=dict(RcvbufErrors=7),RcvbufErrors=11),
                    application=dict(dropped=0,bytes_sent=1,bytes_recv=1,connected_secs=1,ip='ip',peer='peer'))
        after=copy.deepcopy(before);after['kernel']['ipv6']['RcvbufErrors']=9;after['kernel']['RcvbufErrors']=13
        self.assertEqual(counter_deltas(before,after)['kernel_rcvbuf_drops'],2)
        for kernel in (dict(ipv4=dict(RcvbufErrors=3),ipv6=dict(RcvbufErrors=10),RcvbufErrors=13),
                       dict(ipv4=dict(RcvbufErrors=4),RcvbufErrors=13),
                       dict(ipv4=dict(RcvbufErrors=4),ipv6=dict(RcvbufErrors=9),RcvbufErrors=12)):
            after['kernel']=kernel
            with self.assertRaises(ValueError): counter_deltas(before,after)

    def test_independent_outer_inner_ini_and_original_ipv4_defaults(self):
        for mode in modes.MODES:
            default=configs(mode,'0'*64)
            self.assertEqual(default,configs(mode,'0'*64,outer_family=4,inner_family=4))
            for outer,inner in ((4,6),(6,4),(6,6)):
                server,client=configs(mode,'0'*64,outer_family=outer,inner_family=inner)
                self.assertIn('server = '+('[fd42:36:42::1]:' if outer==6 else '10.255.42.1:'),client)
                if inner==6:
                    self.assertIn('tun.ip_mode = ipv6',server)
                    self.assertNotIn('\npool.cidr =',server)
                    self.assertNotIn('\ntun.address =',server)
                    self.assertIn('ipv6 = required',client)
                else:self.assertNotIn('tun.ip_mode = ipv6',server)
        with self.assertRaises(ValueError): configs(modes.MODES[0],'key',outer_family=True)


if __name__=='__main__':unittest.main()
