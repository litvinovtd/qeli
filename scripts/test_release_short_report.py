import copy
import unittest
from release_short_report import baseline, compare, distribution, review_warnings, sockets, validate_mixed
from release_short_test import CORE


class ShortReportTest(unittest.TestCase):
    def test_nearest_rank(self):
        self.assertEqual(distribution(list(range(1,21)))['p95'],19)
        self.assertIsNone(distribution([]))

    def test_ss_ipv4_and_ipv6(self):
        parsed=sockets('0 123 10.9.0.2:1000 10.9.0.1:5201\n rtt:9.5/1.1 cwnd:123 bytes_sent:2000000\n'
                       '0 0 [fd42:206:1::2]:1001 [fd42:206:1::1]:5202\n rtt:1.5/0.2 cwnd:456\n')
        self.assertEqual(len(parsed),2)
        self.assertEqual(parsed[0]['rtt'],9.5)
        self.assertEqual(parsed[1]['cwnd'],456)
        self.assertEqual(parsed[1]['peer'],'fd42:206:1::1')

    def test_baseline_requires_both_families_directions_repeats(self):
        with self.assertRaises(RuntimeError):
            baseline([])
        rows=[dict(stage='baseline',family=f,direction=d,phase=p,mbps=100)
              for f in (4,6) for d in ('upload','download') for p in ('before','after') for _ in range(3)]
        self.assertEqual(len(baseline(rows)),4)
        self.assertEqual(baseline(rows)['6/download']['drift_percent'],0)

    def reference(self):
        return dict(method='test',rates={'a':[300,600]},environment={'kernel':'a'},
                    source_hashes={'helper':'pinned','controller':'pinned'},
                    performance_fixture_sha256={'a':'hash'},measurement_status='VALID',udp_failed_groups=[],
                    unstable_groups=[],aggregates={'a':dict(n=3,median_mbps=100,cv_percent=1,max_loss_percent=0)})

    def test_compare_fails_closed_on_config_or_method_change(self):
        a=self.reference()
        for key,value in (('rates',{}),('method','other'),('environment',{}),('source_hashes',{}),('performance_fixture_sha256',{})):
            b=copy.deepcopy(a)
            b[key]=value
            with self.assertRaises(RuntimeError):
                compare(a,b)

    def test_reject_unstable_reference(self):
        a=self.reference()
        b=copy.deepcopy(a)
        b['unstable_groups']=['a']
        with self.assertRaises(RuntimeError):
            compare(a,b)

    def test_compare_individual_cells(self):
        a=self.reference()
        b=copy.deepcopy(a)
        a['aggregates']['a']['median_mbps']=80
        self.assertAlmostEqual(compare(a,b)['a']['throughput_delta_percent'],-20)

    def test_rtt_warning_requires_relative_and_absolute_growth(self):
        metric=dict(inner_rtt_ms=dict(p95=10),server=dict(cpu_percent_per_mbps=1,rss_peak_kib=100,tun_drop_ppm=10),
                    client=dict(cpu_percent_per_mbps=1,rss_peak_kib=100,tun_drop_ppm=10))
        ref=dict(metric_aggregates={'cell':metric})
        new=copy.deepcopy(ref)
        new['metric_aggregates']['cell']['inner_rtt_ms']['p95']=11.9
        self.assertEqual(review_warnings(new,ref),[])
        new['metric_aggregates']['cell']['inner_rtt_ms']['p95']=13
        self.assertEqual(len(review_warnings(new,ref)),1)

    def test_mixed_receipt_is_complete_and_sequential(self):
        main=dict(binary_sha256='a'*64,rates={m:[300,600] for m in CORE},finished_utc='2026-10-16T10:00:00+00:00')
        value=dict(method='qeli-release-short-mixed-v1',status='complete',binary_sha256='a'*64,
                   rates=main['rates'],started_utc='2026-10-16T11:00:00+00:00',sessions=list(CORE),windows=[],
                   restoration={r:dict(processes=True) for r in ('server','client')})
        for m in CORE:
            for f in (4,6):
                value['windows'].append(dict(stage='mixed',mode=m,family=f,overlap_seconds=30,results=[
                    dict(protocol=p,direction=d,streams=s,seconds=30,omit=2,mbps=300,rate_mbps=300,
                         loss_percent=0,cookie=m+str(f)+p,label=m+str(f)+p)
                    for p,d,s in (('TCP','download',4),('UDP','upload',1))]))
        self.assertEqual(validate_mixed(value,main),[])
        value['started_utc']='2026-10-16T09:00:00+00:00'
        with self.assertRaises(RuntimeError):
            validate_mixed(value,main)
        value['started_utc']='2026-10-16T11:00:00+00:00'
        value['windows'].pop()
        with self.assertRaises(RuntimeError):
            validate_mixed(value,main)


if __name__=='__main__':
    unittest.main()
