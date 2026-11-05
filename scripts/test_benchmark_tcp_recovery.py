import copy
import math
import unittest
from benchmark_tcp_recovery import analyze, recovery_windows


class RecoveryEvidenceTests(unittest.TestCase):
    def samples(self):
        return [dict(seconds=i/2, bytes=i*1_250_000) for i in range(21)]

    def test_constant_delivery_distinguishes_one_and_five_second_confirmation(self):
        result = recovery_windows(self.samples(), 2, 18)
        one, five = [v['observation'] for v in result['confirmations']]
        self.assertEqual(one['confirmed_after_ready_s'], 1)
        self.assertEqual(five['confirmed_after_ready_s'], 5)
        self.assertEqual(one['mbps'], 20)

    def test_pre_admission_burst_cannot_fill_post_admission_window(self):
        samples = [dict(seconds=i, bytes=n) for i,n in enumerate(
            (0, 10_000_000, 20_000_000, 20_000_000, 20_000_000, 22_500_000, 25_000_000))]
        one = recovery_windows(samples, 2.1, 18, (1,))['confirmations'][0]['observation']
        self.assertEqual((one['start_s'], one['end_s']), (4, 5))

    def test_unobserved_gap_is_not_interpolated_into_early_recovery(self):
        samples = [dict(seconds=0, bytes=0), dict(seconds=1, bytes=0),
                   dict(seconds=10, bytes=22_500_000)]
        one = recovery_windows(samples, 1, 18, (1,))['confirmations'][0]['observation']
        self.assertEqual(one['end_s'], 10)
        self.assertEqual(one['duration_s'], 9)
        self.assertEqual(one['largest_sample_gap_s'], 9)

    def test_receiver_stall_and_insufficient_observation_are_not_recovery(self):
        samples = [dict(seconds=i, bytes=0) for i in range(4)]
        self.assertTrue(all(v['observation'] is None for v in
                            recovery_windows(samples, 0, 18)['confirmations']))
        self.assertIsNone(recovery_windows(self.samples(), 9, 18)['confirmations'][1]['observation'])

    def test_corrupt_samples_are_rejected(self):
        for field,value in (('seconds', math.nan), ('seconds', math.inf),
                            ('seconds', True), ('seconds', -.5),
                            ('bytes', -1), ('bytes', 2.5), ('bytes', True)):
            samples=self.samples();samples[1][field]=value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError):
                recovery_windows(samples, 0, 18)
        samples=self.samples();samples[2]['bytes']=0
        with self.assertRaises(ValueError):recovery_windows(samples, 0, 18)
        samples=self.samples();samples[1]['seconds']=0
        with self.assertRaises(ValueError):recovery_windows(samples, 0, 18)

    def test_invalid_or_unbracketed_admission_is_rejected(self):
        for ready in (-1, 10, math.inf, True):
            with self.subTest(ready=ready),self.assertRaises(ValueError):
                recovery_windows(self.samples(), ready, 18)
        for threshold in (0, -1, math.nan, True):
            with self.subTest(threshold=threshold),self.assertRaises(ValueError):
                recovery_windows(self.samples(), 0, threshold)

    def test_integrity_and_independently_polled_retirement(self):
        evidence=dict(schema='qeli.tcp-recovery.v1',threshold_mbps=18,
                      events=dict(fault_s=0,downlink_ready_s=2,carrier_replaced_s=2.1),
                      receiver=dict(samples=self.samples(),expected_bytes=25_000_000,
                                    received_bytes=25_000_000,sequence_errors=0,exit_status=0))
        self.assertTrue(analyze(evidence)['integrity_verified'])
        for key,value in (('received_bytes', 1), ('sequence_errors', 1), ('exit_status', 1),
                          ('expected_bytes', True)):
            bad=copy.deepcopy(evidence);bad['receiver'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):analyze(bad)


if __name__ == '__main__':
    unittest.main()
