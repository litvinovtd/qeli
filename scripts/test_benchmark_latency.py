import unittest

from benchmark_evidence import parse_ping_latency


def population(values, transmitted=None):
    transmitted = len(values) if transmitted is None else transmitted
    lines = [f'[{1000+i*.02:.6f}] 64 bytes from 10.9.0.1: icmp_seq={i+1} ttl=64 time={v} ms' for i,v in enumerate(values)]
    lines.append(f'{transmitted} packets transmitted, {len(values)} received, {100*(transmitted-len(values))/transmitted:.3g}% packet loss, time 2000ms')
    return '\n'.join(lines)


class LatencyTests(unittest.TestCase):
    def test_nearest_rank_retains_tail_and_every_sample(self):
        result = parse_ping_latency(population(range(100, 0, -1)), 100)
        self.assertEqual([result[k] for k in ('p50_ms','p95_ms','p99_ms','max_ms')], [50,95,99,100])
        self.assertEqual(len(result['replies']), 100)
        result = parse_ping_latency(population(range(200, 0, -1)), 200)
        self.assertEqual([result[k] for k in ('p50_ms','p95_ms','p99_ms','max_ms')], [100,190,198,200])

    def test_loss_is_separate_from_received_rtt_population(self):
        result = parse_ping_latency(population([1,2,100], 4), 4)
        self.assertEqual((result['lost_percent'],result['received'],result['p99_ms']), (25,3,100))

    def test_truncated_missing_duplicate_and_censored_refuse(self):
        raw = population([1,2,3])
        for changed in (raw.replace('3 packets','2 packets'), raw.split('\n',1)[1],
                        raw.replace('icmp_seq=2','icmp_seq=1'), raw.replace('time=1','time<1'),
                        raw+'\n'+raw.splitlines()[-1], raw.replace('0% packet loss','40% packet loss')):
            with self.subTest(raw=changed), self.assertRaises(ValueError):
                parse_ping_latency(changed,3)

    def test_invalid_request_and_empty_population_refuse(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError): parse_ping_latency(population([1]), value)
        with self.assertRaises(ValueError):
            parse_ping_latency('3 packets transmitted, 0 received, 100% packet loss, time 2000ms',3)


if __name__ == '__main__':
    unittest.main()
