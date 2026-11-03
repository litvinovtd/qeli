from pathlib import Path
import unittest

from benchmark_auth import admit_burst, instrument_peer


def row(index=0):
    start = 1_000_000_000 + index * 1_000_000
    return dict(case='valid', transport='tcp', accepted=True, server_proof_verified=True, response='OK',
        hello_started_ns=start, proof_verified_ns=start + 2_000_000,
        auth_started_ns=start + 3_000_000, auth_verified_ns=start + 8_000_000)


class AuthEvidenceTests(unittest.TestCase):
    def test_rates_use_shared_burst_interval_not_sum_of_durations(self):
        result = admit_burst([row(), row(1)], 'tcp', 2)
        self.assertAlmostEqual(result['burst_seconds'], .009)
        self.assertAlmostEqual(result['burst_admissions_per_second'], 2 / .009)
        self.assertEqual(result['auth_ms'], [5, 5])
        self.assertEqual(result['handshake_ms'], [8, 8])
        self.assertEqual(result['release_start_spread_ms'], 1)

    def test_no_missing_failed_or_wrong_transport_peer_can_be_filtered(self):
        with self.assertRaises(ValueError): admit_burst([row()], 'tcp', 2)
        for key, value in [('accepted', False), ('accepted', 1), ('server_proof_verified', False),
                           ('response', 'ERR'), ('case', 'legacy'), ('transport', 'udp')]:
            bad = row(); bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                admit_burst([row(), bad], 'tcp', 2)

    def test_invalid_or_reversed_clocks_are_refused(self):
        for key, value in [('hello_started_ns', True), ('auth_started_ns', 0),
                           ('auth_verified_ns', float('nan')), ('auth_verified_ns', 1_001_000_000),
                           ('auth_verified_ns', 1_003_000_000)]:
            bad = row(); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): admit_burst([bad], 'tcp', 1)

    def test_nearest_rank_and_each_raw_latency_are_preserved(self):
        peers = [row(index) for index in range(4)]
        peers[-1]['auth_verified_ns'] += 20_000_000
        result = admit_burst(peers, 'tcp', 4)
        self.assertEqual(result['auth_ms'], [5, 5, 5, 25])
        self.assertEqual(result['auth_p50_ms'], 5)
        self.assertEqual(result['auth_p95_ms'], 25)
        self.assertEqual(result['auth_max_ms'], 25)

    def test_instrumentation_reuses_contract_peer_and_refuses_source_drift(self):
        source = (Path(__file__).resolve().parents[1] / 'qeli/examples/audit_auth_contracts.rs').read_text()
        output = instrument_peer(source)
        self.assertIn('barrier("go")?;\n    let hello_started_ns', output)
        self.assertIn('std::io::stdout().flush()?;\n    barrier("release")?', output)
        for removed in [source.replace('wire.send(&hello, true)?;', 'send_changed();'),
                        source.replace('    let mut auth =', '    let auth ='), source + '// changed\n']:
            with self.assertRaises(ValueError): instrument_peer(removed)
        self.assertEqual(output.count('derive_keys_hybrid('), source.count('derive_keys_hybrid('))


if __name__ == '__main__': unittest.main()
