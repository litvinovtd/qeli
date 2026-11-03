from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from benchmark_auth_native import admit_native_burst, instrument_sources, validate_control_path, validate_instrumented_peer
from benchmark import MODES
from test_benchmark_auth import row


class NativeAuthTests(unittest.TestCase):
    def test_stale_peer_refused_before_output_or_network_setup(self):
        import benchmark_auth_native_lab as runner
        with tempfile.TemporaryDirectory() as temp:
            peer = Path(temp) / 'stale-peer'
            peer.write_bytes(b'ordinary compiled CLI without private observer')
            output = Path(temp) / 'measurements'
            args = ['runner', '--qeli', str(peer), '--peer', str(peer), '--output', str(output)]
            with mock.patch.object(sys, 'argv', args), mock.patch.object(runner.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'lacks instrumentation marker'):
                    runner.main()
                run.assert_not_called()
            self.assertFalse(output.exists())

    def test_instrumentation_marker_across_read_boundary_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            peer = Path(temp) / 'peer'
            peer.write_bytes(b'\0' * (1024 * 1024 - 5) + b'QELI_AUTH_BARRIER' + b'\0')
            validate_instrumented_peer(peer)

    def test_control_path_limit_counts_utf8_bytes_and_refuses_before_start(self):
        validate_control_path(Path('/' + 'x' * 93))
        with self.assertRaises(ValueError): validate_control_path(Path('/' + 'x' * 94))
        with self.assertRaises(ValueError): validate_control_path(Path('/' + 'я' * 47))

    def sources(self):
        root = Path(__file__).resolve().parents[1] / 'qeli/src'
        return [(root / name).read_text() for name in ('transport_core/session.rs', 'client/mod.rs')]

    def test_instruments_actual_raw_hybrid_udp_paths_without_copying_crypto(self):
        original = self.sources()
        session, client = instrument_sources(*original)
        self.assertEqual(session.count('audit_auth_barrier("go").await?;'), 2)
        self.assertEqual(client.count('session::audit_auth_barrier("go").await?;'), 1)
        self.assertLess(client.index('parse_auth_ok(&response_str)?'), client.index('session::audit_auth_finish('))
        self.assertLess(client.index('server negotiated UDP_ROAM_V1 but omitted'), client.index('session::audit_auth_finish('))
        for before, after in zip(original, (session, client)):
            self.assertEqual(before.count('derive_keys_hybrid('), after.count('derive_keys_hybrid('))
            self.assertEqual(before.count('verify_server_identity('), after.count('verify_server_identity('))
        self.assertIn('std::process::exit(0)', session)

    def test_source_drift_and_double_instrumentation_are_refused(self):
        session, client = self.sources()
        with self.assertRaises(ValueError): instrument_sources(*instrument_sources(session, client))
        for changed in [session.replace('verify_key(server_static).await?;', 'changed();'),
                        session.replace('stream.write_all_flush(&client_hello).await?;', 'changed();')]:
            with self.assertRaises(ValueError): instrument_sources(changed, client)
        with self.assertRaises(ValueError):
            instrument_sources(session, client.replace('let n_frags = ch_frags.len();', 'let n_frags = 0;'))

    def test_all_native_modes_require_exact_pids_mode_handshake_and_proof(self):
        self.assertEqual(len(MODES), 12)
        for mode in MODES:
            peer = row()
            peer.update(pid=7, mode=mode['name'], transport='quic' if mode.get('quic') else mode['transport'],
                inner_handshake='raw_x25519' if mode['client_mode'] in ('plain', 'reality-tls') else 'hybrid_mlkem_x25519')
            self.assertEqual(admit_native_burst([peer], mode, 1, [7])['accepted'], 1)
            for key, value in [('pid', True), ('pid', 8), ('mode', 'other'), ('inner_handshake', 'other'),
                               ('accepted', False), ('server_proof_verified', False), ('response', 'ERR')]:
                bad = dict(peer); bad[key] = value
                with self.subTest(mode=mode['name'], key=key), self.assertRaises(ValueError):
                    admit_native_burst([bad], mode, 1, [7])
            with self.assertRaises(ValueError): admit_native_burst([peer, peer], mode, 2, [7, 7])


if __name__ == '__main__': unittest.main()
