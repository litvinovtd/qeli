"""Independent INNER_PQ_V1 HKDF oracle and live-path wiring guards.

Behavioral/adversarial crypto and TLS/H2 tests live in Rust. These portable
checks prevent fixture drift or a platform/secondary path bypassing that core.
"""
from pathlib import Path
import hashlib
import hmac
import json
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]

def expand(prk, label):
    return hmac.digest(prk, label + b'\x01', 'sha256')  # one SHA-256 block, L=32

class InnerPqTests(unittest.TestCase):
    def test_independent_headers_and_kdf_known_answers(self):
        fixture = json.loads((ROOT/'conformance/inner-pq-v1.json').read_text())
        for side, magic, body in [('client', b'QELIPQ\0C',1216), ('server', b'QELIPQ\0S',1120)]:
            expected = magic + struct.pack('>HHHH',1,0x11ec,3,body) + bytes(16)
            self.assertEqual(expected.hex(), fixture[side+'_header'])
        transcript = hashlib.sha256(b'INNER_PQ_V1 KAT transcript').digest()
        self.assertEqual(transcript.hex(), fixture['transcript'])
        prk = hmac.digest(b'qeli-reality-inner-pq-v1', bytes(range(96)), 'sha256')
        root = expand(prk,b'transcript-bound-session-root\0'+transcript)
        for field,label in [('s2c',b'server-to-client-enc-key'),
                            ('c2s',b'client-to-server-enc-key'),('resume',b'qeli-resume-secret-v1')]:
            self.assertEqual(expand(root,label).hex(),fixture[field])

    def test_primary_and_secondary_use_the_same_required_exchange(self):
        session = (ROOT/'qeli/src/transport_core/session.rs').read_text(encoding='utf8')
        secondary = (ROOT/'qeli/src/client/mod.rs').read_text(encoding='utf8')
        primary = session.split('pub(crate) async fn authenticate_tcp',1)[1].split('let server_name',1)[0]
        secondary = secondary.split('async fn tcp_secondary_handshake',1)[1].split('let server_name',1)[0]
        for body in [primary,secondary]:
            self.assertIn('raw_client_keys(',body)
            self.assertNotIn('derive_keys_bound(',body)
            self.assertNotIn('derive_keys(',body)
        helper = session.split('pub(crate) async fn raw_client_keys',1)[1].split('/// Run the primary',1)[0]
        self.assertIn('config.obfuscation.mode == "reality-tls" && config.obfuscation.reality_compact',helper)
        required = helper.split('if config.obfuscation.mode',1)[1].split('stream.write_all_flush',1)[0]
        self.assertIn('inner_pq::client_exchange(stream, client, &pinned).await?',required)
        self.assertIn('return Ok(RawClientKeys',required)

    def test_server_dispatch_and_secrets_remain_bound(self):
        handler = (ROOT/'qeli/src/server/handler.rs').read_text(encoding='utf8')
        self.assertIn('inner_raw && prefix == crate::protocol::inner_pq::SENTINEL',handler)
        self.assertIn('inner_pq::server_exchange(',handler)
        self.assertIn('material.data_keys()',handler)
        self.assertIn('material.resume_secret()',handler)
        code = (ROOT/'qeli/src/protocol/inner_pq.rs').read_text(encoding='utf8')
        self.assertIn('client, server, identity',code)
        self.assertIn('check_header(&received_header, true)?',code)
        self.assertIn('check_header(&received_header, false)?',code)

if __name__ == '__main__':
    unittest.main()
