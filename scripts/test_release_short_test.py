import json
from pathlib import Path
import tempfile
import unittest
import contextlib
import io
from types import SimpleNamespace
from unittest.mock import Mock, patch

import release_short_test as short


class ReleaseShortTest(unittest.TestCase):
    def setUp(self):
        self.rates = {mode:[300,600] for mode in short.CORE}

    def test_plan_coverage(self):
        sessions=short.plan()
        self.assertEqual(len(sessions),56)
        self.assertEqual(sum(len(short.tasks(s,self.rates)) for s in sessions)+24,384)
        self.assertEqual({s['mode'] for s in sessions if s['policy']=='off'},set(short.MODES))
        self.assertEqual(len([s for s in sessions if s['stage']=='perf']),12)
        self.assertEqual({s['mode'] for s in sessions if s['outer']==6},set(short.CORE))

    def test_no_candidate_rate_adjustment(self):
        session=dict(stage='perf',mode='udp-quic')
        tasks=short.tasks(session,self.rates)
        self.assertEqual(len(tasks),16)
        self.assertEqual({s['rate_mbps'] for s in tasks if s['protocol']=='UDP'},{300,600})
        self.assertEqual({s['streams'] for s in tasks if s['protocol']=='TCP'},{1,4})

    def test_smoke_is_explicitly_not_full_plan(self):
        sessions=short.selected_plan(True)
        self.assertEqual(len(sessions),4)
        self.assertEqual(sum(len(short.tasks(s,self.rates)) for s in sessions),16)
        self.assertTrue(all(s['stage']=='smoke' for s in sessions))

    def test_mixed_is_separate_bounded_scope(self):
        sessions=short.selected_plan(mixed_only=True)
        self.assertEqual(len(sessions),4)
        windows=[w for s in sessions for w in short.tasks(s,self.rates)]
        self.assertEqual(len(windows),8)
        self.assertTrue(all(w['protocol']=='MIXED' and w['seconds']==30 for w in windows))

    def test_fixture_literal_queue_and_ipv6(self):
        server='[profile:bench]\nidentity_key=/identity\n[logging]\nlevel=info\n'
        client='[qeli]\nkey=public\n[logging]\nlevel=info\n'
        s,c=short.configure(server,client,'tcp-reality-tls','fd42:82:1::10','/opt/qeli-release-short-test')
        self.assertIn('obf.mode = reality-tls',s)
        self.assertIn('server = [fd42:82:1::10]:443',c)
        self.assertIn('tun.tx_queue_len = 1000',c)
        self.assertNotIn('[tun]',c)
        _,c=short.configure(server,client,'tcp-faketls','172.30.82.10','/opt/qeli-release-short-test',client_queue=False)
        self.assertNotIn('tun.tx_queue_len',c)

    def test_no_empty_restoration_pass(self):
        with self.assertRaises(KeyError):
            short.restoration({}, {})

    def test_stable_excludes_only_lifetimes(self):
        self.assertEqual(short.stable({'expires':1,'mtu':1400}),{'mtu':1400})
        self.assertNotEqual(short.stable({'txqlen':500}),short.stable({'txqlen':1000}))

    def test_aggregate_preserves_failures(self):
        rows=[dict(stage='perf',mode='udp-quic',family=6,direction='upload',protocol='UDP',streams=1,
                   rate_mbps=600,mbps=v,loss_percent=l,retransmits=None) for v,l in ((600,0),(590,2),(600,0))]
        value=next(iter(short.aggregate(rows).values()))
        self.assertEqual(value['n'],3)
        self.assertEqual(value['max_loss_percent'],2)
        self.assertEqual(value['min_mbps'],590)

    def test_atomic_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'result.json'
            short.atomic(p,{'status':'failed'})
            self.assertEqual(json.loads(p.read_text()),{'status':'failed'})

    def test_lock_refusal_never_touches_existing_root(self):
        cfg=dict(hosts=dict(server='server',client='client'),udp_rates=self.rates,
                 candidate_sha256='a'*64,previous_sha256='b'*64,
                 udp_buffers=dict(apply=False,qeli_receive_bytes=4194304,iperf_receive_rb_bytes=4194304))
        for effects in ([RuntimeError('lock busy')], ['',RuntimeError('root exists'),'']):
            guest=SimpleNamespace(role='server',cmd=Mock(side_effect=effects),helper=Mock(),put=Mock(),
                                  c=SimpleNamespace(close=Mock()))
            with tempfile.TemporaryDirectory() as folder, patch.object(short,'Guest',return_value=guest), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(RuntimeError):
                    short.execute(cfg,'existing',Path(folder)/'receipt.json')
                guest.helper.assert_not_called()
                guest.put.assert_not_called()
                guest.c.close.assert_called_once()

    def test_buffer_pilot_is_required_only_not_full_qualification(self):
        sessions=short.selected_plan(buffer_pilot=True)
        self.assertEqual(len(sessions),4)
        self.assertTrue(all(s['policy']=='required' for s in sessions))
        windows=[w for s in sessions for w in short.tasks(s,self.rates)]
        self.assertEqual(len(windows)+8,40)
        self.assertEqual({w['rate_mbps'] for w in windows if w['protocol']=='UDP'},{600})

    def test_buffer_reference_is_three_repeats_same_pilot_load(self):
        sessions=short.selected_plan(buffer_reference=True)
        self.assertEqual(len(sessions),12)
        self.assertTrue(all(s['policy']=='required' and s['stage']=='perf' for s in sessions))
        self.assertEqual({s['rep'] for s in sessions},{1,2,3})
        self.assertEqual(sum(len(short.tasks(s,self.rates)) for s in sessions)+24,120)
        self.assertEqual([s['mode'] for s in sessions[:4]],list(short.CORE))
        self.assertEqual([s['mode'] for s in sessions[4:8]],list(reversed(short.CORE)))
        self.assertTrue(all(w['streams']==4 if w['protocol']=='TCP' else w['rate_mbps']==600
                            for s in sessions for w in short.tasks(s,self.rates)))


if __name__=='__main__':
    unittest.main()
