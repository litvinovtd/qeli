import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import release_short_buffers as b
import release_short_guest as g


def text(rb=8388608, pid=123, address='[fd42::1]:5202'):
    return f'ESTAB 0 0 {address} [fd42::2]:56789 users:(("iperf3",pid={pid},fd=7)) ino:42\n skmem:(r0,rb{rb},t0,tb212992,f0,w0,o0,bl0,d0)\n'


class BuffersTest(unittest.TestCase):
    def test_accounting_and_ownership(self):
        row=b.sockets(text())[0]
        self.assertEqual((row['rb'],row['tb'],row['inode']),(8388608,212992,42))
        self.assertEqual(b.owned([row],{'999':{}}),[])
        self.assertEqual(b.qeli_check(dict(ss=text(),processes={'123':{}}),True,b.LIMIT)['sockets'][0]['rb']/2,b.LIMIT)
        for source in ('',text(425984),text(pid=999)):
            with self.assertRaises(RuntimeError):
                b.qeli_check(dict(ss=source,processes={'123':{}}),True,b.LIMIT)

    def test_actual_receiver_default_is_not_doubled(self):
        obs={r:dict(samples=[dict(udp_memory=dict(t=1,ss=text(b.LIMIT),processes={'123':{}}))]) for r in ('server','client')}
        self.assertTrue(b.iperf_check(obs,'download',b.LIMIT)['client']['receiver'])
        obs['client']['samples'][0]['udp_memory']['ss']=text(212992)
        with self.assertRaisesRegex(RuntimeError,'receiver rb'):
            b.iperf_check(obs,'download',b.LIMIT)
        self.assertTrue(b.iperf_check(obs,'upload',b.LIMIT)['server']['receiver'])
        obs['server']['samples']=[]
        with self.assertRaisesRegex(RuntimeError,'missing/duplicate'):
            b.iperf_check(obs,'upload',b.LIMIT)

    def test_explicit_policy(self):
        valid=dict(apply=False,qeli_receive_bytes=b.LIMIT,iperf_receive_rb_bytes=b.LIMIT)
        self.assertEqual(b.policy(valid)['version'],b.VERSION)
        for invalid in (None,{},dict(valid,apply='yes'),dict(valid,qeli_receive_bytes=212992)):
            with self.assertRaises(RuntimeError): b.policy(invalid)

    def test_rollback_restores_both_and_refuses_foreign_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'state').mkdir()
            original={k:212992 for k in b.KEYS}
            expected={k:b.LIMIT for k in b.KEYS}
            boot=Path(tmp)/'boot';boot.write_text('boot')
            g.save(root/'state/buffer-policy.json',dict(original=original,expected=expected,boot_id='boot'))
            values=copy.copy(expected)
            def run(args):
                self.assertEqual(args[:2],['sysctl','-w'])
                key,v=args[2].split('=');self.assertIn(key,b.KEYS);values[key]=int(v)
                return SimpleNamespace(stdout='')
            real_read=Path.read_text
            def read(path,*a,**kw):
                return 'boot' if str(path).replace('\\','/')=='/proc/sys/kernel/random/boot_id' else real_read(path,*a,**kw)
            with patch.object(g,'buffer_values',side_effect=lambda:dict(values)),patch.object(g,'run',side_effect=run),patch.object(Path,'read_text',read):
                g.buffer_restore(root)
                self.assertEqual(values,original)
                values.update(expected);values[b.KEYS[0]]=9999999
                with self.assertRaisesRegex(RuntimeError,'foreign buffer'):
                    g.buffer_restore(root)
                self.assertEqual(values[b.KEYS[0]],9999999)
                self.assertEqual(values[b.KEYS[1]],212992)  # Other rollback still attempted.

    def test_lease_expiry_rolls_back_even_if_halt_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'state').mkdir();(root/'state/lease-touch').touch()
            with patch.object(g.time,'time',return_value=10**12),patch.object(g,'halt',side_effect=RuntimeError('halt failed')),patch.object(g,'buffer_restore') as restore:
                with self.assertRaisesRegex(RuntimeError,'halt failed'):g.lease(root)
                restore.assert_called_once_with(root)

    def test_partial_setup_is_receipted_and_rolled_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'state').mkdir()
            values={k:212992 for k in b.KEYS}
            original=dict(values)
            real_read=Path.read_text
            def read(path,*a,**kw):
                return 'boot' if str(path).replace('\\','/')=='/proc/sys/kernel/random/boot_id' else real_read(path,*a,**kw)
            def run(args):
                self.assertTrue((root/'state/buffer-policy.json').exists())
                key,value=args[2].split('=')
                if key==b.KEYS[1] and int(value)==b.LIMIT:
                    raise RuntimeError('injected partial setup failure')
                values[key]=int(value)
                return SimpleNamespace(stdout='')
            with patch.object(g,'buffer_values',side_effect=lambda:dict(values)),patch.object(g,'processes',return_value={}),patch.object(g,'run',side_effect=run),patch.object(Path,'read_text',read):
                with self.assertRaisesRegex(RuntimeError,'partial setup failure'):
                    g.buffer_prepare(root,dict(apply=True,qeli_receive_bytes=b.LIMIT,iperf_receive_rb_bytes=b.LIMIT))
            self.assertEqual(values,original)


if __name__=='__main__': unittest.main()
