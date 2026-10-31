import json
from pathlib import Path
import tempfile
import unittest
import sys
from unittest.mock import patch
from types import SimpleNamespace
import contextlib
import io

import release_short_guest as guest


class GuestOwnershipTest(unittest.TestCase):
    def test_spawn_waits_for_the_intended_executable(self):
        expected=str(Path(sys.executable).resolve())
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'owned').mkdir()
            child=SimpleNamespace(pid=12345,poll=lambda:None)
            with patch.object(guest.shutil,'which',return_value=expected), \
                    patch.object(guest.subprocess,'Popen',return_value=child), \
                    patch.object(guest,'identity',side_effect=[('/launching/python','100','R'),(expected,'100','S')]) as identity, \
                    patch.object(guest.os,'getpgid',return_value=12345,create=True), \
                    patch.object(guest.time,'sleep'):
                self.assertEqual(guest.spawn(root,'child',[expected]),12345)
            self.assertEqual(identity.call_count,2)
            self.assertEqual(json.loads((root/'owned/child.json').read_text()),dict(pid=12345,exe=expected,start='100'))

    def test_spawn_does_not_adopt_a_reused_pid(self):
        expected=str(Path(sys.executable).resolve())
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'owned').mkdir()
            child=SimpleNamespace(pid=12345,poll=lambda:None)
            with patch.object(guest.shutil,'which',return_value=expected), \
                    patch.object(guest.subprocess,'Popen',return_value=child), \
                    patch.object(guest,'identity',side_effect=[('/launching/python','100','R'),(expected,'999','S')]), \
                    patch.object(guest.time,'sleep'),patch.object(guest.os,'killpg',create=True) as kill:
                with self.assertRaisesRegex(RuntimeError,'PID reused during spawn'):
                    guest.spawn(root,'child',[expected])
                kill.assert_not_called()
            self.assertTrue(json.loads((root/'owned/child.json').read_text())['launching'])

    def test_spawn_timeout_retains_uncertain_ownership(self):
        expected=str(Path(sys.executable).resolve())
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'owned').mkdir()
            child=SimpleNamespace(pid=12345,poll=lambda:None)
            with patch.object(guest.shutil,'which',return_value=expected), \
                    patch.object(guest.subprocess,'Popen',return_value=child), \
                    patch.object(guest,'identity',return_value=('/unexpected/executable','100','S')), \
                    patch.object(guest.time,'monotonic',side_effect=[0,6]), \
                    patch.object(guest.os,'killpg',create=True) as kill:
                with self.assertRaisesRegex(RuntimeError,'did not settle'):
                    guest.spawn(root,'child',[expected])
                kill.assert_not_called()
            self.assertTrue((root/'owned/child.json').exists())

    def receipt(self, root):
        (root/'owned').mkdir()
        path=root/'owned'/'child.json'
        path.write_text(json.dumps(dict(pid=12345,exe='/private/qeli',start='100')))
        return path

    def test_exited_child_does_not_fail_cleanup(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            receipt=self.receipt(root)
            with patch.object(guest,'identity',side_effect=FileNotFoundError):
                guest.halt(root)
            self.assertFalse(receipt.exists())

    def test_pid_reuse_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            receipt=self.receipt(root)
            with patch.object(guest,'identity',return_value=('/private/qeli','999','S')), patch.object(guest.os,'killpg',create=True) as kill:
                with self.assertRaises(RuntimeError):
                    guest.halt(root)
                kill.assert_not_called()
            self.assertTrue(receipt.exists())

    def test_changed_executable_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);receipt=self.receipt(root)
            with patch.object(guest,'identity',return_value=('/foreign/executable','100','S')), \
                    patch.object(guest.os,'killpg',create=True) as kill:
                with self.assertRaisesRegex(RuntimeError,'ownership changed'):
                    guest.halt(root)
                kill.assert_not_called()
            self.assertTrue(receipt.exists())

    def test_kill_escalation_revalidates_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);receipt=self.receipt(root)
            observations=[('/private/qeli','100','S')]*61+[('/foreign/exe','100','S')]
            with patch.object(guest,'identity',side_effect=observations), \
                    patch.object(guest.os,'getpgid',return_value=12345,create=True), \
                    patch.object(guest.os,'killpg',create=True) as kill,patch.object(guest.time,'sleep'):
                with self.assertRaisesRegex(RuntimeError,'before SIGKILL'):
                    guest.halt(root)
                kill.assert_called_once_with(12345,guest.signal.SIGTERM)
            self.assertTrue(receipt.exists())

    def test_process_disappears_during_signal(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            receipt=self.receipt(root)
            with patch.object(guest,'identity',return_value=('/private/qeli','100','S')), \
                    patch.object(guest.os,'getpgid',return_value=12345,create=True), \
                    patch.object(guest.os,'killpg',side_effect=ProcessLookupError,create=True):
                guest.halt(root)
            self.assertFalse(receipt.exists())

    def test_launch_uses_private_device_id(self):
        with patch.object(sys,'argv',['guest','/opt/qeli-release-short-unit','launch','client','unit']), \
                patch.object(guest.os,'umask'),patch.object(guest,'spawn',return_value=123) as spawn, \
                contextlib.redirect_stdout(io.StringIO()):
            guest.main()
            env=spawn.call_args.args[3]
            self.assertEqual(Path(env['QELI_DEVICE_ID_FILE']),Path('/opt/qeli-release-short-unit/state/device-id'))

    def test_measure_rejects_nonfinite_statistics(self):
        spec=dict(label='unit',family=4,target='10.9.0.1',port=5201,seconds=10,omit=2,
                  protocol='UDP',streams=1,rate_mbps=300,direction='upload')
        for field in ('bits_per_second','lost_percent','jitter_ms'):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                (root/'windows'/'unit').mkdir(parents=True)
                received=dict(seconds=10,bits_per_second=300e6,lost_percent=0,jitter_ms=0)
                received[field]=float('nan')
                data=dict(start=dict(test_start=dict(protocol='UDP',num_streams=1,duration=10,omit=2),
                                     connected=[dict(remote_host='10.9.0.1',remote_port=5201)],cookie='unique'),
                          end=dict(sum_received=received,sum_sent={}))
                with patch.object(guest,'owned_run',return_value=SimpleNamespace(stdout=json.dumps(data),stderr='',returncode=0)):
                    with self.assertRaises(RuntimeError):
                        guest.measure(root,spec)

    def test_mixed_requires_overlapping_workloads(self):
        spec=dict(label='group',family=4,target='10.9.0.1',seconds=30,omit=2,rate_mbps=300)
        for overlaps in (True,False):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                (root/'windows').mkdir()
                def measured(_, s):
                    start=1e9 if overlaps or s['protocol']=='TCP' else 40e9
                    return dict(**s,started_ns=start,finished_ns=start+32e9)
                with patch.object(guest,'measure',side_effect=measured):
                    if overlaps:
                        result=guest.mixed(root,spec)
                        self.assertEqual(result['overlap_seconds'],32)
                        self.assertEqual({r['port'] for r in result['results']},{5201,5202})
                    else:
                        with self.assertRaises(RuntimeError):
                            guest.mixed(root,spec)


if __name__=='__main__':
    unittest.main()
