#!/usr/bin/env python3
"""Q33 kernel tuning faults and recovery in private Linux chroot filesystems.

Actual Bash/coreutils publication, explicit sysctl/module seams. Full installer and
real namespaced kernel mutation are qualified separately by the manager gate.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest
import test_binary_installer as fixture


@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root/chroot required')
class TuningTests(unittest.TestCase):
    setUp=fixture.BinaryTests.setUp
    tearDownClass=fixture.BinaryTests.__dict__['tearDownClass']
    stub=fixture.BinaryTests.__dict__['stub']
    run_installer=fixture.BinaryTests.run_installer

    @classmethod
    def setUpClass(cls):
        fixture.BinaryTests.setUpClass.__func__(cls)
        source=Path(shutil.which('mv'));shutil.copy2(source,cls.base/'usr/bin/mv')
        for lib in re.findall(r'(/[^\s]+)',subprocess.run(['ldd',str(source)],capture_output=True,text=True).stdout):
            target=cls.base/lib.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(lib,target)
        for name in ['etc/sysctl.d','etc/modules-load.d','etc/qeli/client-links','records/kernel']:
            (cls.base/name).mkdir(parents=True,exist_ok=True)
        cls.stub('sysctl',r'''case "$1" in
 -n) [[ "$2" != net.ipv4.tcp_moderate_rcvbuf || "$(< /records/mode)" != moderate_unread ]] || exit 1
     [[ "$2" != net.core.rmem_max || "$(< /records/mode)" != unread ]] || exit 1
     [[ -f /records/kernel/$2 ]] || exit 1;cat /records/kernel/"$2" ;;
 -w) k="${2%%=*}";v="${2#*=}";printf '%s\n' "$k" >> /records/writes
     [[ "$k" != net.ipv4.tcp_moderate_rcvbuf || "$(< /records/mode)" != moderate_denied ]] || exit 1
     [[ "$k" != net.core.rmem_max || "$(< /records/mode)" != denied ]] || exit 1
     [[ "$k" != net.core.rmem_max || "$(< /records/mode)" != mismatch ]] || exit 0
     printf '%s\n' "$v" > /records/kernel/"$k" ;;
 -p) while IFS='=' read -r k v;do [[ -n "$k" && "$k" != \#* ]] || continue
       printf '%s\n' "$v" > /records/kernel/"$k"
     done < "$2" ;;
 *) exit 2 ;;
esac''')
        cls.stub('modprobe','exit 1')
        text=fixture.SOURCE.read_text()
        targets=re.findall(r'^(net\.[a-z0-9_.]+)=(.+)$',text,re.M)
        assert len(targets)==11
        assert dict(targets)['net.ipv4.tcp_moderate_rcvbuf']=='1'
        assert 'net.ipv4.tcp_mem' not in dict(targets)
        cls.targets=dict(targets)
        for k in cls.targets:
            (cls.base/'records/kernel'/k).write_text('old_'+k+'\n')

    def receipts(self):
        return sorted((self.root/'etc/qeli/client-links').glob('kernel-tuning-*'))

    def tune(self):
        return self.run_installer('_apply_perf_tuning; printf "%s\\n" "$SYSCTL_STATUS"')

    def test_readback_success_and_exact_runtime_file_recovery(self):
        path=self.root/'etc/sysctl.d/99-qeli-perf.conf';path.write_text('# administrator settings\n');path.chmod(0o644)
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('applied and verified (11/11',p.stdout)
        receipt=self.receipts()[0]
        self.assertEqual(receipt.stat().st_uid,0);self.assertEqual(receipt.stat().st_mode&0o777,0o700)
        for f in receipt.iterdir():
            self.assertEqual(f.stat().st_uid,0);self.assertEqual(f.stat().st_mode&0o777,0o600)
        self.assertIn('-m 644', (receipt/'restore.txt').read_text())
        p=self.run_installer('bash -e '+'/' + str(receipt.relative_to(self.root)) + '/restore.txt')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(path.read_text(),'# administrator settings\n');self.assertEqual(path.stat().st_mode&0o777,0o644)
        self.assertFalse((self.root/'etc/modules-load.d/qeli-bbr.conf').exists())
        for key in self.targets:self.assertEqual((self.root/'records/kernel'/key).read_text(),'old_'+key+'\n')

    def test_write_refusal_continues_but_reports_incomplete(self):
        (self.root/'records/mode').write_text('denied')
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('incomplete (10/11',p.stdout);self.assertNotIn('applied and verified',p.stdout)
        self.assertEqual((self.root/'records/kernel/net.core.rmem_max').read_text(),'old_net.core.rmem_max\n')
        self.assertTrue((self.receipts()[0]/'runtime.before').read_text().count('=')==11)

    def test_udp_auto_ceilings_are_floors_not_downgrades(self):
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            (self.root/'records/kernel'/key).write_text('67108864\n')
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('applied and verified (11/11',p.stdout)
        for key in ('net.core.rmem_max', 'net.core.wmem_max'):
            self.assertEqual((self.root/'records/kernel'/key).read_text(),'67108864\n')
            self.assertIn(key+'=67108864', (self.root/'etc/sysctl.d/99-qeli-perf.conf').read_text())

    def test_successful_command_without_effect_is_detected(self):
        (self.root/'records/mode').write_text('mismatch')
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('incomplete (10/11',p.stdout);self.assertIn('0 writes unavailable/failed',p.stdout)

    def test_unreadable_old_value_is_never_written_at_runtime(self):
        (self.root/'records/mode').write_text('unread')
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('incomplete',p.stdout)
        self.assertNotIn('net.core.rmem_max',(self.root/'records/writes').read_text())
        self.assertNotIn('net.core.rmem_max=',(self.receipts()[0]/'runtime.before').read_text())
        self.assertIn('net.core.rmem_max=',(self.root/'etc/sysctl.d/99-qeli-perf.conf').read_text())

    def test_tcp_autotuning_enable_and_restore_preserve_manual_config_and_global_budget(self):
        key=self.root/'records/kernel/net.ipv4.tcp_moderate_rcvbuf';key.write_text('0\n')
        budget=self.root/'records/kernel/net.ipv4.tcp_mem';budget.write_text('22221 29628 44442\n')
        config=self.root/'etc/qeli/server.conf'
        manual=b'[profile:manual]\nperf.tcp.send_buffer_size = 524288\nperf.tcp.recv_buffer_size = 1048576\n'
        config.write_bytes(manual)
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('applied and verified (11/11',p.stdout)
        self.assertEqual(key.read_text(),'1\n')
        self.assertEqual(config.read_bytes(),manual)
        self.assertEqual(budget.read_text(),'22221 29628 44442\n')
        receipt=self.receipts()[0]
        self.assertIn('net.ipv4.tcp_moderate_rcvbuf=0\n',(receipt/'runtime.before').read_text())
        self.assertNotIn('net.ipv4.tcp_mem=',(receipt/'requested.conf').read_text())
        self.assertNotIn('net.ipv4.tcp_mem',(self.root/'records/writes').read_text())
        p=self.run_installer('bash -e /'+str(receipt.relative_to(self.root))+'/restore.txt')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(key.read_text(),'0\n')
        self.assertEqual(config.read_bytes(),manual)
        self.assertEqual(budget.read_text(),'22221 29628 44442\n')

    def test_tcp_autotuning_write_denied_reports_incomplete(self):
        key=self.root/'records/kernel/net.ipv4.tcp_moderate_rcvbuf';key.write_text('0\n')
        (self.root/'records/mode').write_text('moderate_denied')
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('incomplete (10/11',p.stdout)
        self.assertNotIn('applied and verified',p.stdout)
        self.assertEqual(key.read_text(),'0\n')

    def test_unavailable_tcp_autotuning_is_not_written(self):
        (self.root/'records/mode').write_text('moderate_unread')
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('incomplete (10/11',p.stdout)
        self.assertNotIn('net.ipv4.tcp_moderate_rcvbuf',(self.root/'records/writes').read_text())
        self.assertNotIn('net.ipv4.tcp_moderate_rcvbuf=',(self.receipts()[0]/'runtime.before').read_text())

    def test_unsafe_tuning_paths_refused_before_whole_installer_changes(self):
        self.env['QELI_FORCE_RECONFIG']='1'
        witness=self.root/'outside/tuning';witness.write_text('administrator witness')
        config=self.root/'etc/qeli/server.conf';before=config.read_bytes()
        for name in ['etc/sysctl.d','etc/modules-load.d','etc/sysctl.d/99-qeli-perf.conf','etc/modules-load.d/qeli-bbr.conf']:
            with self.subTest(path=name):
                p=self.root/name
                if p.is_dir():p.rmdir()
                p.symlink_to('/outside/tuning')
                try:
                    result=self.run_installer(whole=True)
                    self.assertNotEqual(result.returncode,0)
                    self.assertEqual(witness.read_text(),'administrator witness')
                    self.assertEqual(config.read_bytes(),before)
                    self.assertEqual((self.root/'usr/bin/qeli').read_bytes(),self.old)
                    self.assertFalse((self.root/'records/apt.log').exists())
                finally:
                    p.unlink()
                    if name.endswith('.d'):p.mkdir()

    def test_hardlink_publication_preserves_external_inode(self):
        witness=self.root/'outside/tuning';witness.write_text('administrator witness');witness.chmod(0o644)
        path=self.root/'etc/sysctl.d/99-qeli-perf.conf';path.hardlink_to(witness)
        p=self.tune();self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(witness.read_text(),'administrator witness');self.assertEqual(witness.stat().st_mode&0o777,0o644)
        self.assertNotEqual(path.stat().st_ino,witness.stat().st_ino)

    def test_same_stamp_reconfiguration_retains_distinct_recovery_receipts(self):
        p=self.run_installer('RUN_STAMP=fixed; _apply_perf_tuning; _apply_perf_tuning')
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(len(self.receipts()),2)
        snapshots=[(r/'runtime.before').read_text() for r in self.receipts()]
        self.assertEqual(sum('old_net.' in s for s in snapshots),1)
        self.assertEqual(sum((r/'99-qeli-perf.conf.before').exists() for r in self.receipts()),1)


if __name__=='__main__':unittest.main(verbosity=2)
