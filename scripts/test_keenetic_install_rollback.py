# Owned shell install faults; no real router/service/firewall mutation.
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from test_keenetic_templates import KeeneticFixture, ROOT, SHELL

class KeeneticInstallRollbackTests(KeeneticFixture):
    def seed_code(self):
        self.seed_installed()
        library=self.installed("etc/qeli/lifecycle.sh")
        library.write_text("old library")
        for rel,mode in [("bin/qeli-client",0o711),("etc/init.d/S99qeli",0o751),("etc/qeli/lifecycle.sh",0o640)]:
            self.installed(rel).chmod(mode)
        return self.code_snapshot()

    def code_snapshot(self):
        result={}
        for rel in ["bin/qeli-client","etc/init.d/S99qeli","etc/qeli/lifecycle.sh"]:
            p=self.installed(rel)
            result[rel]=(p.read_bytes(),p.stat().st_mode&0o777) if p.exists() else None
        return result

    def fault_rename(self):
        real=shlex.quote(shutil.which("mv"))
        self.write_command("mv",r'''
role=publish
case "$2" in *rollback.*) role=rollback ;; esac
printf 'mv %s %s\n' "$role" "$3" >> "$QELI_FIXTURE_ROOT/rename-calls"
case "$QELI_FAIL:$role:$3" in
 fail-lib:publish:*/etc/qeli/lifecycle.sh|fail-bin:publish:*/bin/qeli-client|fail-init:publish:*/etc/init.d/S99qeli|fail-marker:publish:*/etc/qeli/install-pending) exit 17 ;;
 fail-rollback:publish:*/etc/init.d/S99qeli|fail-rollback:rollback:*/bin/qeli-client) exit 17 ;;
 term-bin:publish:*/bin/qeli-client)
   '''+real+r''' "$@" || exit $?
   kill -TERM "$PPID"
   exit 0 ;;
esac
exec '''+real+' "$@"')

    def marker(self):
        return self.installed("etc/qeli/install-pending")

    def test_code_rename_failures_restore_old_bytes_and_modes(self):
        before=self.seed_code();self.fault_rename()
        for fail in ["fail-lib","fail-bin","fail-init"]:
            with self.subTest(fail=fail):
                p=self.installer(QELI_FAIL=fail)
                self.assertNotEqual(p.returncode,0)
                self.assertEqual(self.code_snapshot(),before)
                self.assertEqual(self.installed("etc/qeli/client.conf").read_text(),"old secret config")
                self.assertFalse(self.marker().exists());self.assert_no_temps()
        self.assertEqual(self.installer().returncode,0)
        self.assertEqual(self.installed("bin/qeli-client").read_text(),"canonical-aarch64")
        self.assertFalse(self.marker().exists());self.assert_no_temps()

    def test_previously_absent_library_is_removed_on_rollback(self):
        self.seed_installed();before=self.code_snapshot();self.fault_rename()
        p=self.installer(QELI_FAIL="fail-init")
        self.assertNotEqual(p.returncode,0)
        self.assertEqual(self.code_snapshot(),before);self.assert_no_temps()

    def test_failed_first_install_removes_new_code_and_unpublished_config(self):
        self.fault_rename()
        self.assertNotEqual(self.installer(QELI_FAIL="fail-init").returncode,0)
        self.assertEqual(self.code_snapshot(),{rel:None for rel in self.code_snapshot()})
        self.assertFalse(self.installed("etc/qeli/client.conf").exists())
        self.assertFalse(self.marker().exists());self.assert_no_temps()

    def test_failed_rollback_retains_recovery_marker_backup_and_refuses_retry(self):
        before=self.seed_code();self.fault_rename()
        p=self.installer(QELI_FAIL="fail-rollback")
        self.assertNotEqual(p.returncode,0)
        self.assertIn("rollback incomplete",p.stderr)
        self.assertTrue(self.marker().exists())
        self.assertEqual(self.marker().stat().st_mode&0o777,0o600)
        backups=list(self.opt.rglob(".qeli-client.rollback.*"));self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),before["bin/qeli-client"][0])
        self.assertIn(str(backups[0]),self.marker().read_text())
        self.assertEqual(self.installed("etc/init.d/S99qeli").read_bytes(),before["etc/init.d/S99qeli"][0])
        self.assertFalse((self.opt/"var/run/qeli.lifecycle.lock").exists())
        calls=[c for c in self.calls() if c!="opkg print-architecture"]
        self.assertNotEqual(self.installer().returncode,0)
        self.assertEqual([c for c in self.calls() if c!="opkg print-architecture"],calls)
        self.assertTrue(backups[0].exists())

    def test_backup_copy_failure_never_publishes_new_code(self):
        before=self.seed_code();real=shlex.quote(shutil.which("cp"))
        self.write_command("cp",'case "$2" in */bin/qeli-client) exit 17 ;; esac\nexec '+real+' "$@"')
        self.assertNotEqual(self.installer().returncode,0)
        self.assertEqual(self.code_snapshot(),before)
        self.assertFalse(self.marker().exists());self.assert_no_temps()

    def test_marker_publication_failure_keeps_original_code(self):
        before=self.seed_code();self.fault_rename()
        self.assertNotEqual(self.installer(QELI_FAIL="fail-marker").returncode,0)
        self.assertEqual(self.code_snapshot(),before)
        self.assertFalse(self.marker().exists());self.assert_no_temps()

    def test_marker_retirement_failure_restores_code_and_keeps_start_guard(self):
        before=self.seed_code();real=shlex.quote(shutil.which("rm"))
        self.write_command("rm",'case "$2" in */etc/qeli/install-pending) exit 17 ;; esac\nexec '+real+' "$@"')
        self.assertNotEqual(self.installer().returncode,0)
        self.assertEqual(self.code_snapshot(),before)
        self.assertTrue(self.marker().exists())
        self.assertFalse((self.opt/"var/run/qeli.lifecycle.lock").exists())

    def test_term_after_binary_rename_rolls_back_before_unlock(self):
        before=self.seed_code();self.fault_rename()
        p=self.installer(QELI_FAIL="term-bin")
        self.assertNotEqual(p.returncode,0)
        self.assertEqual(self.code_snapshot(),before)
        self.assertFalse(self.marker().exists());self.assert_no_temps()

    def test_symlink_and_fifo_targets_fail_before_dependencies_without_touching_victim(self):
        victim=self.root/"victim";victim.write_text("preserve me");victim.chmod(0o644)
        for rel in ["bin/qeli-client","etc/init.d/S99qeli","etc/qeli/client.conf","etc/qeli/lifecycle.sh"]:
            for broken in [False,True]:
                with self.subTest(rel=rel,broken=broken):
                    p=self.installed(rel);p.parent.mkdir(parents=True,exist_ok=True)
                    p.symlink_to(self.root/"absent" if broken else victim)
                    result=self.installer();self.assertNotEqual(result.returncode,0)
                    self.assertNotIn("opkg update",self.calls())
                    self.assertTrue(p.is_symlink());p.unlink()
                    self.assertEqual(victim.read_text(),"preserve me")
                    self.assertEqual(victim.stat().st_mode&0o777,0o644)
        fifo=self.installed("bin/qeli-client");os.mkfifo(fifo)
        self.assertNotEqual(self.installer().returncode,0)
        self.assertTrue(fifo.is_fifo());self.assertNotIn("opkg update",self.calls())

    def test_linked_config_directory_is_not_chmodded(self):
        foreign=self.root/"foreign";foreign.mkdir();foreign.chmod(0o755)
        (foreign/"client.conf").write_text("preserve config")
        folder=self.installed("etc/qeli");folder.parent.mkdir(parents=True)
        folder.symlink_to(foreign,target_is_directory=True)
        self.assertNotEqual(self.installer().returncode,0)
        self.assertEqual(foreign.stat().st_mode&0o777,0o755)
        self.assertEqual((foreign/"client.conf").read_text(),"preserve config")
        self.assertNotIn("opkg update",self.calls())

    def test_pending_marker_blocks_both_init_and_active_hook_before_callbacks(self):
        self.seed_installed()
        (self.root/"tun").touch()
        (self.bin/"readlink").symlink_to(shutil.which("readlink"))
        self.installed("bin/qeli-client").write_text('#!/bin/sh\nprintf "inspect\\n" >> "$QELI_FIXTURE_ROOT/binary-calls"\nexit 17\n')
        self.installed("bin/qeli-client").chmod(0o700)
        for rel in ["release/keenetic/S99qeli","release/keenetic/opkgtun/S99qeli"]:
            script=self.copy_template(ROOT/rel,self.root/"init.sh")
            for linked in [False,True]:
                if linked:self.marker().symlink_to(self.root/"absent-marker")
                else:self.marker().write_text("pending")
                p=subprocess.run(SHELL+[str(script),"start"],env=self.env,capture_output=True,text=True,timeout=8)
                self.assertNotEqual(p.returncode,0,p.stdout+p.stderr)
                self.assertIn("installation pending",p.stderr)
                self.assertEqual(self.calls("binary-calls"),[]);self.marker().unlink()
        self.hook_setup();self.marker().write_text("pending")
        p=self.run_script(self.hook)
        self.assertNotEqual(p.returncode,0)
        self.assertEqual(self.calls("ndmc-calls"),[])
        self.assertFalse((self.opt/"var/run/qeli.lifecycle.lock").exists())
