"""Real Keenetic shell templates with isolated /opt, command and ndm models.
No service, firewall, proc/sys, network or actual router mutation. Linux lab only.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = shlex.split(os.environ.get('QELI_ROUTER_TEST_SHELL', '/bin/sh'))

@unittest.skipUnless(os.name == 'posix' and shutil.which(SHELL[0]), 'requires Linux/POSIX shell')
class KeeneticFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-keenetic-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name);self.bin=self.root/'bin';self.bin.mkdir()
        self.opt=self.root/'opt';self.bundle=self.root/'bundle with spaces';self.bundle.mkdir()
        self.env=dict(os.environ,PATH=str(self.bin),QELI_FIXTURE_ROOT=str(self.root),QELI_FIXTURE_BIN=str(self.bin),
            QELI_ARCH='aarch64-3.10',QELI_FAIL='',QELI_SHOW_FAIL='0',QELI_CONNECTED='no',
            QELI_CUR4='10.8.0.2',QELI_CUR6='fd00::2',QELI_FIXTURE_OWNER='0')
        for name in ('awk','grep','head','uname','mkdir','chmod','mktemp','mv','rm','dirname','cp','touch','cat','sed','rmdir','stat'):
            command=shutil.which(name);self.assertIsNotNone(command)
            (self.bin/name).symlink_to(command)
        # Router fixtures model root-owned /opt files even when CI is unprivileged.
        # Keep real modes and delegate every path outside this fixture to real stat.
        stat=shlex.quote(shutil.which('stat'))
        self.write_command('stat',r'''
if [ "$1" = -c ]; then
  case "$3" in "$QELI_FIXTURE_ROOT"/*)
    case "$2" in
      %u)
        '''+stat+r''' -c '%u' "$3" >/dev/null || exit $?
        printf '%s\n' "$QELI_FIXTURE_OWNER"; exit 0 ;;
      %u:%a)
        mode=$('''+stat+r''' -c '%a' "$3") || exit $?
        printf '%s:%s\n' "$QELI_FIXTURE_OWNER" "$mode"; exit 0 ;;
    esac ;;
  esac
fi
exec '''+stat+' "$@"')
        self.write_command('ip','exit 0')
        self.write_command('iptables','exit 0')
        self.write_command('ip6tables','exit 0')
        self.write_command('sleep','exit 0')
        self.write_command('opkg',r'''
printf 'opkg %s\n' "$*" >> "$QELI_FIXTURE_ROOT/calls"
case "$*" in
 'print-architecture') printf 'arch %s 10\n' "$QELI_ARCH" ;;
 *) [ "$QELI_FAIL" != "opkg:$*" ] ;;
esac
''')
        install=shlex.quote(shutil.which('install'))
        self.write_command('install',r'''
case "$QELI_FAIL:$2" in
 install-bin:*/qeli-client*) exit 17 ;;
 install-init:*/S99qeli) exit 17 ;;
 install-conf:*/client.conf.example) exit 17 ;;
 install-lib:*/lifecycle.sh) exit 17 ;;
esac
exec '''+install+' "$@"')
        self.write_command('ndmc',r'''
printf '%s\n' "$2" >> "$QELI_FIXTURE_ROOT/ndmc-calls"
case "$2" in
 'show interface '*)
   [ "$QELI_SHOW_FAIL" != 1 ] || exit 17
   printf 'connected: %s\naddress: %s\nipv6 address: %s\n' "$QELI_CONNECTED" "$QELI_CUR4" "$QELI_CUR6" ;;
 *)
   if [ -n "$QELI_FAIL" ]; then case "$2" in *"$QELI_FAIL"*) exit 17 ;; esac; fi ;;
esac
''')
        (self.bundle/'lifecycle.sh').write_text((ROOT/'release/keenetic/lifecycle.sh').read_text().replace('/opt/',str(self.opt)+'/').replace('/var/run/qeli.lifecycle.lock',str(self.opt/'var/run/qeli.lifecycle.lock')))
        (self.bundle/'S99qeli').write_text('new init template')
        (self.bundle/'client.conf.example').write_text('[qeli]\nserver = fixture.invalid:443\n')
        (self.bundle/'qeli-client-keenetic-aarch64').write_text('canonical-aarch64')
        (self.bundle/'qeli-client-keenetic-mipsel').write_text('canonical-mipsel')

    def write_command(self,name,body):
        p=self.bin/name
        if p.is_symlink():p.unlink()
        p.write_text('#!/bin/sh\n'+body+'\n');p.chmod(0o700)

    def copy_template(self,source,target):
        if Path(source).name in ('S99qeli','010-qeli.sh'):
            helper=self.opt/'etc/qeli/lifecycle.sh';helper.parent.mkdir(parents=True,exist_ok=True);helper.parent.chmod(0o700)
            helper.write_text((self.bundle/'lifecycle.sh').read_text())
        text=Path(source).read_text()
        text=text.replace('export PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'export PATH="$QELI_FIXTURE_BIN"')
        text=text.replace('/opt/',str(self.opt)+'/')
        text=text.replace('/dev/net/tun',str(self.root/'tun'))
        target.write_text(text);return target

    def installer(self,**env):
        source=Path(os.environ.get('QELI_LIFECYCLE_BASELINE',str(ROOT/'release/keenetic')))/'install-keenetic.sh'
        self.copy_template(source,self.bundle/'install.sh')
        return self.run_script(self.bundle/'install.sh',**env)

    def run_script(self,path,**env):
        return subprocess.run(SHELL+[str(path)],env=dict(self.env,**env),capture_output=True,text=True,timeout=15)

    def installed(self,name):return self.opt/name
    def seed_installed(self,config=True):
        for name,value in {'bin/qeli-client':'old binary','etc/init.d/S99qeli':'old init',
                **({'etc/qeli/client.conf':'old secret config'} if config else {})}.items():
            p=self.installed(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
    def calls(self,name='calls'):
        p=self.root/name;return p.read_text().splitlines() if p.exists() else []
    def assert_no_temps(self):
        self.assertFalse(list(self.opt.rglob('.qeli-client.*')))
        self.assertFalse(list(self.opt.rglob('.S99qeli.*')))
        self.assertFalse(list(self.opt.rglob('.client.conf.*')))
        self.assertFalse(list(self.opt.rglob('.lifecycle.*')))
        self.assertFalse((self.opt/'var/run/qeli.lifecycle.lock').exists())

    def hook_setup(self,plan='10.8.0.2\nipv4=10.8.0.2/32\nipv6=fd00::2/128\nmtu=1400\n',state='opkgtun0'):
        folder=self.opt/'var/run';folder.mkdir(parents=True,exist_ok=True)
        log=self.opt/'var/log';log.mkdir(parents=True,exist_ok=True)
        (folder/'qeli.opkgtun').write_text(state)
        (folder/'qeli.tunip').write_text(plan)
        self.hook=self.copy_template(ROOT/'release/keenetic/opkgtun/010-qeli.sh',self.root/'hook.sh')
        return folder
    def hook_log(self):
        p=self.opt/'var/log/qeli-client.log';return p.read_text() if p.exists() else ''

class KeeneticInstallerTests(KeeneticFixture):
    def test_foreign_config_owner_is_rejected_before_publication(self):
        self.seed_installed()
        before={str(p.relative_to(self.opt)):p.read_bytes() for p in self.opt.rglob('*') if p.is_file()}
        result=self.installer(QELI_FIXTURE_OWNER='1234')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('root-owned config directory required',result.stdout+result.stderr)
        self.assertEqual({str(p.relative_to(self.opt)):p.read_bytes() for p in self.opt.rglob('*') if p.is_file()},before)
        self.assert_no_temps()

    def test_owner_model_preserves_modes_and_delegates_outside_paths(self):
        target=self.root/'owned-file';target.write_text('fixture');target.chmod(0o640)
        missing=subprocess.run([str(self.bin/'stat'),'-c','%u',str(self.root/'missing')],env=self.env,capture_output=True,text=True,timeout=5)
        self.assertNotEqual(missing.returncode,0)
        def probe(path,format):
            p=subprocess.run([str(self.bin/'stat'),'-c',format,str(path)],env=dict(self.env,QELI_FIXTURE_OWNER='1234'),capture_output=True,text=True,timeout=5)
            self.assertEqual(p.returncode,0,p.stderr)
            return p.stdout.strip()
        self.assertEqual(probe(target,'%u:%a'),'1234:640')
        with tempfile.TemporaryDirectory(prefix='qeli-stat-outside-') as outside:
            other=Path(outside)/'file';other.write_text('outside');other.chmod(0o600)
            self.assertEqual(probe(other,'%u:%a'),str(os.getuid())+':600')

    def test_canonical_binary_names_both_arches_are_published(self):
        for arch,suffix in [('aarch64-3.10','aarch64'),('mipsel-3.4','mipsel')]:
            result=self.installer(QELI_ARCH=arch);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(self.installed('bin/qeli-client').read_text(),'canonical-'+suffix)
            self.assertEqual(self.installed('bin/qeli-client').stat().st_mode&0o777,0o755)
            self.assertEqual(self.installed('etc/qeli/client.conf').stat().st_mode&0o777,0o600)
            self.assertEqual(self.installed('etc/qeli').stat().st_mode&0o777,0o700)
            self.assert_no_temps()

    def test_legacy_bundle_name_is_supported_but_canonical_name_wins(self):
        (self.bundle/'qeli-client-aarch64').write_text('legacy')
        self.assertEqual(self.installer().returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'canonical-aarch64')
        (self.bundle/'qeli-client-keenetic-aarch64').unlink()
        self.assertEqual(self.installer().returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'legacy')

    def test_existing_configuration_survives_upgrade_and_permissions_are_restricted(self):
        self.seed_installed();self.installed('etc/qeli/client.conf').chmod(0o644)
        self.assertEqual(self.installer().returncode,0)
        self.assertEqual(self.installed('etc/qeli/client.conf').read_text(),'old secret config')
        self.assertEqual(self.installed('etc/qeli/client.conf').stat().st_mode&0o777,0o600)

    def test_required_package_update_and_install_errors_prevent_publication(self):
        self.seed_installed()
        for fail in ('opkg:update','opkg:install ip-full iptables'):
            result=self.installer(QELI_FAIL=fail);self.assertNotEqual(result.returncode,0)
            self.assertNotIn('Готово.',result.stdout)
            self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary')
            self.assertEqual(self.installed('etc/init.d/S99qeli').read_text(),'old init')

    def test_missing_required_command_after_package_success_is_rejected(self):
        (self.bin/'ip').unlink();self.seed_installed()
        self.assertNotEqual(self.installer().returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary')

    def test_upgrade_refuses_existing_pid_and_pending_publication_before_dependencies(self):
        self.seed_installed();folder=self.opt/'var/run';folder.mkdir(parents=True)
        for name in ('qeli-client.pid','qeli-client.pid.pending'):
            path=folder/name;path.write_text('fixture state')
            result=self.installer();self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary')
            self.assertNotIn('opkg update',self.calls());path.unlink()

    def test_optional_ipv6_package_failure_is_explicit_warning(self):
        (self.bin/'ip6tables').unlink()
        result=self.installer(QELI_FAIL='opkg:install ip6tables')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ВНИМАНИЕ: ip6tables',result.stdout)
        self.assertIn('opkg install ip6tables',self.calls())

    def test_empty_missing_bundle_inputs_fail_before_dependency_changes(self):
        for name in ('qeli-client-keenetic-aarch64','S99qeli','client.conf.example','lifecycle.sh'):
            p=self.bundle/name;data=p.read_bytes();p.write_bytes(b'')
            result=self.installer();self.assertNotEqual(result.returncode,0)
            self.assertNotIn('opkg update',self.calls());p.write_bytes(data)

    def test_unsupported_architecture_is_rejected_before_dependency_changes(self):
        result=self.installer(QELI_ARCH='mips-3.4');self.assertNotEqual(result.returncode,0)
        self.assertNotIn('opkg update',self.calls())

    def test_preparation_errors_keep_old_binary_and_init_and_cleanup_temporary_files(self):
        self.seed_installed()
        for fail in ('install-bin','install-init','install-lib'):
            result=self.installer(QELI_FAIL=fail);self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary')
            self.assertEqual(self.installed('etc/init.d/S99qeli').read_text(),'old init')
            self.assert_no_temps()

    def test_new_config_copy_failure_does_not_publish_prepared_binary(self):
        self.seed_installed(config=False)
        self.assertNotEqual(self.installer(QELI_FAIL='install-conf').returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary')
        self.assertEqual(self.installed('etc/init.d/S99qeli').read_text(),'old init')
        self.assertFalse(self.installed('etc/qeli/client.conf').exists());self.assert_no_temps()

    def test_publication_failure_cleans_temps_and_retry_succeeds(self):
        self.seed_installed();real=shlex.quote(shutil.which('mv'))
        self.write_command('mv',r'''
case "$QELI_FAIL:$*" in mv-bin:*/bin/qeli-client) exit 17 ;; esac
exec '''+real+' "$@"')
        self.assertNotEqual(self.installer(QELI_FAIL='mv-bin').returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary');self.assert_no_temps()
        self.assertEqual(self.installer().returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'canonical-aarch64')

    def test_publication_directory_targets_fail_before_dependencies(self):
        for target in ('bin/qeli-client','etc/init.d/S99qeli','etc/qeli/client.conf','etc/qeli/lifecycle.sh'):
            with self.subTest(target=target):
                path=self.installed(target);path.parent.mkdir(parents=True,exist_ok=True);path.mkdir()
                self.assertNotEqual(self.installer().returncode,0)
                self.assertNotIn('opkg update',self.calls())
                self.assertEqual(list(path.iterdir()),[])
                path.rmdir()
                self.assert_no_temps()

    def test_library_publication_failure_keeps_old_binary_init_and_library(self):
        self.seed_installed();library=self.installed('etc/qeli/lifecycle.sh');library.write_text('old helper')
        real=shlex.quote(shutil.which('mv'))
        self.write_command('mv',r'''
case "$QELI_FAIL:$*" in mv-lib:*/etc/qeli/lifecycle.sh) exit 17 ;; esac
exec '''+real+' "$@"')
        self.assertNotEqual(self.installer(QELI_FAIL='mv-lib').returncode,0)
        self.assertEqual(self.installed('bin/qeli-client').read_text(),'old binary')
        self.assertEqual(self.installed('etc/init.d/S99qeli').read_text(),'old init')
        self.assertEqual(library.read_text(),'old helper');self.assert_no_temps()
        self.assertEqual(self.installer().returncode,0)
        self.assertEqual(library.read_text(),(self.bundle/'lifecycle.sh').read_text())
        self.assertEqual(library.stat().st_mode&0o777,0o600)

class KeeneticHookTests(KeeneticFixture):
    def test_dual_family_and_mtu_are_applied_and_success_follows_save(self):
        self.hook_setup();result=self.run_script(self.hook)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('interface OpkgTun0 ip address 10.8.0.2 255.255.255.255',self.calls('ndmc-calls'))
        self.assertIn('interface OpkgTun0 ipv6 address fd00::2/128',self.calls('ndmc-calls'))
        self.assertIn('interface OpkgTun0 ip mtu 1400',self.calls('ndmc-calls'))
        self.assertEqual(self.calls('ndmc-calls')[-1],'system configuration save')
        self.assertIn('OpkgTun0 up (',self.hook_log())

    def test_each_ndm_mutation_failure_stops_save_and_success_log_then_retry(self):
        self.hook_setup()
        for fail in ('description','ip global','ip address','ipv6 address','ip mtu','adjust-mss','security-level',' up','system configuration save'):
            with self.subTest(fail=fail):
                (self.root/'ndmc-calls').unlink(missing_ok=True)
                (self.opt/'var/log/qeli-client.log').unlink(missing_ok=True)
                self.assertNotEqual(self.run_script(self.hook,QELI_FAIL=fail).returncode,0)
                self.assertNotIn('OpkgTun0 up (',self.hook_log())
                if fail!='system configuration save':self.assertNotIn('system configuration save',self.calls('ndmc-calls'))
                self.assertTrue((self.opt/'var/run/qeli.opkgtun.apply-pending').exists())
                (self.root/'ndmc-calls').unlink()
                self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
                self.assertEqual(self.calls('ndmc-calls')[-1],'system configuration save')
                self.assertFalse((self.opt/'var/run/qeli.opkgtun.apply-pending').exists())

    def test_pending_creation_failure_prevents_ndm_mutations(self):
        folder=self.hook_setup();(folder/'qeli.opkgtun.apply-pending').mkdir()
        self.assertNotEqual(self.run_script(self.hook).returncode,0)
        self.assertNotIn('interface OpkgTun0 description qeli-VPN',self.calls('ndmc-calls'))
        self.assertNotIn('OpkgTun0 up (',self.hook_log())

    def test_pending_removal_failure_requires_retry_and_never_logs_success(self):
        folder=self.hook_setup();real=shlex.quote(shutil.which('rm'))
        self.write_command('rm',r'''
case "$QELI_FAIL:$*" in pending-remove:*.apply-pending) exit 17 ;; esac
exec '''+real+' "$@"')
        self.assertNotEqual(self.run_script(self.hook,QELI_FAIL='pending-remove').returncode,0)
        self.assertTrue((folder/'qeli.opkgtun.apply-pending').exists())
        self.assertNotIn('OpkgTun0 up (',self.hook_log())
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertFalse((folder/'qeli.opkgtun.apply-pending').exists())
        self.assertIn('OpkgTun0 up (',self.hook_log())

    def test_invalid_interface_markers_cannot_issue_ndm_commands(self):
        folder=self.hook_setup()
        for state in ('opkgtun0garbage','opkgtun0; bad','opkgtun','wan','opkgtun1234567890'):
            (folder/'qeli.opkgtun').write_text(state)
            self.assertNotEqual(self.run_script(self.hook).returncode,0)
            self.assertEqual(self.calls('ndmc-calls'),[])
        (folder/'qeli.opkgtun').unlink()
        self.assertEqual(self.run_script(self.hook).returncode,0)

    def test_missing_plan_waits_without_publishing_l3_success(self):
        folder=self.hook_setup();(folder/'qeli.tunip').unlink()
        self.assertEqual(self.run_script(self.hook).returncode,0)
        self.assertNotIn('system configuration save',self.calls('ndmc-calls'))
        self.assertNotIn('OpkgTun0 up (',self.hook_log())

    def test_missing_ndm_interface_defers_without_success(self):
        self.hook_setup()
        self.assertEqual(self.run_script(self.hook,QELI_SHOW_FAIL='1').returncode,0)
        self.assertNotIn('system configuration save',self.calls('ndmc-calls'))
        self.assertNotIn('OpkgTun0 up (',self.hook_log())

    def test_connected_matching_addresses_do_not_repeat_mutations(self):
        folder=self.hook_setup()
        self.assertEqual(self.run_script(self.hook).returncode,0)
        self.assertEqual((folder/'qeli.opkgtun.applied').stat().st_mode&0o777,0o600)
        (self.root/'ndmc-calls').unlink()
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertEqual(self.calls('ndmc-calls'),['show interface OpkgTun0'])

    def saved_hook(self):
        folder=self.hook_setup()
        self.assertEqual(self.run_script(self.hook).returncode,0)
        (self.root/'ndmc-calls').unlink()
        (self.opt/'var/log/qeli-client.log').unlink()
        return folder

    def test_matching_addresses_without_complete_receipt_still_apply(self):
        self.hook_setup()
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertEqual(self.calls('ndmc-calls')[-1],'system configuration save')

    def test_mtu_only_plan_change_reapplies_and_next_event_is_noop(self):
        folder=self.saved_hook();plan=folder/'qeli.tunip'
        plan.write_text(plan.read_text().replace('mtu=1400','mtu=1280'))
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertIn('interface OpkgTun0 ip mtu 1280',self.calls('ndmc-calls'))
        (self.root/'ndmc-calls').unlink()
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertEqual(self.calls('ndmc-calls'),['show interface OpkgTun0'])

    def test_missing_plan_with_connected_interface_defers_and_logs_wait(self):
        folder=self.saved_hook();(folder/'qeli.tunip').unlink()
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertNotIn('system configuration save',self.calls('ndmc-calls'))
        self.assertIn('нет IP',self.hook_log())

    def test_ipv4_substring_or_regex_lookalike_cannot_qualify_noop(self):
        self.saved_hook()
        for address in ('10.8.0.20','10x8x0x2'):
            with self.subTest(address=address):
                (self.root/'ndmc-calls').unlink(missing_ok=True)
                self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes',QELI_CUR4=address).returncode,0)
                self.assertEqual(self.calls('ndmc-calls')[-1],'system configuration save')

    def test_ipv6_substring_cannot_qualify_noop(self):
        self.saved_hook()
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes',QELI_CUR6='fd00::20').returncode,0)
        self.assertEqual(self.calls('ndmc-calls')[-1],'system configuration save')

    def test_failed_show_cannot_qualify_cached_noop(self):
        self.saved_hook()
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes',QELI_SHOW_FAIL='1').returncode,0)
        self.assertIn('interface OpkgTun0',self.calls('ndmc-calls'))
        self.assertNotIn('system configuration save',self.calls('ndmc-calls'))

    def test_receipt_directory_is_not_mistaken_for_successful_publication(self):
        folder=self.hook_setup();(folder/'qeli.opkgtun.applied').mkdir()
        self.assertNotEqual(self.run_script(self.hook).returncode,0)
        self.assertTrue((folder/'qeli.opkgtun.apply-pending').exists())
        self.assertFalse(list(folder.glob('qeli.opkgtun.applied.*')))
        self.assertNotIn('OpkgTun0 up (',self.hook_log())

    def test_receipt_publication_failure_retains_pending_and_retries(self):
        folder=self.hook_setup();real=shlex.quote(shutil.which('mv'))
        self.write_command('mv',r'''
case "$QELI_FAIL:$*" in receipt-move:*.applied) exit 17 ;; esac
exec '''+real+' "$@"')
        self.assertNotEqual(self.run_script(self.hook,QELI_FAIL='receipt-move').returncode,0)
        self.assertTrue((folder/'qeli.opkgtun.apply-pending').exists())
        self.assertFalse((folder/'qeli.opkgtun.applied').exists())
        self.assertFalse(list(folder.glob('qeli.opkgtun.applied.*')))
        self.assertNotIn('OpkgTun0 up (',self.hook_log())
        self.assertEqual(self.run_script(self.hook,QELI_CONNECTED='yes').returncode,0)
        self.assertFalse((folder/'qeli.opkgtun.apply-pending').exists())
        self.assertTrue((folder/'qeli.opkgtun.applied').exists())

    def rotate_plan_after_first_read(self):
        target=str(self.opt/'var/run/qeli.tunip')
        (self.root/'next-plan').write_text('10.8.0.9\nipv4=10.8.0.9/32\nipv6=fd00::9/128\nmtu=1280\n')
        for name in ('cat','sed'):
            real=shlex.quote(shutil.which(name))
            self.write_command(name,real+r''' "$@"
for argument in "$@"; do
 if [ "$argument" = '''+shlex.quote(target)+r''' ] && [ ! -f "$QELI_FIXTURE_ROOT/rotated" ]; then
   cp "$QELI_FIXTURE_ROOT/next-plan" "$argument";touch "$QELI_FIXTURE_ROOT/rotated"
 fi
done
''')

    def test_replacement_before_lock_applies_current_snapshot_without_stale_mutation(self):
        folder=self.hook_setup();self.rotate_plan_after_first_read()
        # Replacement happened before publication exclusion was acquired. The
        # hook rereads under that lock and may safely apply the current snapshot.
        self.assertEqual(self.run_script(self.hook).returncode,0)
        self.assertNotIn('interface OpkgTun0 ip address 10.8.0.2 255.255.255.255',self.calls('ndmc-calls'))
        self.assertEqual(self.calls('ndmc-calls').count('system configuration save'),1)
        self.assertEqual((folder/'qeli.opkgtun.applied').read_text(), 'opkgtun0\n'+(folder/'qeli.tunip').read_text())
        self.assertFalse((folder/'qeli.opkgtun.apply-pending').exists())
        self.assertIn('interface OpkgTun0 ip address 10.8.0.9 255.255.255.255',self.calls('ndmc-calls'))
        self.assertIn('interface OpkgTun0 ipv6 address fd00::9/128',self.calls('ndmc-calls'))
        self.assertIn('interface OpkgTun0 ip mtu 1280',self.calls('ndmc-calls'))

if __name__=='__main__':unittest.main()
