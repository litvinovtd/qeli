"""Linux-owned native process tests for Keenetic scripts; fake network callbacks.
Short polling qualifies control flow, not the production 15-second budget.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import unittest
from test_keenetic_templates import KeeneticFixture, ROOT, SHELL
NATIVE=Path(os.environ.get('QELI_KEENETIC_PROCESS_FIXTURE','/nonexistent-qeli-native-fixture'))
def start_ticks(pid):return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
def running(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[0]!='Z'
    except FileNotFoundError:return False
class ProcessCases:
    def setUp(self):
        super().setUp()
        self.native=self.opt/'bin/qeli-client';self.native.parent.mkdir(parents=True)
        shutil.copyfile(NATIVE,self.native);self.native.chmod(0o700)
        (self.root/'tun').touch();(self.bin/'readlink').symlink_to(shutil.which('readlink'))
        self.write_command('sleep','exec '+shlex.quote(shutil.which('sleep'))+' 0.05')
        self.write_command('ip',r'printf "ip %s\n" "$*" >> "$QELI_FIXTURE_ROOT/calls"; exit 0')
        for path in ('etc/qeli','var/run','var/log'):(self.opt/path).mkdir(parents=True)
        self.conf=self.opt/'etc/qeli/client.conf';self.conf.write_text('[qeli]\ngateway_nat = true\n')
        self.pidfile=self.opt/'var/run/qeli-client.pid'
        self.plan=self.opt/('var/run/qeli.tunip' if 'opkgtun' in self.TEMPLATE else 'var/run/qeli.network-plan')
        self.marker=self.opt/'var/run/qeli.opkgtun';self.events=self.root/'events';self.children=[]
        self.env.update(QELI_HELPER_EVENTS=str(self.events),QELI_HELPER_PIDFILE=str(self.pidfile),QELI_HELPER_MODE='normal')
        self.script=self.root/'service.sh'
        baseline=os.environ.get('QELI_OPKGTUN_INIT_BASELINE')
        source=Path(baseline)/'S99qeli' if baseline and 'opkgtun' in self.TEMPLATE else ROOT/self.TEMPLATE
        self.copy_template(source,self.script)
        text=self.script.read_text().replace('[ "$waited" -lt 15 ]','[ "$waited" -lt 3 ]').replace('[ $i -lt 60 ]','[ $i -lt 2 ]')
        head,dispatch=text.rsplit('case "$1" in',1)
        self.body=head+r"""
nat_up() { [ "$QELI_FAIL" != nat-up ]; }
nat_down() { printf 'CLEANUP\n' >> "$QELI_HELPER_EVENTS"; [ "$QELI_FAIL" != cleanup ]; }
kill() { [ "$QELI_FAIL" != signal ] || return 17; command kill "$@"; }
"""
        self.script.write_text(self.body+'case "$1" in'+dispatch)
        self.addCleanup(self.cleanup_owned_helpers)
    def event_lines(self):return self.events.read_text().splitlines() if self.events.exists() else []
    def helper_pids(self):return {int(l.split()[1]) for l in self.event_lines() if l.startswith('READY ')}
    def cleanup_owned_helpers(self):
        for pid in self.helper_pids():
            try:
                target=os.readlink(f'/proc/{pid}/exe')
                if target in (str(self.native),str(self.native)+' (deleted)'):os.kill(pid,9)
            except (FileNotFoundError,ProcessLookupError):pass
        for p in self.children:
            if p.poll() is None:p.kill()
            p.wait(timeout=3)
        until=time.monotonic()+3
        while any(running(pid) for pid in self.helper_pids()) and time.monotonic()<until:time.sleep(.02)
        self.assertFalse(any(running(pid) for pid in self.helper_pids()),'fixture helper leaked')
    def service(self,action,**env):
        return subprocess.run(SHELL+[str(self.script),action],env=dict(self.env,**env),capture_output=True,text=True,timeout=10)
    def start(self,**env):
        p=self.service('start',**env);self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        pid,ticks=self.pidfile.read_text().split();self.assertEqual(ticks,start_ticks(int(pid)));return int(pid)
    def assert_joined(self,pid):
        lines=self.event_lines();exit_at=next(i for i,l in enumerate(lines) if l.startswith('EXIT '+str(pid)+' '))
        self.assertIn('plan=1 pid=1',lines[exit_at])
        self.assertGreater(lines.index('CLEANUP'),exit_at)
        self.assertFalse(running(pid));self.assertFalse(any('link del' in c for c in self.calls()))
    def test_start_private_identity_and_repeated_start(self):
        pid=self.start();self.assertEqual(self.pidfile.stat().st_mode&0o777,0o600)
        self.assertEqual(self.service('start').returncode,0);self.assertEqual(self.helper_pids(),{pid})
        self.assertEqual(self.service('stop').returncode,0)
    def test_invalid_and_group_pid_records_never_admit_or_signal(self):
        self.plan.write_text('retained')
        for record in ('0 1','-1 1','1 1','02 1','999999999999 1','bad 1','2 bad','2 1 extra','2 1\n3 1','42'):
            self.pidfile.write_text(record)
            self.assertNotEqual(self.service('stop').returncode,0);self.assertNotEqual(self.service('start').returncode,0)
            self.assertEqual(self.pidfile.read_text(),record);self.assertEqual(self.plan.read_text(),'retained')
        self.assertEqual(self.helper_pids(),set());self.assertNotIn('CLEANUP',self.event_lines())
    def test_foreign_executable_is_not_signalled(self):
        victim=subprocess.Popen([shutil.which('sleep'),'30']);self.children.append(victim)
        self.pidfile.write_text(f'{victim.pid} {start_ticks(victim.pid)}\n');self.plan.write_text('retained')
        self.assertNotEqual(self.service('stop').returncode,0);self.assertIsNone(victim.poll())
        self.assertNotEqual(self.service('start').returncode,0);self.assertEqual(self.service('status').returncode,4)
        self.assertEqual(self.plan.read_text(),'retained');self.assertNotIn('CLEANUP',self.event_lines())
    def test_start_tick_mismatch_keeps_process_until_corrected(self):
        pid=self.start();record=self.pidfile.read_text();self.pidfile.write_text(f'{pid} 0\n')
        self.assertNotEqual(self.service('stop').returncode,0);self.assertTrue(running(pid))
        self.assertEqual(self.service('status').returncode,4);self.assertNotIn('CLEANUP',self.event_lines())
        self.pidfile.write_text(record);self.assertEqual(self.service('stop').returncode,0)
    def test_real_exit_precedes_cleanup_with_plan_retained(self):
        pid=self.start(QELI_HELPER_DELAY_MS='100')
        receipt=self.marker.with_name(self.marker.name+'.applied')
        if 'opkgtun' in self.TEMPLATE:receipt.write_text('fixture receipt')
        self.assertEqual(self.service('stop').returncode,0);self.assert_joined(pid)
        self.assertEqual(receipt.exists(), 'opkgtun' in self.TEMPLATE)
        self.assertFalse(self.pidfile.exists());self.assertFalse(self.plan.exists());self.assertFalse(self.marker.exists())
    def test_term_timeout_and_restart_retain_state(self):
        pid=self.start(QELI_HELPER_MODE='ignore');before=self.pidfile.read_text();plan=self.plan.read_text()
        for action in ('stop','restart'):
            self.assertNotEqual(self.service(action).returncode,0);self.assertTrue(running(pid))
            self.assertEqual(self.pidfile.read_text(),before);self.assertEqual(self.plan.read_text(),plan)
            self.assertEqual(self.helper_pids(),{pid});self.assertNotIn('CLEANUP',self.event_lines())
        if 'opkgtun' in self.TEMPLATE:self.assertTrue(self.marker.exists())
    def test_exit_between_stat_and_exe_is_joined_without_false_identity_failure(self):
        child=subprocess.Popen([str(self.native)],env=dict(self.env,QELI_TUNIP_FILE=str(self.plan)),
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.children.append(child);pid=child.pid
        until=time.monotonic()+3
        while pid not in self.helper_pids() and time.monotonic()<until:time.sleep(.01)
        self.assertIn(pid,self.helper_pids())
        self.pidfile.write_text(str(pid)+' '+start_ticks(pid))
        real=shlex.quote(shutil.which('readlink'))
        self.write_command('readlink',r'''
if [ "$1" = "/proc/$QELI_OWNED_PID/exe" ] && [ ! -e "$QELI_FIXTURE_ROOT/race-fired" ]; then
  touch "$QELI_FIXTURE_ROOT/race-fired"
  # This PID is the helper just launched by this test, with a unique executable.
  kill -TERM "$QELI_OWNED_PID" || exit 18
  i=0
  while '''+real+r''' "/proc/$QELI_OWNED_PID/exe" >/dev/null 2>&1 && [ "$i" -lt 100 ]; do
    sleep .01; i=$((i+1))
  done
fi
exec '''+real+' "$@"')
        result=self.service('stop',QELI_OWNED_PID=str(pid))
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assert_joined(pid);self.assertTrue((self.root/'race-fired').exists())

    def test_unreadable_live_exe_retains_state_and_refuses_signals(self):
        pid=self.start();real=shlex.quote(shutil.which('readlink'))
        self.write_command('readlink',r'''
case "$1" in /proc/*/exe) exit 17 ;; esac
exec '''+real+' "$@"')
        self.assertNotEqual(self.service('stop').returncode,0)
        self.assertTrue(running(pid));self.assertTrue(self.pidfile.exists())
        self.assertNotIn('TERM '+str(pid)+' ', '\n'.join(self.event_lines()))
        self.write_command('readlink','exec '+real+' "$@"')
        self.assertEqual(self.service('stop').returncode,0)

    def test_signal_error_retains_state_until_retry(self):
        pid=self.start();self.assertNotEqual(self.service('stop',QELI_FAIL='signal').returncode,0)
        self.assertTrue(running(pid));self.assertTrue(self.pidfile.exists());self.assertTrue(self.plan.exists())
        self.assertNotIn('CLEANUP',self.event_lines());self.assertEqual(self.service('stop').returncode,0)
    def test_cleanup_error_after_join_retains_identity_for_retry(self):
        pid=self.start();self.assertNotEqual(self.service('stop',QELI_FAIL='cleanup').returncode,0)
        self.assert_joined(pid);self.assertTrue(self.pidfile.exists());self.assertTrue(self.plan.exists())
        self.assertEqual(self.service('status').returncode,3)
        self.assertEqual(self.service('stop').returncode,0);self.assertFalse(self.pidfile.exists())
    def test_immediate_exit_is_failure(self):
        self.assertNotEqual(self.service('start',QELI_HELPER_MODE='exit').returncode,0)
        self.assertFalse(self.pidfile.exists());self.assertFalse(self.plan.exists())
        self.assertEqual(list(self.pidfile.parent.glob(self.pidfile.name+'.*')),[])
    def test_missing_binary_config_or_readlink_rejects_launch(self):
        for path in (self.native,self.conf,self.bin/'readlink'):
            moved=path.with_name(path.name+'.held');path.rename(moved)
            self.assertNotEqual(self.service('start').returncode,0);moved.rename(path)
        self.assertEqual(self.helper_pids(),set());self.assertFalse(self.pidfile.exists())
    def fail_publication(self):
        self.write_command('mv','case "$QELI_FAIL:$*" in publish:*/qeli-client.pid|publish-signal:*/qeli-client.pid) exit 17 ;; esac\nexec '+shlex.quote(shutil.which('mv'))+' "$@"')
        self.script.write_text(self.script.read_text().replace('[ "$QELI_FAIL" != signal ]','[ "$QELI_FAIL" != signal ] && [ "$QELI_FAIL" != publish-signal ]'))
    def test_publication_error_joins_child_and_removes_staging(self):
        self.fail_publication();self.assertNotEqual(self.service('start',QELI_FAIL='publish').returncode,0)
        self.assertTrue(self.helper_pids());self.assertFalse(any(running(p) for p in self.helper_pids()))
        self.assertFalse(self.pidfile.exists());self.assertFalse(self.plan.exists())
        self.assertEqual(list(self.pidfile.parent.glob(self.pidfile.name+'.*')),[])
    def test_publication_and_signal_error_retains_pending_identity(self):
        self.fail_publication();self.assertNotEqual(self.service('start',QELI_FAIL='publish-signal').returncode,0)
        pids=self.helper_pids();self.assertEqual(len(pids),1);self.assertTrue(all(running(p) for p in pids))
        pending=list(self.pidfile.parent.glob(self.pidfile.name+'.*'));self.assertEqual(len(pending),1)
        self.assertNotEqual(self.service('start').returncode,0);self.assertNotEqual(self.service('stop').returncode,0)
        self.assertTrue(self.plan.exists());self.assertEqual(self.helper_pids(),pids)
        pending[0].rename(self.pidfile);self.assertEqual(self.service('stop').returncode,0)
    def test_old_single_pid_record_requires_review(self):
        pid=self.start();record=self.pidfile.read_text();self.pidfile.write_text(str(pid))
        self.assertNotEqual(self.service('stop').returncode,0);self.assertTrue(running(pid))
        self.assertEqual(self.service('status').returncode,4)
        self.pidfile.write_text(record);self.assertEqual(self.service('stop').returncode,0)
    def test_status_live_stopped_and_unverified(self):
        self.assertEqual(self.service('status').returncode,3);pid=self.start();self.assertEqual(self.service('status').returncode,0)
        self.assertEqual(self.service('stop').returncode,0);self.assertFalse(running(pid))
        self.assertEqual(self.service('status').returncode,3)
    def test_deleted_executable_qualifies_original_process(self):
        pid=self.start();replacement=self.native.with_name('replacement');shutil.copyfile(NATIVE,replacement)
        replacement.chmod(0o700);replacement.replace(self.native)
        self.assertEqual(self.service('stop').returncode,0);self.assert_joined(pid)
    def test_nat_failure_aborts_through_joined_stop(self):
        self.assertNotEqual(self.service('start',QELI_FAIL='nat-up').returncode,0)
        pid=next(iter(self.helper_pids()));self.assert_joined(pid)
        self.assertFalse(self.pidfile.exists());self.assertFalse(self.plan.exists())
    def test_missing_plan_timeout_aborts_through_joined_stop(self):
        self.conf.write_text('[qeli]\ngateway_nat = false\n')
        self.script.write_text(self.script.read_text().replace('case "$1" in','OPKGTUN=""\ncase "$1" in'))
        self.assertNotEqual(self.service('start',QELI_HELPER_MODE='no-plan',QELI_TEST_GATEWAY_OWNER='legacy').returncode,0)
        pid=next(iter(self.helper_pids()));self.assertFalse(running(pid));self.assertFalse(self.pidfile.exists())
        lines=self.event_lines();self.assertGreater(lines.index('CLEANUP'),next(i for i,l in enumerate(lines) if l.startswith('EXIT ')))
    def test_comm_parenthesis_and_spaces(self):
        pid=self.start(QELI_HELPER_COMM='1');self.assertEqual(self.service('stop').returncode,0);self.assert_joined(pid)
    def test_pid_removal_error_retains_identity_until_retry(self):
        pid=self.start();self.write_command('rm',r"""
case "$QELI_FAIL:$*" in pid-remove:*/qeli-client.pid) exit 17 ;; esac
exec """+shlex.quote(shutil.which('rm'))+' "$@"')
        self.assertNotEqual(self.service('stop',QELI_FAIL='pid-remove').returncode,0)
        self.assertFalse(running(pid));self.assertTrue(self.pidfile.exists())
        self.assertEqual(self.service('stop').returncode,0);self.assertFalse(self.pidfile.exists())
    def test_orphan_publication_gates_actions_without_clearing_plan(self):
        pending=self.pidfile.with_name(self.pidfile.name+'.pending');pending.write_text('review');self.plan.write_text('retained')
        for action in ('start','stop','restart'):self.assertNotEqual(self.service(action).returncode,0)
        self.assertEqual(self.plan.read_text(),'retained');self.assertTrue(pending.exists())
        self.assertEqual(self.helper_pids(),set());self.assertNotIn('CLEANUP',self.event_lines())
    def test_missing_pid_stop_is_idempotent_without_link_deletion(self):
        self.assertEqual(self.service('stop').returncode,0);self.assertEqual(self.service('stop').returncode,0)
        self.assertFalse(any('link del' in c for c in self.calls()))
@unittest.skipUnless(NATIVE.is_file(),'requires explicitly built Linux native process fixture')
class KeeneticBaseProcessTests(ProcessCases,KeeneticFixture):
    TEMPLATE='release/keenetic/S99qeli'
@unittest.skipUnless(NATIVE.is_file(),'requires explicitly built Linux native process fixture')
class KeeneticOpkgTunProcessTests(ProcessCases,KeeneticFixture):
    TEMPLATE='release/keenetic/opkgtun/S99qeli'
    def test_fresh_launch_invalidates_cache_without_erasing_address_ownership(self):
        receipt = self.marker.with_name(self.marker.name+'.applied')
        pending = self.marker.with_name(self.marker.name+'.apply-pending')
        plan = '10.8.0.2\nipv4=10.8.0.2/32\nmtu=1400\ngeneration=1\n'
        old = 'opkgtun0\n'+plan
        receipt.write_text(old)
        pid = self.start()
        self.assertEqual(receipt.read_text(), old)
        self.assertTrue(pending.exists())
        # The native helper owns process admission; this write models the new
        # authenticated plan, including a reset generation, rather than its C stub.
        self.plan.write_text(plan)
        hook = self.copy_template(ROOT/'release/keenetic/opkgtun/010-qeli.sh', self.root/'hook.sh')
        self.assertEqual(self.run_script(hook, QELI_CONNECTED='yes').returncode, 0)
        self.assertIn('system configuration save', self.calls('ndmc-calls'))
        self.assertEqual(receipt.read_text(), old)
        self.assertEqual(receipt.read_text(), old)
        self.assertFalse(pending.exists())
        self.assertEqual(self.service('start').returncode, 0)
        self.assertEqual(self.helper_pids(), {pid})
        self.assertEqual(receipt.read_text(), old)
        (self.root/'ndmc-calls').unlink()
        self.assertEqual(self.run_script(hook, QELI_CONNECTED='yes').returncode, 0)
        self.assertEqual(self.calls('ndmc-calls'), ['show interface OpkgTun0'])
        self.assertEqual(self.service('stop').returncode, 0)

    def test_receipt_invalidation_failure_refuses_launch_and_keeps_recovery(self):
        receipt = self.marker.with_name(self.marker.name+'.applied')
        receipt.mkdir()
        (receipt/'canary').write_text('retained')
        self.plan.write_text('retained plan')
        self.assertNotEqual(self.service('start').returncode, 0)
        self.assertEqual(self.helper_pids(), set())
        self.assertEqual((receipt/'canary').read_text(), 'retained')
        self.assertEqual(self.plan.read_text(), 'retained plan')
        self.assertFalse(self.pidfile.exists())

    def test_preflight_failure_keeps_old_receipt_and_pending(self):
        receipt = self.marker.with_name(self.marker.name+'.applied')
        pending = self.marker.with_name(self.marker.name+'.apply-pending')
        receipt.write_text('retained receipt')
        pending.write_text('retained pending')
        self.assertNotEqual(self.service('start', QELI_TEST_GATEWAY_EXIT='17').returncode, 0)
        self.assertEqual(self.helper_pids(), set())
        self.assertEqual(receipt.read_text(), 'retained receipt')
        self.assertEqual(pending.read_text(), 'retained pending')

    def test_stop_and_fresh_start_retain_partial_and_saved_address_ownership(self):
        receipt = self.marker.with_name(self.marker.name+'.applied')
        pending = self.marker.with_name(self.marker.name+'.apply-pending')
        self.start()
        saved = 'opkgtun0\n10.8.0.2\nipv4=10.8.0.2/32\nipv6=fd00::2/128\n'
        partial = 'opkgtun0\n10.8.0.2\nipv4=10.8.0.2/32\nipv6=fd00::9/128\n'
        receipt.write_text(saved);pending.write_text(partial)
        self.assertEqual(self.service('stop').returncode, 0)
        self.assertEqual(receipt.read_text(), saved);self.assertEqual(pending.read_text(), partial)
        self.assertFalse(self.marker.exists())
        self.start()
        self.assertEqual(receipt.read_text(), saved);self.assertEqual(pending.read_text(), partial)
        self.assertEqual(self.service('stop').returncode, 0)

    def test_linked_or_directory_pending_refuses_launch_without_touching_foreign_file(self):
        pending = self.marker.with_name(self.marker.name+'.apply-pending')
        foreign = self.root/'foreign';foreign.write_text('foreign data')
        for kind in ['directory', 'link']:
            with self.subTest(kind=kind):
                if kind=='directory':pending.mkdir()
                else:pending.symlink_to(foreign)
                self.plan.write_text('retained plan')
                self.assertNotEqual(self.service('start').returncode, 0)
                self.assertEqual(self.helper_pids(), set())
                self.assertEqual(self.plan.read_text(), 'retained plan')
                self.assertEqual(foreign.read_text(), 'foreign data')
                if kind=='directory':pending.rmdir()
                else:pending.unlink()

    def test_marker_publication_error_joins_before_failure(self):
        self.marker.mkdir();self.assertNotEqual(self.service('start').returncode,0)
        pid=next(iter(self.helper_pids()));self.assertFalse(running(pid));self.assertTrue(self.pidfile.exists())
        self.marker.rmdir();self.assertEqual(self.service('stop').returncode,0);self.assertFalse(self.pidfile.exists())
