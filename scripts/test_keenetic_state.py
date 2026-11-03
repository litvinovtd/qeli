"""Keenetic legacy state tests: temporary proc/sys files and firewall command model.
No actual forwarding/firewall/PID signals or router service execution.
"""
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
from test_keenetic_templates import KeeneticFixture, ROOT

class StateCases:
    def setUp(self):
        super().setUp()
        (self.root/'tun').touch()
        (self.bin/'readlink').symlink_to(shutil.which('readlink'))
        executable=self.opt/'bin/qeli-client';executable.parent.mkdir(parents=True)
        executable.write_text('#!/bin/sh\nif [ "$3" = --print-gateway-owner ]; then printf "legacy\\n"; exit 0; fi\nexit 99\n');executable.chmod(0o700)
        self.sysroot=self.root/'proc-sys'
        self.ip4=self.sysroot/'net/ipv4/ip_forward'
        self.ip6=self.sysroot/'net/ipv6/conf/all/forwarding'
        self.ra=self.sysroot/'net/ipv6/conf/eth0/accept_ra'
        for p,value in [(self.ip4,'0'),(self.ip6,'0'),(self.ra,'1')]:
            p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value+'\n')
        (self.opt/'var/run').mkdir(parents=True)
        (self.opt/'var/log').mkdir(parents=True)
        (self.opt/'etc/qeli').mkdir(parents=True)
        (self.opt/'etc/qeli/client.conf').write_text('[qeli]\ngateway_nat = false\nforward = false\n')
        self.state=self.opt/'var/run/qeli-forwarding.state'
        self.plan=self.opt/('var/run/qeli.tunip' if 'opkgtun' in self.TEMPLATE else 'var/run/qeli.network-plan')
        self.plan.write_text('ipv4=10.8.0.2/32\nipv6=fd00::2/128\n')
        self.write_command('ip',r"""
printf 'ip %s\n' "$*" >> "$QELI_FIXTURE_ROOT/calls"
[ "$QELI_FAIL" != wan-query ] || exit 17
case "$*" in '-6 route show default') printf 'default via fixture dev eth0\n' ;; esac
""")
        self.rules=self.root/'rules.json';self.rules.write_text('[]')
        model=self.root/'firewall.py'
        model.write_text(r"""import json,os,sys
from pathlib import Path
root=Path(os.environ['QELI_FIXTURE_ROOT']);args=sys.argv[1:];fw=Path(sys.argv[0]).name
with (root/'firewall-calls').open('a') as out:out.write(fw+' '+repr(args)+'\n')
operation=next(a for a in args if a in ('-C','-A','-D'))
table=args[args.index('-t')+1] if '-t' in args else 'filter'
if '-t' in args:
 n=args.index('-t');args=args[:n]+args[n+2:]
args=[a for a in args if a!=operation];key=[fw,table,*args]
p=root/'rules.json';rules=json.loads(p.read_text());fail=os.environ.get('QELI_FAIL','')
if fail=='firewall-check' and operation=='-C':sys.exit(2)
if fail=='firewall-delete' and operation=='-D':sys.exit(17)
if fail=='firewall-add' and operation=='-A':sys.exit(17)
if operation=='-C':sys.exit(0 if key in rules else 1)
if operation=='-A':rules.append(key)
elif key in rules:rules.remove(key)
else:sys.exit(1)
p.write_text(json.dumps(rules))
""")
        for command in ('iptables','ip6tables'):
            # argv0 must identify the family while interpreter remains absolute.
            p=self.bin/command;p.unlink();p.write_text('#!'+sys.executable+'\n'+model.read_text());p.chmod(0o700)
        self.template=self.root/'state-template.sh'
        self.copy_template(ROOT/self.TEMPLATE,self.template)
        text=self.template.read_text().replace('/proc/sys/',str(self.sysroot)+'/').replace('/proc/',str(self.root/'proc')+'/')
        text,dispatch=text.rsplit('case "$1" in',1)
        self.dispatch='case "$1" in'+dispatch
        # Tests exercise legacy functions for both templates; never operate ndm.
        self.body=text+'\n. '+shlex.quote(str(self.opt/'etc/qeli/lifecycle.sh'))+'\nOPKGTUN=""; TUN=vpn0; GATEWAY_OWNER=legacy\n'

    def execute(self,expression,**env):
        script=self.root/'state-case.sh'
        # Every potential builtin signal is intercepted in the model.
        script.write_text(self.body+r"""
kill() { printf 'kill %s\n' "$*" >> "$QELI_FIXTURE_ROOT/calls"; return 1; }
echo() {
  command echo "$@"
  case "$QELI_FAIL:$*" in restore-write:0|journal-write:*_touched=1) return 17 ;; esac
}
"""+expression+'\n')
        return self.run_script(script,**env)

    def up(self):
        result=self.execute('nat_up');self.assertEqual(result.returncode,0,result.stderr)
    def seed_untagged(self):
        rules=[]
        for fw in ('iptables','ip6tables'):
            rules.extend([[fw,'nat','POSTROUTING','-o','vpn0','-j','MASQUERADE'],
                [fw,'filter','FORWARD','-i','br0','-o','vpn0','-j','ACCEPT']])
        self.rules.write_text(json.dumps(rules));return rules

    def test_snapshot_is_complete_private_and_atomic(self):
        result=self.execute('save_forwarding_state');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.state.stat().st_mode&0o777,0o600)
        self.assertEqual(self.state.read_text(),'version=2\nipv4=0\nipv6=0\nwan6=eth0\naccept_ra6=1\ntun=vpn0\nlan=br0\n')
        self.assertEqual(list(self.state.parent.glob(self.state.name+'.*')),[])

    def test_failed_snapshot_read_never_creates_checkpoint_or_changes_forwarding(self):
        self.ip4.unlink();self.ip4.mkdir()
        result=self.execute('nat_up');self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.state.exists());self.assertEqual(self.ip6.read_text().strip(),'0')
        self.assertFalse((self.root/'firewall-calls').exists())

    def test_ipv4_only_host_does_not_require_ipv6_sysctl_or_firewall(self):
        self.ip6.unlink();self.ra.unlink();self.plan.write_text('ipv4=10.8.0.2/32\n')
        (self.bin/'ip6tables').unlink();self.up()
        self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(self.ip4.read_text().strip(),'0');self.assertFalse(self.state.exists())

    def test_disabled_ipv6_family_is_not_probed_or_read(self):
        self.plan.write_text('ipv4=10.8.0.2/32\n');self.ip6.unlink();self.ip6.mkdir()
        self.assertEqual(self.execute('nat_up',QELI_FAIL='wan-query').returncode,0)
        self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(self.ip4.read_text().strip(),'0')

    def test_ipv6_only_plan_does_not_require_ipv4_sysctl_or_firewall(self):
        self.plan.write_text('ipv6=fd00::2/128\n');self.ip4.unlink();self.ip4.mkdir()
        (self.bin/'iptables').unlink();self.up()
        self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(self.ip6.read_text().strip(),'0');self.assertEqual(self.ra.read_text().strip(),'1')
        self.assertFalse(self.state.exists())

    def test_unavailable_untouched_ra_sysctl_does_not_block_recovery(self):
        self.ra.unlink();self.up()
        self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(self.ip6.read_text().strip(),'0');self.assertFalse(self.state.exists())

    def test_failed_wan_query_rejects_snapshot_before_changes(self):
        self.assertNotEqual(self.execute('nat_up',QELI_FAIL='wan-query').returncode,0)
        self.assertFalse(self.state.exists());self.assertEqual(self.ip4.read_text().strip(),'0')
        self.assertFalse((self.root/'firewall-calls').exists())

    def test_existing_checkpoint_rejects_new_rule_interfaces_until_cleanup(self):
        self.up();before=self.rules.read_text()
        self.assertNotEqual(self.execute('TUN=other; nat_up').returncode,0)
        self.assertEqual(self.rules.read_text(),before)
        self.assertEqual(self.execute('nat_down').returncode,0)

    def test_failed_snapshot_publication_cleans_temporary_file(self):
        real=shlex.quote(shutil.which('mv'))
        self.write_command('mv','[ "$QELI_FAIL" != state-publish ] || exit 17\nexec '+real+' "$@"')
        self.assertNotEqual(self.execute('save_forwarding_state',QELI_FAIL='state-publish').returncode,0)
        self.assertFalse(self.state.exists());self.assertEqual(list(self.state.parent.glob(self.state.name+'.*')),[])

    def test_dual_stack_cleanup_preserves_untagged_admin_rules_and_restores_values(self):
        original=self.seed_untagged();self.up()
        self.assertEqual(self.ip4.read_text().strip(),'1');self.assertEqual(self.ip6.read_text().strip(),'1');self.assertEqual(self.ra.read_text().strip(),'2')
        self.assertEqual(len(json.loads(self.rules.read_text())),len(original)+8)
        result=self.execute('GATEWAY=no; OPKGTUN=opkgtun9; TUN=changed; LAN_IF=changed; nat_down')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.rules.read_text()),original)
        self.assertEqual(self.ip4.read_text().strip(),'0');self.assertEqual(self.ip6.read_text().strip(),'0');self.assertEqual(self.ra.read_text().strip(),'1')
        self.assertFalse(self.state.exists())

    def test_repeated_apply_never_duplicates_owned_rules(self):
        original=self.seed_untagged();self.up();self.up()
        self.assertEqual(len(json.loads(self.rules.read_text())),len(original)+8)
        self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(json.loads(self.rules.read_text()),original)

    def test_check_and_add_failures_reject_apply_and_allow_cleanup_retry(self):
        for fail in ('firewall-check','firewall-add'):
            result=self.execute('nat_up',QELI_FAIL=fail);self.assertNotEqual(result.returncode,0)
            self.assertTrue(self.state.exists())
            self.assertEqual(json.loads(self.rules.read_text()),[])
            self.assertEqual(self.execute('nat_down').returncode,0);self.assertFalse(self.state.exists())
            self.assertEqual(self.ip4.read_text().strip(),'0')

    def test_missing_required_firewall_during_cleanup_retains_retry_state(self):
        self.up();(self.bin/'ip6tables').unlink()
        self.assertNotEqual(self.execute('nat_down').returncode,0)
        self.assertTrue(self.state.exists());self.assertEqual(self.ip6.read_text().strip(),'1')

    def test_no_checkpoint_means_no_firewall_deletion(self):
        original=self.seed_untagged();self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(json.loads(self.rules.read_text()),original)
        self.assertFalse((self.root/'firewall-calls').exists())

    def test_untouched_family_is_not_restored_over_an_administrator_change(self):
        self.plan.write_text('ipv4=10.8.0.2/32\n');self.up()
        self.ip6.write_text('1\n');self.ra.write_text('2\n')
        self.assertEqual(self.execute('nat_down').returncode,0)
        self.assertEqual(self.ip6.read_text().strip(),'1');self.assertEqual(self.ra.read_text().strip(),'2')

    def test_delete_and_check_errors_retain_checkpoint_until_successful_retry(self):
        self.up()
        for fail in ('firewall-delete','firewall-check'):
            result=self.execute('nat_down',QELI_FAIL=fail);self.assertNotEqual(result.returncode,0)
            self.assertTrue(self.state.exists());self.assertEqual(self.ip4.read_text().strip(),'1')
        self.assertEqual(self.execute('nat_down').returncode,0);self.assertFalse(self.state.exists())

    def test_restore_read_error_keeps_checkpoint_and_retry_completes(self):
        self.up();self.ra.unlink();self.ra.mkdir()
        self.assertNotEqual(self.execute('nat_down').returncode,0);self.assertTrue(self.state.exists())
        self.ra.rmdir();self.ra.write_text('2\n')
        self.assertEqual(self.execute('nat_down').returncode,0);self.assertFalse(self.state.exists())
        self.assertEqual(self.ra.read_text().strip(),'1')

    def test_restore_write_error_keeps_checkpoint_and_retry_completes(self):
        self.up();self.assertNotEqual(self.execute('nat_down',QELI_FAIL='restore-write').returncode,0)
        self.assertTrue(self.state.exists())
        self.assertEqual(self.execute('nat_down').returncode,0);self.assertFalse(self.state.exists())

    def test_journal_error_precedes_forwarding_mutation(self):
        self.assertNotEqual(self.execute('nat_up',QELI_FAIL='journal-write').returncode,0)
        self.assertTrue(self.state.exists());self.assertEqual(self.ip4.read_text().strip(),'0')
        self.assertFalse((self.root/'firewall-calls').exists())

    def test_corrupt_and_old_checkpoint_reject_cleanup_without_mutation(self):
        for content in ('version=2\nipv4=bad\nipv6=0\ntun=vpn0\nlan=br0\n','ipv4=0\nipv6=0\n','version=9\nipv4=0\n'):
            self.state.write_text(content)
            result=self.execute('nat_down');self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.state.read_text(),content);self.assertEqual(self.ip4.read_text().strip(),'0')

    def test_failed_stale_recovery_gates_start_and_keeps_plan(self):
        self.state.write_text('ipv4=0\nipv6=0\n');before=self.plan.read_text()
        result=self.execute('start');self.assertNotEqual(result.returncode,0)
        self.assertNotIn('qeli-client: старт',result.stdout)
        self.assertEqual(self.plan.read_text(),before);self.assertTrue(self.state.exists())

    def test_failed_cleanup_gates_stop_and_restart_without_signals(self):
        self.state.write_text('ipv4=0\nipv6=0\n');pid=self.opt/'var/run/qeli-client.pid';pid.write_text('900001 1')
        before=self.plan.read_text()
        for expression in ('stop','set -- restart\n'+self.dispatch):
            result=self.execute(expression);self.assertNotEqual(result.returncode,0)
            self.assertNotIn('qeli-client: старт',result.stdout)
            self.assertEqual(pid.read_text(),'900001 1');self.assertEqual(self.plan.read_text(),before)
        self.assertFalse(any(c.startswith('kill ') for c in self.calls()))

class KeeneticBaseStateTests(StateCases,KeeneticFixture):
    TEMPLATE='release/keenetic/S99qeli'
class KeeneticOpkgTunStateTests(StateCases,KeeneticFixture):
    TEMPLATE='release/keenetic/opkgtun/S99qeli'
