"""Actual shell lifecycle with stateful ndmc model, not Keenetic firmware."""
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
from test_keenetic_templates import KeeneticFixture

MODEL = r'''import json,os,sys
from pathlib import Path
root=Path(os.environ['QELI_FIXTURE_ROOT']);command=sys.argv[2]
with (root/'ndmc-calls').open('a') as out:out.write(command+'\n')
path=root/'ndm.json';state=json.loads(path.read_text());words=command.split()
fail=os.environ.get('QELI_FAIL','')
if fail and fail in command:sys.exit(17)
if words[:2]==['show','interface']:
 current=state.get(words[2],{'ipv4':'','ipv6':[]})
 print('connected: yes');print('address:',current['ipv4'])
 if os.environ.get('QELI_PEER4'):print('gateway:',os.environ['QELI_PEER4'])
 for address in current['ipv6']:print('ipv6 address:',address)
elif words and words[0]=='interface':
 current=state.setdefault(words[1],{'ipv4':'','ipv6':[]});args=words[2:]
 if args[:2]==['ip','address']:current['ipv4']=args[2]
 elif args==['no','ip','address']:current['ipv4']=''
 elif args[:2]==['ipv6','address']:
  if args[2] not in current['ipv6']:current['ipv6'].append(args[2])
 elif args[:3]==['no','ipv6','address']:
  if args[3] in current['ipv6']:current['ipv6'].remove(args[3])
path.write_text(json.dumps(state))
if command==os.environ.get('QELI_ROTATE_AT') and not (root/'rotated').exists():
 (root/'rotated').touch();(root/'rotation-plan').replace(Path(os.environ['QELI_PLAN_PATH']))
'''


def plan(ipv4='10.8.0.2', ipv6='fd00::2/128', generation=1):
    primary=ipv4 or (ipv6.split('/')[0] if ipv6 else '')
    return primary+'\n'+('ipv4='+ipv4+'/32\n' if ipv4 else '')+('ipv6='+ipv6+'\n' if ipv6 else '')+f'mtu=1400\ngeneration={generation}\n'


class AddressRetirementTests(KeeneticFixture):
    def setUp(self):
        super().setUp()
        self.folder=self.hook_setup(plan=plan())
        baseline=os.environ.get('QELI_OPKGTUN_ADDRESS_BASELINE')
        if baseline:self.copy_template(Path(baseline)/'010-qeli.sh',self.hook)
        self.plan_path=self.folder/'qeli.tunip';self.env['QELI_PLAN_PATH']=str(self.plan_path)
        self.applied=self.folder/'qeli.opkgtun.applied';self.pending=self.folder/'qeli.opkgtun.apply-pending'
        self.model=self.root/'ndm.json';self.model.write_text(json.dumps({'OpkgTun0':{'ipv4':'','ipv6':['2001:db8::99/64']}}))
        self.write_command('ndmc','exec '+shlex.quote(sys.executable)+' '+shlex.quote(str(self.root/'model.py'))+' "$@"')
        (self.root/'model.py').write_text(MODEL)

    def state(self, name='OpkgTun0'):
        return json.loads(self.model.read_text())[name]

    def apply(self, value=None, **env):
        if value is not None:self.plan_path.write_text(value)
        result=self.run_script(self.hook,**env)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        return result

    def seed_saved(self):
        self.apply();(self.root/'ndmc-calls').unlink();(self.opt/'var/log/qeli-client.log').unlink()

    def test_dual_to_ipv4_retires_only_owned_ipv6(self):
        self.seed_saved();self.apply(plan(ipv6='',generation=2))
        self.assertEqual(self.state(),{'ipv4':'10.8.0.2','ipv6':['2001:db8::99/64']})
        self.assertIn('interface OpkgTun0 no ipv6 address fd00::2/128',self.calls('ndmc-calls'))

    def test_dual_to_ipv6_clears_owned_ipv4(self):
        self.seed_saved();self.apply(plan(ipv4='',generation=2))
        self.assertEqual(self.state()['ipv4'],'')
        self.assertIn('interface OpkgTun0 no ip address',self.calls('ndmc-calls'))

    def test_ipv6_readdress_preserves_foreign_address(self):
        self.seed_saved();self.apply(plan(ipv6='fd00::9/128',generation=2))
        self.assertEqual(self.state()['ipv6'],['2001:db8::99/64','fd00::9/128'])

    def test_absent_ipv4_family_does_not_clear_administrator_replacement(self):
        self.seed_saved();state=json.loads(self.model.read_text());state['OpkgTun0']['ipv4']='192.0.2.9';self.model.write_text(json.dumps(state))
        self.apply(plan(ipv4='',generation=2));self.assertEqual(self.state()['ipv4'],'192.0.2.9')
        self.assertNotIn('interface OpkgTun0 no ip address',self.calls('ndmc-calls'))

    def test_peer_mention_cannot_authorize_clearing_foreign_ipv4(self):
        self.seed_saved();state=json.loads(self.model.read_text());state['OpkgTun0']['ipv4']='192.0.2.9';self.model.write_text(json.dumps(state))
        self.apply(plan(ipv4='',generation=2),QELI_PEER4='10.8.0.2')
        self.assertEqual(self.state()['ipv4'],'192.0.2.9')
        self.assertNotIn('interface OpkgTun0 no ip address',self.calls('ndmc-calls'))

    def test_peer_mention_cannot_qualify_cached_plan_when_local_ipv4_changed(self):
        self.seed_saved();state=json.loads(self.model.read_text());state['OpkgTun0']['ipv4']='192.0.2.9';self.model.write_text(json.dumps(state))
        self.apply(QELI_PEER4='10.8.0.2')
        self.assertEqual(self.state()['ipv4'],'10.8.0.2')
        self.assertIn('system configuration save',self.calls('ndmc-calls'))

    def test_partial_plan_replacement_retires_saved_and_pending_addresses(self):
        self.seed_saved();middle=plan(ipv6='fd00::9/128',generation=2);final=plan(ipv6='fd00::10/128',generation=3)
        self.plan_path.write_text(middle);(self.root/'rotation-plan').write_text(final)
        result=self.run_script(self.hook,QELI_ROTATE_AT='interface OpkgTun0 ipv6 address fd00::9/128')
        self.assertNotEqual(result.returncode,0);self.assertIn('fd00::9/128',self.pending.read_text())
        self.apply();self.assertEqual(self.state()['ipv6'],['2001:db8::99/64','fd00::10/128'])
        self.assertFalse(self.pending.exists())

    def test_failed_retirement_preserves_records_then_retries(self):
        self.seed_saved();old=self.applied.read_text();self.plan_path.write_text(plan(ipv6='',generation=2))
        result=self.run_script(self.hook,QELI_FAIL='no ipv6 address')
        self.assertNotEqual(result.returncode,0);self.assertEqual(self.applied.read_text(),old)
        self.assertTrue(self.pending.exists());self.assertNotIn('system configuration save',self.calls('ndmc-calls'))
        self.apply();self.assertEqual(self.state()['ipv6'],['2001:db8::99/64'])

    def test_failed_pending_publication_cannot_add_an_unjournaled_address(self):
        self.seed_saved();self.plan_path.write_text(plan(ipv6='fd00::9/128',generation=2))
        real=shlex.quote(shutil.which('mv'))
        self.write_command('mv','for argument do case "$argument" in *.apply-pending) exit 17 ;; esac; done\nexec '+real+' "$@"')
        result=self.run_script(self.hook);self.assertNotEqual(result.returncode,0)
        self.assertNotIn('fd00::9/128',self.state()['ipv6']);self.assertTrue(self.pending.exists())
        self.assertFalse(list(self.folder.glob('qeli.opkgtun.apply-pending.*')))
        self.write_command('mv','exec '+real+' "$@"');self.apply()
        self.assertEqual(self.state()['ipv6'],['2001:db8::99/64','fd00::9/128'])

    def test_plan_rotation_during_retirement_keeps_pending_ownership(self):
        self.seed_saved();old_pending='opkgtun0\n'+plan(ipv6='fd00::9/128',generation=2);self.pending.write_text(old_pending)
        state=json.loads(self.model.read_text());state['OpkgTun0']['ipv6'].append('fd00::9/128');self.model.write_text(json.dumps(state))
        self.plan_path.write_text(plan(ipv6='fd00::10/128',generation=3));(self.root/'rotation-plan').write_text(plan(ipv6='fd00::11/128',generation=4))
        result=self.run_script(self.hook,QELI_ROTATE_AT='interface OpkgTun0 no ipv6 address fd00::2/128')
        self.assertNotEqual(result.returncode,0);self.assertEqual(self.pending.read_text(),old_pending)
        self.apply();self.assertEqual(self.state()['ipv6'],['2001:db8::99/64','fd00::11/128'])

    def test_same_addresses_new_generation_do_not_delete_them(self):
        self.seed_saved();self.apply(plan(generation=2))
        self.assertFalse(any(' no ' in command for command in self.calls('ndmc-calls')))
        self.assertIn('system configuration save',self.calls('ndmc-calls'))

    def test_interface_change_retires_only_recorded_old_interface_addresses(self):
        self.seed_saved();(self.folder/'qeli.opkgtun').write_text('opkgtun1')
        self.apply(plan(ipv4='10.8.0.9',ipv6='fd00::9/128',generation=2))
        self.assertEqual(self.state(),{'ipv4':'','ipv6':['2001:db8::99/64']})
        self.assertEqual(self.state('OpkgTun1'),{'ipv4':'10.8.0.9','ipv6':['fd00::9/128']})

    def test_legacy_primary_receipt_can_retire_its_ipv4(self):
        self.seed_saved();self.applied.write_text('opkgtun0\n10.8.0.2\n')
        self.apply(plan(ipv4='',generation=2));self.assertEqual(self.state()['ipv4'],'')

    def test_invalid_previous_interface_cannot_mutate_other_interfaces(self):
        self.seed_saved();self.applied.write_text('eth0\n'+plan());self.plan_path.write_text(plan(ipv6='',generation=2))
        result=self.run_script(self.hook);self.assertNotEqual(result.returncode,0)
        self.assertFalse(any(command.startswith('interface eth0') for command in self.calls('ndmc-calls')))
        self.assertNotIn('system configuration save',self.calls('ndmc-calls'))
