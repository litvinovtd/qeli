"""Canonical gateway inspector and init gates; all network actions are models."""
import os
from pathlib import Path
import shlex
import unittest
from test_keenetic_templates import KeeneticFixture
import test_keenetic_state as state
INSPECTOR=Path(os.environ.get('QELI_GATEWAY_INSPECTOR','/nonexistent-qeli-inspector'))
BASE='[qeli]\nserver=192.0.2.1:443\nmode=plain\nbind_static=false\ngateway=false\nuser=fixture\npass=canary-password\n'

class OwnerCases:
    def setUp(self):
        self.f=self.CASE('test_snapshot_is_complete_private_and_atomic');self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.conf=self.f.opt/'etc/qeli/client.conf'
        self.binary=self.f.opt/'bin/qeli-client'
        self.binary.write_text('''#!/bin/sh
if [ "$3" = --print-gateway-owner ]; then
 printf 'inspect\\n' >> "$QELI_FIXTURE_ROOT/owner-calls"
 printf '%s\\n' "${QELI_TEST_GATEWAY_OWNER-core}"
 exit "${QELI_TEST_GATEWAY_EXIT:-0}"
fi
exit 99
''')
        self.binary.chmod(0o700)
    def owner_calls(self):return self.f.calls('owner-calls')
    def test_core_reply_prevents_all_legacy_firewall_and_sysctl_changes(self):
        self.conf.write_text(BASE+'exit_node=true\n')
        result=self.f.execute('load_gateway_owner && nat_up',QELI_TEST_GATEWAY_OWNER='core')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(self.f.state.exists());self.assertEqual(self.f.ip4.read_text().strip(),'0')
        self.assertFalse((self.f.root/'firewall-calls').exists());self.assertEqual(self.owner_calls(),['inspect'])
    def test_legacy_reply_retains_compatibility_apply_and_cleanup(self):
        result=self.f.execute('load_gateway_owner && nat_up',QELI_TEST_GATEWAY_OWNER='legacy')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertTrue(self.f.state.exists())
        self.assertEqual(self.f.ip4.read_text().strip(),'1')
        self.assertEqual(self.f.execute('nat_down').returncode,0);self.assertEqual(self.f.ip4.read_text().strip(),'0')
    def test_inspection_exit_error_prevents_launch_and_preserves_plan(self):
        before=self.f.plan.read_bytes()
        result=self.f.execute('start',QELI_TEST_GATEWAY_EXIT='17')
        self.assertNotEqual(result.returncode,0);self.assertEqual(self.f.plan.read_bytes(),before)
        self.assertNotIn('qeli-client: старт',result.stdout);self.assertFalse(self.f.state.exists())
        self.assertFalse((self.f.opt/'var/run/qeli-client.pid').exists())
    def test_unknown_multiline_or_empty_reply_cannot_start(self):
        for response in ('','unknown','core\nlegacy',' '):
            with self.subTest(response=response):
                before=self.f.plan.read_bytes()
                result=self.f.execute('start',QELI_TEST_GATEWAY_OWNER=response)
                self.assertNotEqual(result.returncode,0);self.assertEqual(self.f.plan.read_bytes(),before)
                self.assertFalse(self.f.state.exists());self.assertNotIn('qeli-client: старт',result.stdout)
    def test_inspection_is_cached_once_before_legacy_decisions(self):
        result=self.f.execute('load_gateway_owner && { QELI_TEST_GATEWAY_OWNER=legacy; nat_up; }',QELI_TEST_GATEWAY_OWNER='core')
        self.assertEqual(result.returncode,0);self.assertEqual(self.owner_calls(),['inspect'])
        self.assertFalse(self.f.state.exists())
    def test_unadmitted_gateway_cannot_fall_back_to_legacy(self):
        result=self.f.execute('GATEWAY_OWNER=""; nat_up')
        self.assertNotEqual(result.returncode,0);self.assertFalse(self.f.state.exists())
        self.assertFalse((self.f.root/'firewall-calls').exists())
    def test_disabled_gateway_and_opkgtun_still_require_interface_admission(self):
        for expression in ('GATEWAY=no; load_gateway_owner','OPKGTUN=opkgtun0; load_gateway_owner'):
            self.assertNotEqual(self.f.execute(expression,QELI_TEST_GATEWAY_EXIT='17').returncode,0)
        self.assertEqual(self.owner_calls(),['inspect','inspect'])
    @unittest.skipUnless(INSPECTOR.is_file(),'requires freshly built actual Linux qeli-client inspector')
    def test_actual_core_parser_matrix_drives_legacy_admission(self):
        self.f.body+='\nBIN='+shlex.quote(str(INSPECTOR))+'\n'
        cases=[('plain-true',BASE+'gateway_nat=true\n','core'),
               ('quoted',BASE+'gateway_nat="TrUe"\n','core'),
               ('case',BASE.replace('[qeli]','[QELI]')+'GATEWAY_NAT=YES\n','core'),
               ('on',BASE+'forward=on\n','core'),
               ('bom','\ufeff'+BASE+'gateway_nat=ON\n','core'),
               ('exit-node',BASE+'exit_node=true\n','core'),
               ('absent',BASE,'legacy'),('false',BASE+'gateway_nat="OFF"\n','legacy'),
               ('invalid-bool',BASE+'gateway_nat=maybe\n',None),
               ('duplicate',BASE+'gateway_nat=true\ngateway_nat=false\n',None),
               ('conflict',BASE+'exit_node=true\nforward=true\n',None)]
        for label,text,wanted in cases:
            with self.subTest(label=label):
                self.conf.write_text(text);before=self.f.plan.read_bytes()
                result=self.f.execute('load_gateway_owner && nat_up')
                if wanted is None:
                    self.assertNotEqual(result.returncode,0);self.assertEqual(self.f.plan.read_bytes(),before)
                    self.assertFalse(self.f.state.exists())
                else:
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                    self.assertEqual(self.f.state.exists(),wanted=='legacy')
                    self.assertEqual(self.f.ip4.read_text().strip(),'1' if wanted=='legacy' else '0')
                    if wanted=='legacy':self.assertEqual(self.f.execute('nat_down').returncode,0)


    @unittest.skipUnless(INSPECTOR.is_file(),'requires actual Linux qeli-client inspector')
    def test_actual_mismatched_device_rejects_before_wrapper_recovery(self):
        self.f.body+='\nBIN='+shlex.quote(str(INSPECTOR))+'\n'
        for device in ('vpn1','opkgtun0','wan0'):
            with self.subTest(device=device):
                self.conf.write_text(BASE+'dev='+device+'\n')
                before=self.f.plan.read_bytes()
                result=self.f.execute('load_gateway_owner')
                self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
                self.assertEqual(self.f.plan.read_bytes(),before)
                self.assertFalse(self.f.state.exists())
                self.assertFalse((self.f.root/'firewall-calls').exists())

    @unittest.skipUnless(INSPECTOR.is_file(),'requires actual Linux qeli-client inspector')
    def test_actual_opkgtun_requires_matching_attached_tun_and_external_gateway(self):
        self.f.body+='\nBIN='+shlex.quote(str(INSPECTOR))+'\n'
        base=BASE+'dev=opkgtun0\ndev_attach=ON\n'
        expression='OPKGTUN=opkgtun0; TUN=opkgtun0; load_gateway_owner'
        cases=[(base,True),(BASE+'dev=opkgtun0\n',False),
               (base.replace('opkgtun0','opkgtun1'),False),
               (base+'device_type=tap\n',False)]
        cases.extend((base+key+'=true\n',False) for key in ('gateway_nat','forward','exit_node'))
        for text,accepted in cases:
            with self.subTest(text=text):
                self.conf.write_text(text);before=self.f.plan.read_bytes()
                result=self.f.execute(expression)
                self.assertEqual(result.returncode==0,accepted,result.stdout+result.stderr)
                self.assertEqual(self.f.plan.read_bytes(),before)
                self.assertFalse(self.f.state.exists())

    @unittest.skipUnless(INSPECTOR.is_file(),'requires actual Linux qeli-client inspector')
    def test_actual_disabled_gateway_cannot_bypass_device_or_attach_check(self):
        self.f.body+='\nBIN='+shlex.quote(str(INSPECTOR))+'\n'
        for extra in ('dev=vpn1\n','dev_attach=true\n','device_type=tap\n'):
            self.conf.write_text(BASE+extra)
            self.assertNotEqual(self.f.execute('GATEWAY=no; load_gateway_owner').returncode,0)
        self.conf.write_text(BASE)
        self.assertEqual(self.f.execute('GATEWAY=no; load_gateway_owner').returncode,0)

    @unittest.skipUnless(INSPECTOR.is_file(),'requires actual Linux qeli-client inspector')
    def test_actual_interface_admission_keeps_shared_ini_parity(self):
        self.f.body+='\nBIN='+shlex.quote(str(INSPECTOR))+'\n'
        for text in (BASE,BASE+'dev="vpn0"\ndev_attach="OFF"\n',
                     '\ufeff'+BASE.replace('[qeli]','[QELI]')+'DEV=vpn0\nDEV_ATTACH=NO\n'):
            self.conf.write_text(text)
            self.assertEqual(self.f.execute('load_gateway_owner').returncode,0)

class KeeneticGatewayBaseTests(OwnerCases,unittest.TestCase):
    CASE=state.KeeneticBaseStateTests
class KeeneticGatewayOpkgTunTests(OwnerCases,unittest.TestCase):
    CASE=state.KeeneticOpkgTunStateTests

if __name__=='__main__':unittest.main()
