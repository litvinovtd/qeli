import tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from audit_android_leak_bursts import LeakBursts

class StartupStateTest(unittest.TestCase):
    def run_burst(self,label):
        calls=[];journal=[]
        def arun(*args,**kwargs):
            calls.append((args,kwargs))
            count=int(args[args.index("burst_count")+1]);observe="observe_network" in args
            journal.append("BURST_WATCH_READY run=1 uid=10148 device_ms=90")
            for family in ("ipv4","ipv6"):
                for protocol in ("tcp","udp"):
                    journal.append(f"BURST_BEGIN run=1 uid=10148 family={family} protocol={protocol} count={count}")
                    for i in range(count):
                        if observe:journal.append(f"BURST_STATE run=1 sample={i} uid=10148 family={family} protocol={protocol} before_ms=99 after_ms=100 network=103 vpn=true iface=tun0 v4=true v6=true")
                        journal.append(f"BURST run=1 sample={i} tag=Q29PROTECTED uid=10148 family={family} protocol={protocol} bytes=257 started_ms=100 done_ms=101 error=EACCES")
            journal.append("BURST_FINISHED run=1 uid=10148")
            return types.SimpleNamespace(returncode=0,stdout="fixture broadcast",stderr="")
        with tempfile.TemporaryDirectory() as temp:
            bursts=LeakBursts(arun,Path(temp),None,{'startup_state_enabled':True,'probe_uids':{'com.qeli.test':'10148'}})
            bursts.logs=lambda:"\n".join(journal)
            row=bursts.run(label)
        return row,calls[0]
    def test_cold_observation_uses_background_deadline_and_all_96_states(self):
        row,(argv,kwargs)=self.run_burst('cold-lockdown-start')
        self.assertEqual(len(row['samples']),96)
        self.assertEqual(len(row['network_states']),96)
        self.assertNotIn('--receiver-foreground',argv)
        self.assertEqual(kwargs['timeout'],35)
        self.assertFalse(any(v['success'] for v in row['samples']))
    def test_other_phases_keep_48_samples_and_foreground_deadline(self):
        row,(argv,kwargs)=self.run_burst('connected-steady')
        self.assertEqual(len(row['samples']),48)
        self.assertEqual(row['network_states'],[])
        self.assertIn('--receiver-foreground',argv)
        self.assertEqual(kwargs['timeout'],20)

class PublishedStartTest(unittest.TestCase):
    def run_start(self, missing=False, failed=False, late=False, follow_failed=False):
        from audit_android_startup_dns import StartupDns
        def node(**values):return types.SimpleNamespace(get=lambda k,d=None:values.get(k,d))
        class Settings:
            ui=lambda self,label:None
            widget=lambda self,tree,label:(object(),node(checked="true" if self.enabled else "false"))
            text_node=lambda self,tree,label:object()
            enabled=False
            def tap(self,n):self.enabled=True
        class Bursts:
            def run(self,label,*args,**kwargs):
                if args:args[0]()
                samples=[]
                for family in ("ipv4","ipv6"):
                    for protocol in ("tcp","udp"):
                        for sample,at,ok in ((0,1010,False),(1,1510,not failed),(2,1700,True)):
                            samples.append(dict(family=family,protocol=protocol,sample=sample,started_ms=at,success=ok,detail="fixture"))
                if label=='cold-lockdown-start':
                    if late:samples=[v for v in samples if v['started_ms']<1500]
                else:
                    samples=[dict(family=f,protocol=p,sample=0,started_ms=2000,success=not follow_failed,detail='followup') for f in ('ipv4','ipv6') for p in ('tcp','udp')]
                row={'samples':samples}
                result['leak_bursts'].append(row)
                return row
        log='1.000 Native NetworkPlan 1 APPLIED: fixture\n'
        if not missing:log+='1.501 Android VPN CONNECTED: generation=1 network=102 device_ms=1500\n'
        result={'require_published_start':True,'startup_state_enabled':True,'leak_bursts':[]}
        def bounded_wait(predicate,message,seconds):
            if not predicate():raise AssertionError(message)
        with tempfile.TemporaryDirectory() as temp:
            startup=StartupDns(lambda *a,**k:types.SimpleNamespace(stdout=log),Path(temp),result)
            with patch('audit_android_startup_dns.wait_until',side_effect=bounded_wait):
                startup.enable_lockdown(Settings(),Bursts())
        return result
    def test_pre_connected_errors_remain_fail_but_post_connected_must_pass(self):
        r=self.run_start()
        self.assertEqual(r['cold_start']['immediate_first_socket_status'],'FAIL_POST_PLAN_BLOCKING')
        self.assertEqual(r['cold_start']['published_start']['status'],'PASS')
        self.assertEqual(r['cold_start']['published_start']['post_connected_samples'],12)
        self.assertEqual(r['cold_start']['published_start']['cold_burst_post_connected_samples'],8)
    def test_missing_connected_and_post_connected_errors_are_rejected(self):
        with self.assertRaisesRegex(AssertionError,'did not publish CONNECTED'):self.run_start(missing=True)
        with self.assertRaisesRegex(AssertionError,'FAIL_POST_CONNECTED_BLOCKING'):self.run_start(failed=True)
    def test_late_publication_uses_fresh_followup_and_preserves_cold_coverage_gap(self):
        r=self.run_start(late=True)
        observation=r['cold_start']['published_start']
        self.assertEqual(observation['coverage'],'FOLLOWUP_ONLY_COLD_COVERAGE_GAP_RETAINED')
        self.assertEqual(observation['cold_burst_post_connected_samples'],0)
        self.assertEqual(observation['post_connected_samples'],4)
        self.assertTrue(all(v['source_phase']=='startup-followup' for v in observation['first_post_connected'].values()))
    def test_failed_followup_cannot_hide_coverage_gap(self):
        with self.assertRaisesRegex(AssertionError,'startup follow-up failed'):
            self.run_start(late=True,follow_failed=True)

if __name__=='__main__':unittest.main()
