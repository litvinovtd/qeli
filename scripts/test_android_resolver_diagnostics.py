import sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from audit_android_startup_dns import StartupDns

class ResolverDiagnosticsTest(unittest.TestCase):
    def run_helper(self, uid=10148, expected_uid=10148):
        journal=[];names=[]
        def arun(*args,**kwargs):
            if "broadcast" in args:
                name=args[args.index("dns_name")+1];mode=args[args.index("dns_mode")+1];names.append(name)
                # An unrelated prior operation and metadata must not masquerade as completion.
                journal.append(f"DNS uid={uid} mode={mode} name={name} metadata=activeVPN")
                suffix="error=DnsException:ENONET" if mode=="auto" else "answers=198.19.0.1"
                journal.append(f"DNS uid={uid} mode={mode} name={name} done_ms=42 {suffix}")
                output="Broadcast completed"
            elif "cat" in args:output="DNS uid=999 name=q29-old.test done_ms=1\n"+"\n".join(journal)
            else:output="state snapshot"
            return types.SimpleNamespace(stdout=output,stderr="")
        result={"probe_uids":{"com.qeli.test":str(expected_uid)}}
        with tempfile.TemporaryDirectory() as tmp:
            with patch("audit_android_startup_dns.time.time_ns",side_effect=range(100,108)):
                StartupDns(arun,Path(tmp),result).diagnose()
            self.assertEqual(len(list(Path(tmp).glob("resolver-*.log"))),7)
        return result,names

    def test_mixed_error_and_answers_are_preserved_per_unique_operation(self):
        result,names=self.run_helper()
        self.assertEqual(len(set(names)),7)
        self.assertEqual(len(result["resolver_diagnostics"]),7)
        auto=next(row for row in result["resolver_diagnostics"] if row["mode"]=="auto")
        self.assertTrue(any("ENONET" in line for line in auto["records"]))
        self.assertTrue(all("q29-old" not in line for row in result["resolver_diagnostics"] for line in row["records"]))

    def test_package_manager_uid_may_differ_between_readonly_installs(self):
        result,names=self.run_helper(uid=10149,expected_uid=10149)
        self.assertEqual(len(result["resolver_diagnostics"]),7)

    def test_foreign_uid_cannot_qualify_as_an_ordinary_app_probe(self):
        with self.assertRaises(AssertionError):self.run_helper(uid=0)

if __name__=="__main__":unittest.main()
