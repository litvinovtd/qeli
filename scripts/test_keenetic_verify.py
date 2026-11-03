"""Verification gate tests: all compiler/SSH/service calls are controlled models."""
import contextlib
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).parent))
import keenetic_verify as gate

GRAPH = "qeli v0.8.2 (/private checkout)\n[build-dependencies]\nbuild-helper v1.0.0\nringbuf v0.4.0 (*)\n"
HEADER = "ELF Header:\n  Magic:   7f 45 4c 46 02 01 01 00\n"
ROOT = "/var/tmp/qeli-keenetic-verify.Abc123"
DIGEST = "a" * 64

class GraphTests(unittest.TestCase):
    def test_root_packages_build_section_duplicate_and_ringbuf_are_accepted(self):
        self.assertTrue(gate.client_graph_without_ring(GRAPH))
    def test_ring_dependency_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "ring is present"):
            gate.client_graph_without_ring(GRAPH + "ring v0.17.14\n")
    def test_old_absence_error_strings_are_not_successful_graphs(self):
        for value in ("error: package ID specification ring did not match any packages", "nothing to print"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):gate.client_graph_without_ring(value)
    def test_empty_wrong_root_and_unknown_output_fail_closed(self):
        for value in ("", "[build-dependencies]", "other v1.0.0", "qeli v0.8.2\nerror: failed to load lockfile"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):gate.client_graph_without_ring(value)

class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.connection = Mock();self.connection.client = object()
        self.fail = "";self.root = ROOT;self.graph = GRAPH;self.header = HEADER
        def checked(command, label, **kwargs):
            if label == self.fail:raise RuntimeError(label + " failed rc=17")
            if label == "create isolated verification checkout":return self.root
            if label == "client dependency graph":return self.graph
            if label == "nonempty executable ELF client artifact":return self.header
            return "checked command output"
        self.connection.checked.side_effect = checked
        for name, result in (("sync_router_source", 17),("require_router_source_ready", None),("remote_sha256",DIGEST)):
            patcher=patch.object(gate, name, return_value=result);setattr(self,name,patcher.start());self.addCleanup(patcher.stop)
        self.output=io.StringIO();patcher=contextlib.redirect_stdout(self.output);patcher.__enter__();self.addCleanup(patcher.__exit__,None,None,None)
    def test_success_checks_order_lock_jobs_isolation_hash_and_no_service_actions(self):
        result=gate.verify(self.connection)
        self.assertIn('server_build=OK',self.output.getvalue())
        self.assertEqual(result['remote_root'],ROOT);self.assertEqual(result['artifact_sha256'],DIGEST)
        self.sync_router_source.assert_called_once_with(self.connection.client,gate.LOCAL_ROOT,ROOT)
        self.require_router_source_ready.assert_called_once_with(self.connection.client,ROOT)
        labels=[c.args[1] for c in self.connection.checked.call_args_list]
        self.assertEqual(labels,['create isolated verification checkout','host toolchain inventory','server_build','unit_tests','client_build','client_clippy','client dependency graph','nonempty executable ELF client artifact'])
        commands=[c.args[0] for c in self.connection.checked.call_args_list]
        for command in commands:
            for banned in ('systemctl','pkill','kill -','/opt/qeli-src'):self.assertNotIn(banned,command)
        for command in commands[1:7]:self.assertIn('CARGO_TARGET_DIR='+ROOT+'/target',command)
        for command in commands[1:7]:
            self.assertIn('CARGO_BUILD_BUILD_DIR='+ROOT+'/target',command)
            self.assertIn('rustup which --toolchain 1.97.0 rustc',command)
            self.assertIn('RUSTC="$QELI_ROUTER_RUSTC"',command)
            self.assertIn('cargo +1.97.0 ',command)
        for command in commands[2:6]:self.assertIn('--locked',command);self.assertIn('--jobs 1',command)
        self.assertIn('--features jemalloc --bin qeli',commands[2])
        for command in commands[4:7]:self.assertIn('--no-default-features --features client-bin',command)
        self.remote_sha256.assert_called_once_with(self.connection,ROOT+'/target/release/qeli-client')
    def test_invalid_mktemp_output_never_reaches_source_sync(self):
        for root in ('/opt/qeli-src','/var/tmp/qeli-keenetic-verify.Abc123/../live','relative',ROOT+'\nother','/var/tmp/qeli-keenetic-verify.Abc123;bad'):
            self.root=root
            with self.subTest(root=root),self.assertRaises(RuntimeError):gate.verify(self.connection)
        self.sync_router_source.assert_not_called()
    def test_sync_failure_stops_before_build_and_readiness(self):
        self.sync_router_source.side_effect=IOError('upload failed')
        with self.assertRaises(IOError):gate.verify(self.connection)
        self.assertEqual(self.connection.checked.call_count,1);self.require_router_source_ready.assert_not_called()
    def test_incomplete_source_stops_before_build(self):
        self.require_router_source_ready.side_effect=RuntimeError('sync incomplete')
        with self.assertRaisesRegex(RuntimeError,'sync incomplete'):gate.verify(self.connection)
        self.assertEqual(self.connection.checked.call_count,1)
    def test_each_command_failure_stops_gate_before_later_steps(self):
        for label in ('create isolated verification checkout','host toolchain inventory','server_build','unit_tests','client_build','client_clippy','client dependency graph','nonempty executable ELF client artifact'):
            self.connection.reset_mock();self.remote_sha256.reset_mock();self.fail=label
            with self.subTest(label=label),self.assertRaisesRegex(RuntimeError,'rc=17'):gate.verify(self.connection)
            self.assertEqual(self.connection.checked.call_args.args[1],label);self.remote_sha256.assert_not_called()
    def test_ring_empty_and_error_graphs_stop_before_artifact(self):
        for graph in ('', GRAPH+'ring v0.17.14', 'error: ring did not match any packages'):
            self.graph=graph;self.connection.reset_mock()
            with self.subTest(graph=graph),self.assertRaises(RuntimeError):gate.verify(self.connection)
            self.assertEqual(self.connection.checked.call_args.args[1],'client dependency graph')
    def test_missing_or_nonelf_metadata_cannot_report_success(self):
        for header in ('','file: cannot open binary','ASCII text'):
            self.header=header
            with self.subTest(header=header),self.assertRaisesRegex(RuntimeError,'not an ELF'):gate.verify(self.connection)
        self.remote_sha256.assert_not_called()
    def test_artifact_hash_failure_or_empty_hash_fails(self):
        self.remote_sha256.side_effect=RuntimeError('hash failed')
        with self.assertRaisesRegex(RuntimeError,'hash failed'):gate.verify(self.connection)
        self.remote_sha256.side_effect=None
        self.remote_sha256.return_value='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        with self.assertRaisesRegex(RuntimeError,'empty'):gate.verify(self.connection)

class MainTests(unittest.TestCase):
    def setUp(self):
        self.connection=Mock();self.output=io.StringIO()
        for name,result in (('connect_lab',self.connection),('verify',{})):
            patcher=patch.object(gate,name,return_value=result);setattr(self,name,patcher.start());self.addCleanup(patcher.stop)
        patcher=patch.dict(os.environ,{'QELI_LAB_PASS':'test-only credential'},clear=True);patcher.start();self.addCleanup(patcher.stop)
        for redirect in (contextlib.redirect_stdout(self.output),contextlib.redirect_stderr(self.output)):
            redirect.__enter__();self.addCleanup(redirect.__exit__,None,None,None)
    def test_success_returns_zero_and_closes_connection(self):
        self.assertEqual(gate.main(),0);self.connection.close.assert_called_once()
        self.connect_lab.assert_called_once_with('10.66.116.11','root','test-only credential')
        self.assertIn('PASS',self.output.getvalue())
    def test_missing_password_returns_two_without_connection(self):
        os.environ.pop('QELI_LAB_PASS');self.assertEqual(gate.main(),2);self.connect_lab.assert_not_called()
    def test_connection_failure_returns_one_without_verification(self):
        self.connect_lab.side_effect=RuntimeError('cannot connect')
        self.assertEqual(gate.main(),1);self.verify.assert_not_called()
    def test_verification_exception_closes_and_returns_one(self):
        self.verify.side_effect=IOError('sync failed');self.assertEqual(gate.main(),1)
        self.connection.close.assert_called_once();self.assertNotIn('PASS',self.output.getvalue())
    def test_close_failure_is_not_success(self):
        self.connection.close.side_effect=IOError('close failed');self.assertEqual(gate.main(),1)
        self.assertNotIn('PASS',self.output.getvalue())
    def test_close_failure_preserves_original_failure_diagnostic(self):
        self.verify.side_effect=RuntimeError('build failed');self.connection.close.side_effect=IOError('close failed')
        self.assertEqual(gate.main(),1);self.assertIn('build failed',self.output.getvalue());self.assertIn('close failed',self.output.getvalue())
    def test_explicit_host_user_are_forwarded(self):
        os.environ.update(QELI_LAB_SERVER='fixture.invalid',QELI_LAB_USER='builder')
        self.assertEqual(gate.main(),0);self.connect_lab.assert_called_once_with('fixture.invalid','builder','test-only credential')

if __name__=='__main__':unittest.main()
