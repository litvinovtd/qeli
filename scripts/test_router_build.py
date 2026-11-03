"""Execute router helper failure paths without SSH, toolchain installs or real builds."""
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import router_artifact
import router_toolchain
from test_router_artifact import elf_fixture

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Build tests model transport. Missing Paramiko must never trigger installation
    # or a real connection; the imported lab helper gets a rejecting test-only stub.
    try:
        import paramiko
        transport_context=contextlib.nullcontext()
    except ModuleNotFoundError:
        transport=types.ModuleType('paramiko')
        transport.SSHClient=Mock(side_effect=AssertionError('SSH forbidden in router models'))
        transport_context=patch.dict(sys.modules,{'paramiko':transport})
    with transport_context:
        spec.loader.exec_module(module)
    return module

KEEN = load('q31_keen', ROOT / 'scripts/build_keenetic.py')
OPEN = load('q31_open', ROOT / 'qeli-openwrt/build/build_openwrt.py')
MODULES = (KEEN, OPEN)

class RouterBuildTests(unittest.TestCase):
    def selected(self, module, arch='aarch64'):
        return {arch: module.TARGETS[arch]}

    def invoke_main(self, module, argv, **overrides):
        client = Mock()
        changes = dict(connect=Mock(return_value=client), create_router_checkout=Mock(return_value="/var/tmp/qeli-router-"+("keenetic" if module is KEEN else "openwrt")+"-ABC123"),
            sync_tree=Mock(return_value=1), check_sync_ready=Mock(), ensure_toolchain=Mock(),
            restrict_router_crate_types=Mock(), build=Mock(return_value=0))
        if module is KEEN:
            changes['pull'] = Mock()
        changes.update(overrides)
        with tempfile.TemporaryDirectory(prefix='qeli-router-model-') as output, \
                patch.object(module, 'LOCAL_OUT', Path(output)), \
                patch.multiple(module, **changes), \
                patch.object(sys, 'argv', [module.__file__, *argv]), \
                contextlib.redirect_stdout(io.StringIO()):
            module.main()
        return client, changes

    def test_model_build_no_longer_publishes_separate_legal_archive(self):
        import native_licenses
        with patch.object(native_licenses, 'export_bundle_zip', side_effect=AssertionError('No sidecar archive')):
            self.invoke_main(KEEN, ['aarch64'])

    def test_invalid_arch_and_extra_arguments_never_connect(self):
        for module in MODULES:
            for args in (['typo'], ['aarch64', 'mipsel'], ['--unknown']):
                with self.subTest(module=module.__name__, args=args):
                    connect = Mock(side_effect=AssertionError('SSH must not be attempted'))
                    with patch.object(module, 'connect', connect), patch.object(sys, 'argv', [module.__file__, *args]), contextlib.redirect_stderr(io.StringIO()):
                        with self.assertRaises(SystemExit) as result: module.main()
                    self.assertEqual(result.exception.code, 2)
                    connect.assert_not_called()

    def test_both_helpers_delegate_selected_targets_to_shared_toolchain(self):
        for module in MODULES:
            selected=self.selected(module)
            with patch.object(module,'ensure_router_toolchain',return_value={'zig':'0.13.0'}) as shared,contextlib.redirect_stdout(io.StringIO()):
                module.ensure_toolchain(Mock(),selected)
            self.assertEqual(list(shared.call_args.args[1]),[module.TARGETS['aarch64']])

    def test_every_run_allocates_then_syncs_even_without_sync_option(self):
        for module in MODULES:
            for args in (['aarch64'], ['--sync','aarch64']):
                events=[]
                allocate=Mock(side_effect=lambda c,k:events.append('allocate') or '/var/tmp/qeli-router-'+k+'-ABC123')
                sync=Mock(side_effect=lambda c:events.append(('sync',module.REMOTE_ROOT)) or 1)
                client,changes=self.invoke_main(module,args,create_router_checkout=allocate,sync_tree=sync)
                self.assertEqual(events,['allocate',('sync','/var/tmp/qeli-router-'+('keenetic' if module is KEEN else 'openwrt')+'-ABC123')])
                self.assertIsNone(module.REMOTE_ROOT)
                client.close.assert_called_once()
                self.assertFalse(hasattr(module,'restore_router_manifest'))

    def test_setup_and_sync_failure_always_close_connection(self):
        for module in MODULES:
            for failed in ('create_router_checkout', 'sync_tree', 'check_sync_ready', 'ensure_toolchain','restrict_router_crate_types'):
                client = Mock()
                with self.subTest(module=module.__name__, failed=failed):
                    with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                        self.invoke_main(module, ['--sync', 'aarch64'], connect=Mock(return_value=client),
                            **{failed: Mock(side_effect=RuntimeError('fixture failure'))})
                    client.close.assert_called_once()

    def test_close_failure_propagates_and_clears_run_context(self):
        for module in MODULES:
            client=Mock();client.close.side_effect=RuntimeError('close failed')
            with self.assertRaisesRegex(RuntimeError,'close failed'):
                self.invoke_main(module,['aarch64'],connect=Mock(return_value=client))
            client.close.assert_called_once();self.assertIsNone(module.REMOTE_ROOT)

    def test_artifact_failure_cannot_report_success(self):
        for module in MODULES:
            client = Mock()
            failing = 'pull' if module is KEEN else 'build'
            with self.assertRaises(SystemExit) as result:
                self.invoke_main(module, ['aarch64'], connect=Mock(return_value=client),
                    **{failing: Mock(side_effect=IOError('SFTP read failed'))})
            self.assertEqual(result.exception.code, 1)
            client.close.assert_called_once()

    def test_failed_arch_does_not_prevent_other_selected_arch(self):
        for module in MODULES:
            client = Mock(); events = []
            def build(c, arch, *args):
                events.append(arch)
                if arch == 'aarch64': raise RuntimeError('fixture failure')
                return 0
            with self.assertRaises(SystemExit):
                self.invoke_main(module, [], connect=Mock(return_value=client), build=Mock(side_effect=build))
            self.assertEqual(events, list(module.TARGETS))
            client.close.assert_called_once()

    def transfer(self, module, client):
        if module is KEEN: module.pull(client, 'aarch64', module.TARGETS['aarch64'])
        else: module.build(client, 'aarch64', module.TARGETS['aarch64'])

    def test_verified_pull_success_mismatch_read_failure_and_empty_keep_previous(self):
        for module in MODULES:
            for mode in ('success', 'mismatch', 'read-failure', 'empty'):
                with self.subTest(module=module.__name__, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory); output = root / 'out'; output.mkdir()
                    name = 'qeli-client-keenetic-aarch64' if module is KEEN else 'qeli-client-openwrt-aarch64'
                    destination = output / name; destination.write_bytes(b'previous')
                    payload = elf_fixture(); digest = hashlib.sha256(payload).hexdigest()
                    if mode == 'empty': digest = hashlib.sha256(b'').hexdigest()
                    sf = Mock()
                    sf.open.return_value = io.BytesIO(b'different' if mode == 'mismatch' else payload)
                    if mode == 'read-failure': sf.open.side_effect = IOError('read failed')
                    client = Mock(); client.open_sftp.return_value = sf
                    with patch.multiple(module, REPO_ROOT=root, LOCAL_OUT=output, REMOTE_ROOT='/var/tmp/qeli-router-openwrt-ABC123'), patch.object(router_artifact, 'remote_sha256', return_value=digest), patch.object(module, 'run', return_value=(0, '')), contextlib.redirect_stdout(io.StringIO()):
                        if mode == 'success':
                            self.transfer(module, client)
                            self.assertEqual(destination.read_bytes(), payload)
                        else:
                            with self.assertRaises((RuntimeError, IOError)): self.transfer(module, client)
                            self.assertEqual(destination.read_bytes(), b'previous')
                    sf.close.assert_called_once()

    def test_wrong_elf_with_matching_hash_fails_actual_main_pull_on_both_helpers(self):
        for module in MODULES:
            client=Mock();sf=Mock();sf.open.side_effect=lambda *a:io.BytesIO(b'not ELF')
            client.open_sftp.return_value=sf
            overrides={'connect':Mock(return_value=client)}
            overrides['pull' if module is KEEN else 'build']=module.pull if module is KEEN else module.build
            with patch.object(module,'run',return_value=(0,'')),patch.object(router_artifact,'remote_sha256',return_value=hashlib.sha256(b'not ELF').hexdigest()):
                with self.assertRaises(SystemExit) as result:self.invoke_main(module,['aarch64'],**overrides)
            self.assertEqual(result.exception.code,1);sf.close.assert_called_once();client.close.assert_called_once()

    def test_both_helpers_delegate_sync_and_ready_check_to_shared_owner(self):
        for module in MODULES:
            client = Mock()
            with patch.object(module, 'sync_router_source', return_value=9) as sync, patch.object(module, 'require_router_source_ready') as ready:
                self.assertEqual(module.sync_tree(client), 9)
                module.check_sync_ready(client)
            sync.assert_called_once_with(client, module.LOCAL_SRC, module.REMOTE_ROOT)
            ready.assert_called_once_with(client, module.REMOTE_ROOT)

    def test_incomplete_cached_source_stops_before_setup_or_build_and_closes(self):
        for module in MODULES:
            client = Mock(); setup = Mock(); build = Mock()
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                self.invoke_main(module, ['aarch64'], connect=Mock(return_value=client),
                    check_sync_ready=Mock(side_effect=RuntimeError('incomplete')),
                    ensure_toolchain=setup, build=build)
            setup.assert_not_called(); build.assert_not_called(); client.close.assert_called_once()

    def test_build_uses_locked_client_graph_for_each_target(self):
        for module in MODULES:
            for arch, selected in module.TARGETS.items():
                run = Mock(return_value=(17, 'build failed'))
                with patch.object(module, 'run', run), patch.object(module,'REMOTE_ROOT','/var/tmp/qeli-router-keenetic-ABC123'), contextlib.redirect_stdout(io.StringIO()):
                    if module is KEEN: self.assertEqual(module.build(Mock(), arch, selected), 17)
                    else: self.assertEqual(module.build(Mock(), arch, selected), 17)
                command = run.call_args.args[1]
                self.assertIn('--locked', command)
                self.assertIn('--jobs 1',command)
                self.assertIn('CARGO_TARGET_DIR=',command)
                self.assertIn('CARGO_INCREMENTAL=0',command)
                self.assertIn('--no-default-features --features client-bin', command)
                self.assertIn('--bin qeli-client', command)

if __name__ == '__main__': unittest.main()
