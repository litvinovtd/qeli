"""Execute managed sync against isolated local paths using the real shell and SFTP adapter.
No /opt, SSH service, compiler, network settings or live lab checkout is changed.
"""
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from native_lab import LabConnection
from router_source import sync_router_source, require_router_source_ready

class LocalSftp:
    def __init__(self): self.fail = ''; self.closed = False
    def put(self, local, remote):
        if self.fail and self.fail in remote: raise IOError('injected upload failure')
        shutil.copyfile(local, remote)
    def close(self):
        self.closed = True
        if self.fail == 'close': raise IOError('injected close failure')
    def stat(self, path): return Path(path).stat()
    def mkdir(self, path): Path(path).mkdir()

class LocalClient:
    def __init__(self): self.sftp = LocalSftp(); self.commands = []; self.fail = ''; self.open_fail = False
    def exec_command(self, command, timeout=30):
        self.commands.append(command)
        if self.fail and self.fail in command: rc, output, error = 17, b'', b'injected command failure'
        else:
            result = subprocess.run(command, shell=True, capture_output=True, timeout=timeout)
            rc, output, error = result.returncode, result.stdout, result.stderr
        out = io.BytesIO(output)
        class Channel:
            def set_combine_stderr(self, value):
                assert value
                out.seek(0); out.write(output + error); out.seek(0)
            def recv_exit_status(self): return rc
            def close(self): pass
        out.channel = Channel()
        return io.BytesIO(), out, io.BytesIO(error)
    def open_sftp(self):
        if self.open_fail: raise IOError('injected open failure')
        return self.sftp

@unittest.skipUnless(os.name == 'posix', 'requires POSIX filesystem/shell; run in Linux lab')
class RouterSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-router-source-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.local = root / 'local'; self.remote = root / 'remote'
        for parent in (self.local, self.remote):
            (parent / 'src').mkdir(parents=True); (parent / '.cargo').mkdir()
        for name, value in {'src/client_main.rs':'current', 'src/asset.css':'asset',
                '.cargo/config.toml':'current config', 'Cargo.toml':'current manifest', 'Cargo.lock':'current lock'}.items():
            (self.local / name).write_text(value)
        (self.remote / 'src/removed.rs').write_text('stale module')
        (self.remote / 'src/bin').mkdir(); (self.remote / 'src/bin/old.rs').write_text('stale bin')
        (self.remote / '.cargo/config.toml').write_text('stale config')
        (self.remote / '.cargo/stale').write_text('stale cargo input')
        (self.remote / 'target').mkdir(); (self.remote / 'target/keep').write_text('cache')
        self.client = LocalClient()
        self.marker = self.remote / '.router-sync-incomplete'

    def sync(self): return sync_router_source(self.client, self.local, str(self.remote))
    def ready(self): return require_router_source_ready(self.client, str(self.remote))
    def assert_complete(self):
        for subtree in ('src', '.cargo'):
            def files(parent): return {p.relative_to(parent).as_posix():p.read_bytes() for p in parent.rglob('*') if p.is_file()}
            self.assertEqual(files(self.local / subtree), files(self.remote / subtree))
        for name in ('Cargo.toml', 'Cargo.lock'): self.assertEqual((self.local/name).read_bytes(), (self.remote/name).read_bytes())
        self.assertEqual((self.remote/'target/keep').read_text(), 'cache')
        self.assertFalse(self.marker.exists()); self.ready()

    def test_replaces_deleted_modules_bins_assets_config_and_keeps_target_cache(self):
        self.assertEqual(self.sync(), 2); self.assert_complete()
        self.assertTrue(self.client.sftp.closed)
        self.assertEqual(self.sync(), 2); self.assert_complete()

    def test_missing_mandatory_inputs_cannot_touch_remote_checkout(self):
        for name in ('src/client_main.rs', '.cargo/config.toml', 'Cargo.toml', 'Cargo.lock'):
            p = self.local / name; data = p.read_bytes(); p.unlink()
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'input is missing'): self.sync()
            self.assertEqual(self.client.commands, []); self.assertFalse(self.marker.exists())
            self.assertTrue((self.remote / 'src/removed.rs').exists()); p.write_bytes(data)

    def test_upload_failure_blocks_cached_build_until_retry_completes(self):
        self.client.sftp.fail = '/src/client_main.rs'
        with self.assertRaisesRegex(IOError, 'upload failure'): self.sync()
        self.assertTrue(self.marker.exists()); self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)
        self.assertTrue(self.client.sftp.closed)
        with self.assertRaisesRegex(RuntimeError, 'sync incomplete'): self.ready()
        self.client.sftp = LocalSftp(); self.assertEqual(self.sync(), 2); self.assert_complete()

    def test_manifest_upload_failure_and_sftp_close_failure_keep_marker(self):
        for fail in ('Cargo.lock', 'close'):
            self.client.sftp = LocalSftp(); self.client.sftp.fail = fail
            with self.subTest(fail=fail), self.assertRaises(IOError): self.sync()
            self.assertTrue(self.marker.exists()); self.assertTrue(self.client.sftp.closed)
            with self.assertRaises(RuntimeError): self.ready()
        self.client.sftp = LocalSftp(); self.sync(); self.assert_complete()

    def test_open_cleanup_mkdir_and_marker_removal_failures_stop_and_allow_retry(self):
        for fail in ('open', 'rm -rf', 'mkdir -p ' + str(self.remote / 'src'), 'rm -f'):
            self.client = LocalClient()
            if fail == 'open': self.client.open_fail = True
            else: self.client.fail = fail
            with self.subTest(fail=fail), self.assertRaises((IOError, RuntimeError)): self.sync()
            self.assertTrue(self.marker.exists())
            self.client.fail = ''; self.client.open_fail = False
            with self.assertRaises(RuntimeError): self.ready()
            self.sync(); self.assert_complete()

    def test_marker_creation_error_leaves_previous_sources_and_never_opens_sftp(self):
        self.client.fail = 'umask 077'
        with self.assertRaises(RuntimeError): self.sync()
        self.assertFalse(self.marker.exists()); self.assertTrue((self.remote / 'src/removed.rs').exists())
        self.assertFalse(self.client.sftp.closed)

    def test_unsafe_roots_rejected_before_any_command(self):
        for root in ('/', '/tmp/../opt', 'relative'):
            with self.subTest(root=root), self.assertRaises(ValueError): sync_router_source(self.client, self.local, root)
            with self.assertRaises(ValueError): require_router_source_ready(self.client, root)
        self.assertEqual(self.client.commands, [])

if __name__ == '__main__': unittest.main()
