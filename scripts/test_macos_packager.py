'''Whole packager lifecycle with real input TARs and controlled SSH/sign/build tools.'''
import contextlib
import hashlib
import importlib.util
import io
import os
import plistlib
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

source = Path(os.environ.get('QELI_MAC_PACKAGER_BASELINE', Path(__file__).with_name('build_mac_universal.py')))
spec = importlib.util.spec_from_file_location('qeli_packager_under_test', source)
mac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mac)

class PackagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qeli-mac-packager-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'qeli-mac/dist'; self.dist.mkdir(parents=True)
        self.native = self.root / 'libqeli.dylib'; self.native.write_bytes(b'canonical native')
        self.info = self.root / 'Info.plist.in'
        self.info.write_bytes(plistlib.dumps({'LSMinimumSystemVersion': '15.0'}))
        self.icon = self.dist / 'Qeli.icns'; self.icon.write_bytes(b'icon')
        for arch in ('osx-arm64', 'osx-x64'): self.archive(arch)
        self.previous = self.dist / 'Qeli-macOS-universal.zip'
        self.previous.write_bytes(b'old ZIP')
        self.patches = [
            patch.object(mac, 'ROOT', self.root), patch.object(mac, 'DIST', self.dist),
            patch.object(mac, 'CANONICAL_DYLIB', self.native),
            patch.object(mac, 'INFO_PLIST_IN', self.info), patch.object(mac, 'ICNS', self.icon),
        ]
        for item in self.patches: item.start(); self.addCleanup(item.stop)
        self.runs = 0

    def archive(self, arch, unsafe=False, stale=False):
        with tarfile.open(self.dist / (arch+'.tar.gz'), 'w:gz') as outgoing:
            for name, data in [('QeliMac', b'controlled apphost'), ('libqeli.dylib', b'stale native' if stale else self.native.read_bytes())]:
                item = tarfile.TarInfo(arch+'/'+name); item.size=len(data); item.mode=0o755
                outgoing.addfile(item, io.BytesIO(data))
            if unsafe:
                data = b'escape'; item=tarfile.TarInfo('../outside'); item.size=len(data)
                outgoing.addfile(item, io.BytesIO(data))

    def execute(self, *, version=None, open_failure=None, upload_failure=False,
                corrupt=None, build_failure=False, pull_failure=False, close_failure=False):
        self.runs += 1
        runroot = '/var/tmp/qeli-mac-build.' + str(self.runs).zfill(8)
        connection = Mock(); channels=[]; commands=[]; uploads={}; events=[]
        def checked(command, label, timeout=600):
            commands.append(command)
            if command == mac.RCS+' --version': return version or mac.DEFAULT_RCODESIGN
            if command.startswith('mktemp -d '): return runroot
            if build_failure and 'python3 assemble.py' in command: raise RuntimeError('controlled assembly error')
            return 'controlled success'
        connection.checked.side_effect=checked
        connection.run.return_value=('', 1)
        def opened():
            index=len(channels)
            if index==open_failure: raise RuntimeError('controlled SFTP open error')
            sf=Mock(); channels.append(sf)
            def put(local, remote):
                events.append(('upload', remote))
                if upload_failure: raise RuntimeError('controlled upload error')
                data=Path(local).read_bytes()
                uploads[remote]=data+b'changed' if Path(remote).name==corrupt else data
            sf.put.side_effect=put
            if close_failure and index==0: sf.close.side_effect=RuntimeError('controlled SFTP close error')
            return sf
        connection.open_sftp.side_effect=opened
        def remote_hash(c, path):
            events.append(('hash', path))
            if path in uploads: return hashlib.sha256(uploads[path]).hexdigest()
            if path.endswith('/libqeli.dylib'): return hashlib.sha256(self.native.read_bytes()).hexdigest()
            if path.endswith('.zip'): return 'a'*64
            raise AssertionError(path)
        download=Mock(return_value=(12, 'a'*64, [('qeli-mac/dist/Qeli-macOS-universal.zip', True)]))
        if pull_failure: download.side_effect=RuntimeError('controlled download error')
        with patch.object(mac, 'conn', return_value=connection) as connect, \
             patch.object(mac, 'remote_sha256', side_effect=remote_hash), \
             patch.object(mac, 'pull_verified_artifact', download), contextlib.redirect_stdout(io.StringIO()):
            error=None
            try: mac.main()
            except Exception as caught: error=caught
        return dict(error=error, connection=connection, channels=channels, commands=commands,
                    uploads=uploads, events=events, connect=connect, download=download, root=runroot)

    def closed(self, run):
        run['connection'].close.assert_called_once()
        for sf in run['channels']: sf.close.assert_called_once()

    def test_signer_version_failure_closes_connection(self):
        r=self.execute(version='unexpected signer')
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)

    def test_sftp_open_failure_closes_connection(self):
        r=self.execute(open_failure=0)
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)

    def test_upload_failure_closes_both_handles(self):
        r=self.execute(upload_failure=True)
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)

    def test_upload_sha_failure_closes_both_handles(self):
        r=self.execute(corrupt='osx-arm64.tar.gz')
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)
        self.assertFalse(any('tar -x' in c for c in r['commands']))

    def test_assembly_failure_closes_connection(self):
        r=self.execute(build_failure=True)
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)
        r['download'].assert_not_called()
        self.assertEqual(self.previous.read_bytes(), b'old ZIP')

    def test_download_open_failure_closes_connection(self):
        r=self.execute(open_failure=1)
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)

    def test_download_failure_closes_both_handles(self):
        r=self.execute(pull_failure=True)
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)
        self.assertEqual(self.previous.read_bytes(), b'old ZIP')

    def test_sftp_close_failure_still_closes_connection(self):
        r=self.execute(close_failure=True)
        self.assertIsInstance(r['error'], RuntimeError); self.closed(r)

    def test_missing_local_input_refuses_before_connection(self):
        (self.dist/'osx-arm64.tar.gz').unlink()
        r=self.execute()
        self.assertIsInstance(r['error'], (OSError, RuntimeError))
        r['connect'].assert_not_called()

    def test_traversing_tar_refuses_before_connection(self):
        self.archive('osx-arm64', unsafe=True)
        r=self.execute()
        self.assertIsInstance(r['error'], RuntimeError)
        r['connect'].assert_not_called()

    def test_two_runs_upload_to_separate_private_workspaces(self):
        a=self.execute(); b=self.execute()
        self.assertIsNone(a['error']); self.assertIsNone(b['error'])
        self.assertTrue(set(a['uploads']).isdisjoint(b['uploads']))
        for run in (a,b):
            self.assertTrue(all(name.startswith(run['root']+'/') for name in run['uploads']))
            self.assertFalse(any('/root/mac-build' in c or 'rm -rf' in c or '*' in c.splitlines()[0] for c in run['commands']))
            self.closed(run)

    def test_metadata_substitution_refuses_before_extraction(self):
        r=self.execute(corrupt='Info.plist.in')
        self.assertIsInstance(r['error'], RuntimeError)
        self.assertFalse(any('tar -x' in c for c in r['commands']))
        self.closed(r)

    def test_success_downloads_verified_output_and_closes_handles(self):
        r=self.execute()
        self.assertIsNone(r['error']); self.closed(r)
        r['download'].assert_called_once()
        self.assertEqual(r['download'].call_args.args[2], 'a'*64)

    def test_stale_native_in_tar_refuses_before_connection(self):
        self.archive('osx-x64', stale=True)
        r=self.execute()
        self.assertIsInstance(r['error'], RuntimeError)
        r['connect'].assert_not_called()

if __name__ == '__main__':
    unittest.main()
