"""Committed snapshot and failure ownership for the optional 32-bit release gate.
Real temporary Git repositories; generated ELF/SSH models, not live lab compiles.
"""
import ast
import contextlib
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch
import router_release_gate as gate
from test_router_artifact import elf_fixture

ROOT = '/var/tmp/qeli-router-openwrt-ABC123'
FONT = b'wOF2\x00\x03\r\n\x80\rEND'


class GitFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qeli-gate-git-')
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        (self.repo/'qeli/src').mkdir(parents=True)
        (self.repo/'qeli/.cargo').mkdir()
        for name, data in {'Cargo.toml':b'[package]\nname="fixture"\n',
                           'Cargo.lock':b'version = 4\n',
                           '.cargo/config.toml':b'# fixture\n',
                           'src/lib.rs':b'pub fn fixture() {}\n',
                           'src/font.woff2':FONT}.items():
            (self.repo/'qeli'/name).write_bytes(data)
        self.git('init','--quiet')
        self.commit()

    def git(self, *args):
        return subprocess.check_output(['git','-c','core.autocrlf=false',*args],cwd=self.repo)

    def commit(self):
        self.git('add','qeli')
        self.git('-c','user.name=Audit Fixture','-c','user.email=audit@localhost',
                 'commit','--quiet','-m','fixture')



class SnapshotTests(GitFixture, unittest.TestCase):
    def test_committed_binary_CR_bytes_are_preserved(self):
        _, archive = gate.committed_crate_archive(self.repo)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            self.assertEqual(tar.extractfile('qeli/src/font.woff2').read(),FONT)
        (self.repo/'qeli/src/font.woff2').write_bytes(FONT.replace(b'\r',b''))
        self.commit()
        _, changed = gate.committed_crate_archive(self.repo)
        with tarfile.open(fileobj=io.BytesIO(changed)) as tar:
            self.assertEqual(tar.extractfile('qeli/src/font.woff2').read(),FONT.replace(b'\r',b''))
        self.assertNotEqual(hashlib.sha256(archive).digest(),hashlib.sha256(changed).digest())

    def test_dirty_source_config_and_recipe_refuse_snapshot(self):
        for path in ['qeli/src/lib.rs','qeli/.cargo/config.toml','scripts/router_toolchain.py','scripts/release_ci_gate.py']:
            with self.subTest(path=path):
                target=self.repo/path;target.parent.mkdir(exist_ok=True)
                old=target.read_bytes() if target.exists() else None
                target.write_bytes(b'changed\n')
                with self.assertRaisesRegex(RuntimeError,'committed'):gate.committed_crate_archive(self.repo)
                if old is None:target.unlink()
                else:target.write_bytes(old)

    def test_frozen_snapshot_keeps_original_bytes_after_working_tree_edit(self):
        commit, archive = gate.committed_crate_archive(self.repo)
        (self.repo/'qeli/src/font.woff2').write_bytes(b'replaced')
        self.assertEqual(commit,self.git('rev-parse','HEAD').decode().strip())
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            self.assertEqual(tar.extractfile('qeli/src/font.woff2').read(),FONT)


class BuildGateTests(GitFixture, unittest.TestCase):
    def prepare(self, mutate=None, failure=None):
        connection=Mock();connection.client=object()
        connection.payload=b''
        def build(command,timeout):
            target=command.split('--target ',1)[1].split()[0]
            connection.payload=elf_fixture(target)
            if failure=='build' and 'armv7' in target:return 'expected compiler failure',17
            if failure=='elf' and 'armv7' in target:connection.payload=b'not ELF'
            return 'fixture compile',0
        connection.run.side_effect=build
        connection.checked.side_effect=lambda command,label,timeout=30: (
            '0'*64 if failure=='sha' else hashlib.sha256(connection.payload).hexdigest())
        sftp=MagicMock();sftp.__enter__.return_value=sftp
        sftp.open.side_effect=lambda path,mode:io.BytesIO(connection.payload)
        connection.open_sftp.return_value=sftp
        def sync(client,local,remote):
            self.assertEqual((local/'src/font.woff2').read_bytes(),FONT)
            if mutate:(self.repo/'qeli/src/font.woff2').write_bytes(b'replaced during upload')
            return 5
        patches=[patch.object(gate,'create_router_checkout',return_value=ROOT),
                 patch.object(gate,'sync_router_source',side_effect=sync),
                 patch.object(gate,'require_router_source_ready'),
                 patch.object(gate,'ensure_router_toolchain'),
                 patch.object(gate,'restrict_router_crate_types')]
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        mocks=[stack.enter_context(p) for p in patches]
        return connection,mocks,sftp

    def test_committed_upload_and_common_pinned_commands_admit_both_targets(self):
        connection,mocks,sftp=self.prepare(mutate=True)
        report=gate.verify_router_release(connection,self.repo)
        self.assertEqual([r['status'] for r in report['results']],['PASS','PASS'])
        for arch,call in zip(gate.TARGETS,connection.run.call_args_list):
            command=call.args[0]
            self.assertIn('--locked --jobs 1 --release',command)
            self.assertIn('--remap-path-prefix='+ROOT+'=/usr/src/qeli',command)
            self.assertIn('CARGO_PROFILE_RELEASE_PANIC=abort',command)
            self.assertIn('nightly-2026-06-10' if arch=='mipsel' else '1.97.0',command)
            if arch=='mipsel':self.assertIn('-C link-arg=-msoft-float',command)
        mocks[2].assert_called_once();mocks[4].assert_called_once()
        self.assertEqual(sftp.__exit__.call_count,2)

    def test_failed_first_compile_does_not_hide_second_target_result(self):
        c,_,_=self.prepare(failure='build');report=gate.verify_router_release(c,self.repo)
        self.assertEqual([r['status'] for r in report['results']],['FAIL','PASS'])
        self.assertIn('rc=17',report['results'][0]['error'])

    def test_valid_digest_cannot_admit_non_ELF(self):
        c,_,sftp=self.prepare(failure='elf');report=gate.verify_router_release(c,self.repo)
        self.assertEqual([r['status'] for r in report['results']],['FAIL','PASS'])
        self.assertEqual(sftp.__exit__.call_count,2)

    def test_remote_digest_payload_mismatch_refuses_admission(self):
        c,_,sftp=self.prepare(failure='sha');report=gate.verify_router_release(c,self.repo)
        self.assertEqual([r['status'] for r in report['results']],['FAIL','FAIL'])
        self.assertEqual(sftp.__exit__.call_count,2)

    def test_upload_error_stops_before_tools_or_compile(self):
        c,mocks,_=self.prepare();mocks[1].side_effect=OSError('upload fault')
        with self.assertRaisesRegex(OSError,'upload fault'):gate.verify_router_release(c,self.repo)
        c.run.assert_not_called();mocks[3].assert_not_called()

    def test_tool_error_stops_before_manifest_projection_or_compile(self):
        c,mocks,_=self.prepare();mocks[3].side_effect=RuntimeError('tool fault')
        with self.assertRaisesRegex(RuntimeError,'tool fault'):gate.verify_router_release(c,self.repo)
        c.run.assert_not_called();mocks[4].assert_not_called()

    def test_link_or_escaping_archive_refuses_remote_creation(self):
        for name,kind in [('qeli/../outside',tarfile.REGTYPE),('qeli/link',tarfile.SYMTYPE)]:
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w') as tar:
                entry=tarfile.TarInfo(name);entry.type=kind
                if kind==tarfile.SYMTYPE:entry.linkname='/outside'
                tar.addfile(entry)
            with self.subTest(name=name),patch.object(gate,'create_router_checkout') as create:
                with self.assertRaisesRegex(RuntimeError,'unsafe'):
                    gate.verify_router_release(Mock(),self.repo,snapshot=('fixture',stream.getvalue()))
                create.assert_not_called()


class PreflightCallerTests(unittest.TestCase):
    def execute_gate(self, credential='fixture-only', build_error=None, connect_error=None, close_error=None, snapshot_error=None):
        path=Path(__file__).with_name('release_preflight.py')
        tree=ast.parse(path.read_text())
        nodes=[]
        for node in next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=="main").body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='lab_pass' for t in node.targets):nodes.append(node)
            elif isinstance(node,ast.If) and isinstance(node.test,ast.UnaryOp) and isinstance(node.test.operand,ast.Name) and node.test.operand.id=='lab_pass':nodes.append(node)
        self.assertEqual(len(nodes),2)
        connection=Mock();connection.close.side_effect=close_error
        connect=Mock(return_value=connection,side_effect=connect_error)
        verify=Mock(return_value={'source_commit':'fixture','remote_root':ROOT,'archive_sha256':'0'*64,
            'results':[{'arch':'armv7','status':'PASS','artifact_sha256':'1'*64}]},side_effect=build_error)
        namespace={'os':os,'ROOT':'fixture','source_commit':'fixture','failures':[],'connect_lab':connect,'verify_router_release':verify}
        with patch.dict(os.environ,{'QELI_LAB_PASS':credential},clear=True),patch.object(gate,'committed_crate_archive',return_value=('fixture',b''),side_effect=snapshot_error),contextlib.redirect_stdout(io.StringIO()):
            exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),namespace)
        return namespace['failures'],connect,connection,verify

    def test_disabled_optional_gate_does_not_connect(self):
        errors,connect,connection,_=self.execute_gate(credential='')
        self.assertEqual(errors,[]);connect.assert_not_called();connection.close.assert_not_called()

    def test_dirty_snapshot_refuses_before_connecting(self):
        errors,connect,connection,verify=self.execute_gate(snapshot_error=RuntimeError('dirty source'))
        self.assertEqual(len(errors),1);connect.assert_not_called();verify.assert_not_called()
        connection.close.assert_not_called()

    def test_configured_gate_cannot_skip_unavailable_ssh_dependency(self):
        errors,_,connection,verify=self.execute_gate(connect_error=RuntimeError('paramiko unavailable'))
        self.assertEqual(len(errors),1);verify.assert_not_called();connection.close.assert_not_called()

    def test_exception_closes_connected_ssh_and_records_failure(self):
        errors,_,connection,_=self.execute_gate(build_error=RuntimeError('build fault'))
        self.assertEqual(len(errors),1);connection.close.assert_called_once()

    def test_close_error_is_gate_failure_without_interrupting_later_gates(self):
        errors,_,connection,_=self.execute_gate(close_error=OSError('close fault'))
        self.assertEqual(len(errors),1);self.assertIn('close',errors[0]);connection.close.assert_called_once()


if __name__=='__main__':unittest.main()
