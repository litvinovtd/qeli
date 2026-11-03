"""Source/byte binding and fail-closed APK installation before Android E2E setup."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch
import android_apk_input as apk

DATA=b"fixed APK fixture"; SHA=hashlib.sha256(DATA).hexdigest(); NATIVE="b"*64

class AdmissionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.output=self.root/'output';self.output.mkdir();self.body=self.output/'app-debug.apk';self.body.write_bytes(DATA)
  for name in ['qeli/Cargo.toml','qeli-android/app/build.gradle.kts','conformance/sample.json','LICENSE','LICENSING.md']:
   f=self.root/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(name)
  self.git('init','--quiet');self.git('add','qeli','qeli-android','conformance','LICENSE','LICENSING.md');self.commit();self.head=self.git('rev-parse','HEAD').decode().strip()
  self.receipt=dict(source_commit=self.head,artifact_sha256=SHA,size=len(DATA),variant='debug',native_source_digest=NATIVE,local_artifact='/old/location/app-debug.apk');self.path=self.output/'BUILD.json';self.save();self.git('add','output');self.commit()
  self.addCleanup(patch.stopall);patch.object(apk,'source_digest',return_value=NATIVE).start();self.provenance=patch.object(apk,'validate_evidence',return_value=[]).start()
 def git(self,*args):return subprocess.check_output(['git',*args],cwd=self.root,stderr=subprocess.PIPE)
 def commit(self):self.git('-c','user.name=Fixture','-c','user.email=fixture@invalid','commit','--quiet','-m','input')
 def save(self):self.path.write_text(json.dumps(self.receipt))
 def admit(self):return apk.read_apk_receipt(self.path,self.root)
 def test_frozen_bytes_source_and_sha(self):
  value=self.admit();self.body.write_bytes(b'changed later');self.assertEqual(value.payload,DATA);self.assertEqual(value.sha256,SHA);self.assertEqual(value.source_commit,self.head)
 def test_moved_publication_uses_sibling_not_old_absolute_path(self):self.assertEqual(self.admit().payload,DATA)
 def test_selected_source_drift_refused(self):
  (self.root/'conformance/sample.json').write_text('new');self.git('add','conformance');self.commit()
  with self.assertRaisesRegex(ValueError,'selected source'):self.admit()
 def test_dirty_tree_refused(self):
  (self.root/'qeli-android/app/build.gradle.kts').write_text('dirty')
  with self.assertRaisesRegex(RuntimeError,'clean committed'):self.admit()
 def test_missing_source_commit_refused(self):
  self.receipt['source_commit']='f'*40;self.save();self.git('add','output');self.commit()
  with self.assertRaisesRegex(RuntimeError,'Git snapshot'):self.admit()
 def test_native_digest_and_evidence_refused(self):
  self.receipt['native_source_digest']='c'*64;self.save();self.git('add','output');self.commit()
  with self.assertRaisesRegex(ValueError,'native provenance'):self.admit()
  self.receipt['native_source_digest']=NATIVE;self.save();self.git('add','output');self.commit();self.provenance.return_value=['stale native']
  with self.assertRaisesRegex(ValueError,'native provenance'):self.admit()
 def test_same_size_changed_apk_refused(self):
  self.body.write_bytes(b'X'*len(DATA))
  with self.assertRaisesRegex(ValueError,'SHA256'):self.admit()
 def test_invalid_receipt_fields(self):
  for key,value in [('variant','release'),('artifact_sha256','no'),('source_commit','--help'),('size',True),('size',0),('size',128*1024*1024+1),('size',len(DATA)+1)]:
   with self.subTest(key=key,value=value):
    original=self.receipt[key];self.receipt[key]=value;self.save()
    with self.assertRaises(ValueError):self.admit()
    self.receipt[key]=original
 def test_receipt_size_bound(self):
  self.path.write_bytes(b'x'*65537)
  with self.assertRaisesRegex(ValueError,'64 KiB'):self.admit()

class InstallationTests(unittest.TestCase):
 def setUp(self):
  self.client=MagicMock();self.connection=MagicMock();self.root='/var/tmp/qeli-apk-test.Abcd1234';self.commands=[];self.output='Performing Streamed Install\nSuccess';self.install_error=None
  def checked(cmd,label,timeout):
   self.commands.append(cmd)
   if cmd.startswith('mktemp'):return self.root
   if ' install -r -d ' in cmd:
    if self.install_error:raise self.install_error
    return self.output
   if cmd.startswith('rm -f'):return ''
   raise AssertionError(cmd)
  self.connection.checked.side_effect=checked
  self.addCleanup(patch.stopall);patch.object(apk,'LabConnection',return_value=self.connection).start();self.remote=patch.object(apk,'remote_sha256',return_value=SHA).start();self.input=apk.ApkInput('a'*40,SHA,DATA)
 def install(self):return apk.install_verified_apk(self.client,self.input,'/private/sdk with space/adb')
 def test_exact_private_install_and_cleanup(self):
  self.assertIn('Success',self.install());self.assertIn("180s '/private/sdk with space/adb' install -r -d "+self.root+'/app-debug.apk',self.commands[1]);self.assertEqual(self.commands[-1],'rm -f -- '+self.root+'/app-debug.apk && rmdir -- '+self.root)
  stream=self.client.open_sftp.return_value.__enter__.return_value.open.return_value.__enter__.return_value;stream.write.assert_called_once_with(DATA);stream.set_pipelined.assert_called_once_with(True)
 def test_upload_sha_failure_never_installs(self):
  self.remote.return_value='0'*64
  with self.assertRaisesRegex(RuntimeError,'SHA256 mismatch'):self.install()
  self.assertFalse(any(' install -r' in s for s in self.commands));self.assertTrue(self.commands[-1].startswith('rm -f'))
 def test_nonzero_install_status_never_reports_success(self):
  self.install_error=RuntimeError('install exact APK rc=7')
  with self.assertRaisesRegex(RuntimeError,'rc=7'):self.install()
  self.assertTrue(self.commands[-1].startswith('rm -f'))
 def test_zero_status_without_unambiguous_success_refused(self):
  for value in ['Failure [INSTALL_FAILED]','', 'Success-ish','Success\nFailure [INSTALL_FAILED]']:
   self.output=value
   with self.subTest(value=value),self.assertRaisesRegex(RuntimeError,'did not confirm'):self.install()
 def test_upload_failure_closes_sftp_and_cleans_own_root(self):
  self.client.open_sftp.return_value.__enter__.return_value.open.side_effect=OSError('upload failed')
  with self.assertRaisesRegex(OSError,'upload failed'):self.install()
  self.client.open_sftp.return_value.__exit__.assert_called_once();self.assertTrue(self.commands[-1].startswith('rm -f'))
 def test_untrusted_staging_path_refused_without_delete(self):
  self.root='/root/android-project'
  with self.assertRaisesRegex(RuntimeError,'staging directory'):self.install()
  self.assertEqual(len(self.commands),1);self.client.open_sftp.assert_not_called()

class CliTests(unittest.TestCase):
 def test_four_consumers_require_receipt_before_ssh(self):
  root=Path(__file__).parent
  for name in ['e2e_android_faketls.py','e2e_android_udpquic.py','e2e_android_bonding.py','e2e_final.py']:
   for args,rc in [([],2),(['--help'],0),(['--apk-receipt','/missing/BUILD.json'],2)]:
    with self.subTest(script=name,args=args):
     result=subprocess.run([sys.executable,'-S','-B',str(root/name),*args],capture_output=True,timeout=8);self.assertEqual(result.returncode,rc,result.stdout+result.stderr);self.assertNotIn(b'Connecting',result.stdout+result.stderr)
 def test_final_install_failure_precedes_server_restoration(self):
  import ast
  from types import SimpleNamespace
  source=(Path(__file__).parent/'e2e_final.py').read_text(encoding='utf8');tree=ast.parse(source)
  index=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='original_server_bytes' for t in n.targets))
  gate=tree.body[index-1];self.assertIsInstance(gate,ast.Try)
  cc=MagicMock();sc=MagicMock();reader=MagicMock();namespace=dict(cc=cc,sc=sc,ensure_emulator=MagicMock(),install_verified_apk=MagicMock(side_effect=RuntimeError('ADB rejected')),APK_ARGS=SimpleNamespace(apk='exact input'),ADB='/sdk/adb',read_remote_bytes=reader)
  with self.assertRaisesRegex(RuntimeError,'ADB rejected'):exec(compile(ast.Module(body=[gate,tree.body[index]],type_ignores=[]),'exact final gate','exec'),namespace)
  cc.close.assert_called_once();sc.close.assert_called_once();reader.assert_not_called()
 def test_kill_switch_option_survives(self):
  with patch.object(apk,'read_apk_receipt',return_value=apk.ApkInput('a'*40,SHA,DATA)),contextlib.redirect_stdout(io.StringIO()):
   result=apk.read_cli(['--apk-receipt','BUILD.json','--kill-switch'],kill_switch=True);self.assertTrue(result.kill_switch)

if __name__=='__main__':unittest.main()
