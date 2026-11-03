"""Real Git snapshot admission and APK builder ownership/lifecycle contracts."""
import contextlib
import io
import hashlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import rebuild_apk as apk

DUMMY = dict(commit="a"*40, native_source_digest="b"*64, archive=b"tar",
             archive_sha256=hashlib.sha256(b"tar").hexdigest(), files={"LICENSE":"c"*64})


class BuilderTests(unittest.TestCase):
    def test_import_has_no_ssh(self):
        code = "import native_lab; native_lab.connect_lab=lambda *a: (_ for _ in ()).throw(AssertionError('SSH on import')); import rebuild_apk"
        p = subprocess.run([sys.executable,"-B","-c",code],cwd=Path(__file__).parent,capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr)

    def test_invalid_arguments_before_connection(self):
        for args in [["--invalid"],["--signing-properties","/private/config"],["--release","--signing-properties","relative"],["--gradle-user-home","relative"]]:
            with patch.object(apk,"conn",side_effect=AssertionError("SSH")),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:apk.main(args)
                self.assertEqual(error.exception.code,2)

    def test_source_refusal_before_connection(self):
        with patch.object(apk,"prepare_snapshot",side_effect=RuntimeError("dirty")),patch.object(apk,"conn") as connect:
            with self.assertRaisesRegex(RuntimeError,"dirty"):apk.main([])
            connect.assert_not_called()

    def test_variants_and_handles(self):
        for args,release,props in [([],False,None),(["--release"],True,None),(["--release","--signing-properties","/private/keys"],True,"/private/keys")]:
            c=MagicMock()
            with patch.object(apk,"prepare_snapshot",return_value=DUMMY),patch.object(apk,"conn",return_value=c),patch.object(apk,"build") as build:
                self.assertEqual(apk.main(args),0)
                build.assert_called_once_with(c,c.open_sftp.return_value,release,DUMMY,props,offline=True,gradle_user_home=None,android_sdk="/root/android-sdk")
            c.open_sftp.return_value.close.assert_called_once();c.close.assert_called_once()

    def test_build_failure_closes_handles(self):
        c=MagicMock()
        with patch.object(apk,"prepare_snapshot",return_value=DUMMY),patch.object(apk,"conn",return_value=c),patch.object(apk,"build",side_effect=RuntimeError("compile failure")):
            with self.assertRaisesRegex(RuntimeError,"compile failure"):apk.main([])
        c.open_sftp.return_value.close.assert_called_once();c.close.assert_called_once()

    def test_sftp_open_failure_closes_connection(self):
        c=MagicMock();c.open_sftp.side_effect=OSError("open")
        with patch.object(apk,"prepare_snapshot",return_value=DUMMY),patch.object(apk,"conn",return_value=c):
            with self.assertRaises(OSError):apk.main([])
        c.close.assert_called_once()

    def test_sftp_close_failure_closes_connection(self):
        c=MagicMock();c.open_sftp.return_value.close.side_effect=OSError("close")
        with patch.object(apk,"prepare_snapshot",return_value=DUMMY),patch.object(apk,"conn",return_value=c),patch.object(apk,"build"):
            with self.assertRaises(OSError):apk.main([])
        c.close.assert_called_once()

    def test_orchestration_stays_in_private_roots_and_preserves_build_contract(self):
        for release in [False,True]:
            c=MagicMock();commands=[]
            def command(connection,cmd,t=1200):
                commands.append(cmd)
                if "testDebugUnitTest" in cmd:return "controlled refusal",7
                if "nm -D" in cmd:return "1",0
                return "",0
            with patch.object(apk,"deploy_snapshot",return_value="/var/tmp/qeli-apk-build.AAAAAAAA"),patch.object(apk,"sh",side_effect=command),contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,"APK build failed"):apk.build(c,MagicMock(),release,DUMMY)
            self.assertFalse(any("pkill" in cmd or "journal-1" in cmd or "/root/qeli-src" in cmd for cmd in commands))
            build=[cmd for cmd in commands if "testDebugUnitTest" in cmd][0]
            self.assertIn("/var/tmp/qeli-apk-build.AAAAAAAA/qeli-android",build)
            for flag in ["--offline","--no-daemon","--max-workers=1","timeout --signal=TERM"]:self.assertIn(flag,build)
            self.assertIn("assembleRelease" if release else "assembleDebug",build)
            if release:self.assertEqual(c.checked.call_args.args[0],"rm -f -- /var/tmp/qeli-apk-build.AAAAAAAA/qeli-android/keystore.properties")

    def test_bad_private_root_refuses_before_upload(self):
        for root in ["/root/android-project","/var/tmp/qeli-apk-build.AAAAAAAA/../foreign","/var/tmp/qeli-apk-build.AAAAAAAA\nforeign"]:
            c=MagicMock();c.checked.return_value=root;sf=MagicMock()
            with self.assertRaisesRegex(RuntimeError,"private APK checkout"):apk.deploy_snapshot(c,sf,DUMMY)
            sf.open.assert_not_called()

    def test_upload_hash_failure_before_extraction(self):
        c=MagicMock();c.checked.return_value="/var/tmp/qeli-apk-build.AAAAAAAA"
        with patch.object(apk,"remote_sha256",return_value="d"*64),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,"upload SHA"):apk.deploy_snapshot(c,MagicMock(),DUMMY)
        self.assertEqual(c.checked.call_count,1)

    def test_signing_setup_failure_removes_private_properties(self):
        c=MagicMock();c.checked.side_effect=[RuntimeError("signing"),""]
        with patch.object(apk,"deploy_snapshot",return_value="/var/tmp/qeli-apk-build.AAAAAAAA"):
            with self.assertRaisesRegex(RuntimeError,"signing"):apk.build(c,MagicMock(),True,DUMMY)
        self.assertEqual(c.checked.call_args.args[0],"rm -f -- /var/tmp/qeli-apk-build.AAAAAAAA/qeli-android/keystore.properties")

    def test_explicit_online_cache_and_environment_ownership(self):
        c=MagicMock();commands=[]
        def command(connection,cmd,t=1200):
            commands.append(cmd)
            if "testDebugUnitTest" in cmd:return "controlled refusal",7
            if "nm -D" in cmd:return "1",0
            return "",0
        with patch.object(apk,"deploy_snapshot",return_value="/var/tmp/qeli-apk-build.AAAAAAAA"),patch.object(apk,"sh",side_effect=command),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,"APK build failed"):
                apk.build(c,MagicMock(),False,DUMMY,offline=False,gradle_user_home="/private/cache with spaces",android_sdk="/private/sdk with spaces")
        self.assertIn("CARGO_TARGET_DIR=/var/tmp/qeli-apk-build.AAAAAAAA/qeli/target",commands[0])
        build=[cmd for cmd in commands if "testDebugUnitTest" in cmd][0]
        self.assertIn("GRADLE_USER_HOME='/private/cache with spaces'",build)
        self.assertIn("QELI_NATIVE_JNI_DIR=/var/tmp/qeli-apk-build.AAAAAAAA/qeli-android/app/src/main/jniLibs",build)
        self.assertNotIn("--offline",build)
        self.assertIn("ANDROID_HOME='/private/sdk with spaces'",build)

    def test_release_signer_lookup_uses_selected_private_sdk(self):
        calls=[];c=MagicMock()
        def checked(cmd,label,timeout=1200):
            calls.append((cmd,label))
            if label=="find apksigner":raise RuntimeError("controlled signer query")
            return ""
        c.checked.side_effect=checked
        def command(connection,cmd,t=1200):
            return ("1",0) if "nm -D" in cmd else ("BUILD SUCCESSFUL",0)
        with patch.object(apk,"deploy_snapshot",return_value="/var/tmp/qeli-apk-build.AAAAAAAA"),patch.object(apk,"sh",side_effect=command),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,"controlled signer query"):
                apk.build(c,MagicMock(),True,DUMMY,android_sdk="/private/sdk with spaces")
        lookup=[cmd for cmd,label in calls if label=="find apksigner"][0]
        self.assertIn("find '/private/sdk with spaces/build-tools'",lookup)
        self.assertTrue(calls[-1][0].startswith("rm -f -- /var/tmp/qeli-apk-build."))

    def test_simultaneous_local_outputs_do_not_overwrite_each_other_or_legacy_apk(self):
        payload=b"qualified controlled APK bytes";digest=hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);legacy=root/"qeli-android/dist/app-debug.apk"
            legacy.parent.mkdir(parents=True);legacy.write_bytes(b"previous APK")
            sf=MagicMock();sf.open.side_effect=lambda *args:io.BytesIO(payload)
            c=MagicMock()
            def command(connection,cmd,t=1200):
                if "nm -D" in cmd:return "1",0
                return "BUILD SUCCESSFUL",0
            receipts=[]
            with patch.object(apk,"REPO_ROOT",root),patch.object(apk,"sh",side_effect=command),patch.object(apk,"remote_sha256",return_value=digest),contextlib.redirect_stdout(io.StringIO()):
                for suffix in ["AAAAAAAA","BBBBBBBB"]:
                    with patch.object(apk,"deploy_snapshot",return_value="/var/tmp/qeli-apk-build."+suffix):
                        receipts.append(apk.build(c,sf,False,DUMMY))
            self.assertNotEqual(receipts[0]["local_artifact"],receipts[1]["local_artifact"])
            for receipt in receipts:
                self.assertEqual(Path(receipt["local_artifact"]).read_bytes(),payload)
                self.assertEqual(receipt["artifact_sha256"],digest)
                self.assertTrue(Path(receipt["local_artifact"]).with_name("BUILD.json").is_file())
            self.assertEqual(legacy.read_bytes(),b"previous APK")


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.git("init","--quiet")
        for name in apk.REQUIRED_INPUTS | {"conformance/qeli-links.json","qeli/src/lib.rs","qeli-android/LICENSE"}:
            f=self.root/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b"fixture\r\n\x00bytes")
        self.git("add",".");self.commit()
        self.digest=patch.object(apk,"source_digest",return_value="b"*64);self.digest.start();self.addCleanup(self.digest.stop)
        self.evidence=patch.object(apk,"validate_evidence",return_value=[]);self.evidence.start();self.addCleanup(self.evidence.stop)

    def git(self,*args):
        return subprocess.check_output(["git",*args],cwd=self.root,stderr=subprocess.STDOUT)

    def commit(self):
        self.git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","--quiet","-m","snapshot")

    def test_full_git_bytes_and_required_external_inputs(self):
        snapshot=apk.prepare_snapshot(self.root)
        self.assertEqual(snapshot["commit"],self.git("rev-parse","HEAD").decode().strip())
        with tarfile.open(fileobj=io.BytesIO(snapshot["archive"])) as archive:
            for member in archive:
                if member.isfile():self.assertEqual(archive.extractfile(member).read(),(self.root/member.name).read_bytes())
        for name in apk.REQUIRED_INPUTS | {"conformance/qeli-links.json","qeli-android/LICENSE"}:self.assertIn(name,snapshot["files"])
        self.assertNotIn("qeli-android/conformance/qeli-links.json",snapshot["files"])

    def test_dirty_and_untracked_refuse(self):
        f=self.root/"qeli/src/lib.rs";f.write_bytes(b"dirty")
        with self.assertRaisesRegex(RuntimeError,"clean committed"):apk.prepare_snapshot(self.root)
        self.git("checkout","--","qeli/src/lib.rs");(self.root/"untracked").write_bytes(b"new")
        with self.assertRaisesRegex(RuntimeError,"clean committed"):apk.prepare_snapshot(self.root)

    def test_hidden_git_flags_refuse(self):
        for flag in ["assume-unchanged","skip-worktree"]:
            self.git("update-index","--"+flag,"qeli/src/lib.rs")
            with self.assertRaisesRegex(RuntimeError,"trust flags"):apk.prepare_snapshot(self.root)
            self.git("update-index","--no-"+flag,"qeli/src/lib.rs")

    def test_missing_locks_refuse(self):
        self.git("rm","--quiet","qeli-android/app/gradle.lockfile");self.commit()
        with self.assertRaisesRegex(RuntimeError,"Missing APK snapshot inputs"):apk.prepare_snapshot(self.root)

    def test_stale_native_refuses(self):
        with patch.object(apk,"validate_evidence",return_value=["source digest drift"]):
            with self.assertRaisesRegex(RuntimeError,"native provenance refused"):apk.prepare_snapshot(self.root)

    def test_export_ignore_cannot_hide_committed_input(self):
        (self.root/".gitattributes").write_text("qeli-android/app/gradle.lockfile export-ignore\n")
        self.git("add",".gitattributes");self.commit()
        with self.assertRaisesRegex(RuntimeError,"archive omitted"):apk.prepare_snapshot(self.root)

    def test_export_subst_cannot_transform_committed_input(self):
        (self.root/".gitattributes").write_text("qeli/src/lib.rs export-subst\n")
        (self.root/"qeli/src/lib.rs").write_text("$Format:%H$\n")
        self.git("add",".");self.commit()
        with self.assertRaisesRegex(RuntimeError,"transformed"):apk.prepare_snapshot(self.root)

    def test_head_drift_refuses(self):
        commit=self.git("rev-parse","HEAD").decode().strip()
        with patch.object(apk,"identity",side_effect=[commit,"f"*40]):
            with self.assertRaisesRegex(RuntimeError,"source changed"):apk.prepare_snapshot(self.root)


if __name__ == "__main__":
    unittest.main()
