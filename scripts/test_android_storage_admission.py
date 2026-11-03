import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from audit_android_release_ui import await_download_storage, download_storage_ready

READY = 'Q29_STORAGE_PATH=/storage/emulated/0\nFilesystem 1K-blocks Used Available Use% Mounted on\n/dev/fuse 10000 200 9800 2% /storage/emulated\nQ29_STORAGE_WRITABLE\n'

def proc(text=READY, rc=0):
    return types.SimpleNamespace(stdout=text, stderr='', returncode=rc)

class AndroidStorageAdmissionTests(unittest.TestCase):
    def test_boot_completed_or_writable_underlying_directory_is_insufficient(self):
        for text in ['1\n', READY.replace('/dev/fuse','/dev/block/dm-4'), READY.replace('/storage/emulated\n','/data\n'), READY.replace('Q29_STORAGE_WRITABLE\n','')]:
            with self.subTest(text=text):
                self.assertFalse(download_storage_ready(proc(text)))

    def test_transport_error_and_ambiguous_or_wrong_user_paths_are_refused(self):
        for value in [proc(rc=1), proc(READY+READY), proc(READY.replace('/storage/emulated/0','/storage/emulated/10')), proc(READY.replace(' 2%',''))]:
            with self.subTest(value=value.stdout):
                self.assertFalse(download_storage_ready(value))

    def test_delayed_mount_preserves_observations_and_admits_only_fresh_ready_state(self):
        clock=[0.0];responses=[proc('not mounted\n'),proc()];calls=[]
        def arun(*args,**kwargs):calls.append((args,kwargs));return responses.pop(0)
        def sleep(seconds):clock[0]+=seconds
        with tempfile.TemporaryDirectory() as temp,patch('audit_android_release_ui.time.monotonic',side_effect=lambda:clock[0]),patch('audit_android_release_ui.time.sleep',side_effect=sleep):
            p=Path(temp);result={}
            await_download_storage(arun,p,result,label='before-install',budget_seconds=5)
            rows=json.loads((p/'external-storage-before-install.json').read_text())
            self.assertEqual([v['ready'] for v in rows],[False,True])
            self.assertEqual(len(calls),2)
            self.assertTrue(all(args[0]=='shell' and kwargs['check'] is False for args,kwargs in calls))
            self.assertTrue(all('mkdir' not in args[1] for args,_ in calls))

    def test_probe_timeout_consumes_shared_budget_and_preserves_failure(self):
        clock=[0.0];calls=[]
        def arun(*args,**kwargs):
            calls.append(kwargs['timeout']);clock[0]+=kwargs['timeout']
            raise subprocess.TimeoutExpired('adb',kwargs['timeout'])
        def sleep(seconds):clock[0]+=seconds
        with tempfile.TemporaryDirectory() as temp,patch('audit_android_release_ui.time.monotonic',side_effect=lambda:clock[0]),patch('audit_android_release_ui.time.sleep',side_effect=sleep):
            p=Path(temp);result={}
            with self.assertRaisesRegex(AssertionError,'AVD_EXTERNAL_STORAGE_NOT_READY'):
                await_download_storage(arun,p,result,label='before-import',budget_seconds=3)
            self.assertEqual(calls,[3])
            self.assertEqual(clock[0],3)
            self.assertFalse(result['external_storage_admission']['before-import'][0]['ready'])
            self.assertTrue((p/'external-storage-before-import.json').exists())

    def test_unknown_phase_is_refused_before_any_adb_command(self):
        with self.assertRaises(ValueError):
            await_download_storage(lambda *a,**k:self.fail('ADB must not execute'),Path('.'),{},label='../escape')

if __name__=='__main__':unittest.main()
