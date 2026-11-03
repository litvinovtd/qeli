"""Real Rust PublicationLock vs real dash/ash hook; ndmc remains a model."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
import test_keenetic_templates as templates

HELPER = r'''extern crate self as log;
#[macro_export] macro_rules! warn { ($($t:tt)*) => { eprintln!($($t)*); } }
#[path = "OPERATION_PATH"] mod operation_budget;
#[path = "PUBLICATION_PATH"] mod plan_publication;
fn main() {
 let a:Vec<String>=std::env::args().collect();
 let _scope=operation_budget::Scope::enter(std::time::Instant::now()+std::time::Duration::from_secs(3));
 let path=std::path::Path::new(&a[2]);
 let _lock=plan_publication::PublicationLock::acquire(path).unwrap();
 if a[1]=="hold" {
  std::fs::write(&a[3],b"entered").unwrap();
  let until=std::time::Instant::now()+std::time::Duration::from_secs(5);
  while !std::path::Path::new(&a[4]).exists() {
   assert!(std::time::Instant::now()<until,"fixture release deadline");
   std::thread::sleep(std::time::Duration::from_millis(10));
  }
 } else {
  // Only the atomic-write body is a seam here; the production Rust lock is exact.
  let next=path.with_extension("next");
  std::fs::write(&next,a[3].as_bytes()).unwrap();
  std::fs::rename(next,path).unwrap();
 }
}
'''

@unittest.skipUnless(os.name == 'posix', 'requires Linux/POSIX')
class PublicationTests(templates.KeeneticFixture):
    @classmethod
    def setUpClass(cls):
        compiler=shutil.which('rustc')
        if not compiler:raise unittest.SkipTest('requires Rust compiler for actual lock component')
        cls.build=tempfile.TemporaryDirectory(prefix='qeli-plan-writer-')
        cls.addClassCleanup(cls.build.cleanup)
        folder=Path(cls.build.name);source=folder/'writer.rs'
        source.write_text(HELPER.replace('OPERATION_PATH',str(templates.ROOT/'qeli/src/operation_budget.rs')).replace('PUBLICATION_PATH',str(templates.ROOT/'qeli/src/client/plan_publication.rs')))
        cls.writer=folder/'writer'
        subprocess.run([compiler,'--edition','2021',str(source),'-o',str(cls.writer)],check=True,capture_output=True,text=True,timeout=60)

    def setUp(self):
        super().setUp();self.folder=self.hook_setup()
        baseline=os.environ.get('QELI_PUBLICATION_BASELINE')
        if baseline:self.copy_template(Path(baseline),self.hook)
        self.plan_path=self.folder/'qeli.tunip'
        self.next_plan='10.8.0.9\nipv4=10.8.0.9/32\nmtu=1280\ngeneration=42\n'

    def wait_file(self,path):
        until=time.monotonic()+5
        while not path.exists() and time.monotonic()<until:time.sleep(.01)
        self.assertTrue(path.exists(),'owned process did not reach fixture barrier')

    def child(self,args,release):
        child=subprocess.Popen(args,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def finish():
            release.touch()
            try:child.communicate(timeout=8)
            except subprocess.TimeoutExpired:child.kill();child.communicate()
        self.addCleanup(finish);return child

    def test_publisher_waits_until_hook_saved_receipt_then_next_hook_applies_new_plan(self):
        release=self.root/'release'
        original=(self.bin/'ndmc').read_text().split('\n',1)[1]
        sleep=shlex.quote(shutil.which('sleep'))
        self.write_command('ndmc',original+'''
if [ "$2" = 'interface OpkgTun0 ip global auto' ]; then
 touch "$QELI_FIXTURE_ROOT/entered"
 n=0
 while [ ! -e "$QELI_FIXTURE_ROOT/release" ] && [ "$n" -lt 500 ]; do
  '''+sleep+''' 0.01; n=$((n+1))
 done
 [ -e "$QELI_FIXTURE_ROOT/release" ] || exit 19
fi
''')
        old=self.plan_path.read_text()
        hook=self.child(templates.SHELL+[str(self.hook)],release);self.wait_file(self.root/'entered')
        writer=self.child([str(self.writer),'publish',str(self.plan_path),self.next_plan],release)
        time.sleep(.12)
        self.assertIsNone(writer.poll(),'publisher changed a plan while its old generation was being applied')
        self.assertEqual(self.plan_path.read_text(),old)
        release.touch();out,err=hook.communicate(timeout=8);self.assertEqual(hook.returncode,0,out+err)
        out,err=writer.communicate(timeout=8);self.assertEqual(writer.returncode,0,out+err)
        self.assertEqual((self.folder/'qeli.opkgtun.applied').read_text(),'opkgtun0\n'+old)
        self.assertEqual(self.plan_path.read_text(),self.next_plan)
        self.assertEqual(self.run_script(self.hook).returncode,0)
        self.assertEqual((self.folder/'qeli.opkgtun.applied').read_text(),'opkgtun0\n'+self.next_plan)
        self.assertFalse((self.folder/'qeli.tunip.publish-lock').exists())

    def test_busy_core_publisher_refuses_hook_before_ndm(self):
        entered=self.root/'writer-entered';release=self.root/'writer-release'
        writer=self.child([str(self.writer),'hold',str(self.plan_path),str(entered),str(release)],release)
        self.wait_file(entered)
        result=self.run_script(self.hook)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.calls('ndmc-calls'),[])
        self.assertTrue((self.folder/'qeli.tunip.publish-lock').is_dir())
        release.touch();out,err=writer.communicate(timeout=8);self.assertEqual(writer.returncode,0,out+err)
        self.assertEqual(self.run_script(self.hook).returncode,0)

    def test_first_publication_can_finish_while_hook_holds_lifecycle_and_waits(self):
        self.plan_path.unlink();release=self.root/'release'
        sleep=shlex.quote(shutil.which('sleep'))
        self.write_command('sleep','touch "$QELI_FIXTURE_ROOT/waiting"\nexec '+sleep+' 0.1')
        hook=self.child(templates.SHELL+[str(self.hook)],release);self.wait_file(self.root/'waiting')
        self.assertTrue((self.folder/'qeli.lifecycle.lock').is_dir())
        writer=subprocess.run([str(self.writer),'publish',str(self.plan_path),self.next_plan],capture_output=True,text=True,timeout=5)
        self.assertEqual(writer.returncode,0,writer.stdout+writer.stderr)
        out,err=hook.communicate(timeout=8);self.assertEqual(hook.returncode,0,out+err)
        self.assertEqual((self.folder/'qeli.opkgtun.applied').read_text(),'opkgtun0\n'+self.next_plan)
        self.assertFalse((self.folder/'qeli.tunip.publish-lock').exists())

    def test_stale_lock_retained_without_ndm_mutation(self):
        lock=self.folder/'qeli.tunip.publish-lock';lock.mkdir();(lock/'canary').write_text('unknown owner')
        result=self.run_script(self.hook)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.calls('ndmc-calls'),[])
        self.assertEqual((lock/'canary').read_text(),'unknown owner')
        self.assertFalse((self.folder/'qeli.lifecycle.lock').exists())
