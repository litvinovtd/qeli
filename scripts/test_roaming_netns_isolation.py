"""Linux Bash isolation admission; controlled commands, no kernel namespaces."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Linux Bash required")
class IsolationAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.trace = self.work / "trace"
        self.commands = self.work / "commands"
        self.commands.mkdir()
        self.env = dict(os.environ, QELI_TEST_TRACE=str(self.trace))
        for key in list(self.env):
            if key.startswith("QELI_ROAMING_") or key.startswith("BASH_FUNC_"):
                self.env.pop(key)
        self.env["PATH"] = str(self.commands) + ":" + self.env["PATH"]
        shutil.copy2(ROOT / "roaming_netns_isolation.sh", self.work)
        shutil.copy2(ROOT / "roaming_netns_supervisor.py", self.work)
        self.command("unshare", 'printf "%s\\n" "$@" > "$QELI_TEST_TRACE"; exit 23')
        for name in ("mktemp", "ip", "mount"):
            self.command(name, 'echo MUTATION >> "$QELI_TEST_TRACE"; exit 24')

    def tearDown(self):
        self.temp.cleanup()

    def command(self, name, body):
        path = self.commands / name
        path.write_text("#!/bin/bash\n" + body + "\n")
        path.chmod(0o755)

    def run_bash(self, *args, env=None):
        return subprocess.run(["bash", *map(str, args)], env=dict(self.env, **(env or {})),
                              text=True, capture_output=True, timeout=10)

    def test_both_runners_require_isolation_before_initial_cleanup(self):
        for name in ("roaming_netns_e2e.sh", "roaming_udp_netns_e2e.sh"):
            with self.subTest(runner=name):
                shutil.copy2(ROOT / name, self.work)
                r = self.run_bash(self.work / name, "binary with spaces", "success")
                self.assertEqual(r.returncode, 23, r.stdout + r.stderr)
                lines = self.trace.read_text().splitlines()
                self.assertEqual(lines[:6], ["--mount", "--net", "--pid", "--fork",
                                             "--mount-proc", "--kill-child=KILL"])
                self.assertEqual(lines[-3:], [str(self.work / name), "binary with spaces", "success"])
                self.assertNotIn("MUTATION", lines)

    def test_missing_helper_refuses_before_mktemp_and_ip(self):
        (self.work / "roaming_netns_isolation.sh").unlink()
        for name in ("roaming_netns_e2e.sh", "roaming_udp_netns_e2e.sh"):
            shutil.copy2(ROOT / name, self.work)
            r = self.run_bash(self.work / name)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertIn("isolation helper is missing", r.stderr)
            self.assertFalse(self.trace.exists())

    def test_missing_supervisor_refuses_before_mutation(self):
        (self.work / "roaming_netns_supervisor.py").unlink()
        shutil.copy2(ROOT / "roaming_netns_e2e.sh", self.work)
        r = self.run_bash(self.work / "roaming_netns_e2e.sh")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("namespace supervisor", r.stderr)
        self.assertFalse(self.trace.exists())

    def test_environment_flag_cannot_skip_launcher(self):
        shutil.copy2(ROOT / "roaming_netns_e2e.sh", self.work)
        r = self.run_bash(self.work / "roaming_netns_e2e.sh", env={
            "QELI_ROAMING_ISOLATED_NAMESPACES": "true", "ROAMING_PRIVATE_READY": "1"})
        self.assertEqual(r.returncode, 23, r.stdout + r.stderr)
        self.assertIn("--kill-child=KILL", self.trace.read_text())

    def test_namespace_verification_refuses_same_parent(self):
        fixture = self.work / "must-not-run"
        fixture.write_text('echo MUTATION > "$QELI_TEST_TRACE"\n')
        code = ('source "$1"; roaming_netns_private_run "$(readlink /proc/self/ns/mnt)" '
                '"$(readlink /proc/self/ns/net)" "$(readlink /proc/self/ns/pid)" "$2"')
        r = self.run_bash("-c", code, "verify", self.work / "roaming_netns_isolation.sh", fixture)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("requires a new mnt namespace", r.stderr)
        self.assertFalse(self.trace.exists())

    def test_mount_failure_refuses_before_payload(self):
        fixture = self.work / "must-not-run"
        fixture.write_text('echo PAYLOAD > "$QELI_TEST_TRACE"\n')
        code = 'source "$1"; roaming_netns_private_run parent-mnt parent-net parent-pid "$2"'
        r = self.run_bash("-c", code, "mount-failure", self.work / "roaming_netns_isolation.sh", fixture)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(self.trace.read_text().splitlines(), ["MUTATION"])

    def test_internal_launcher_rejects_invalid_invocation(self):
        for args in ((), ("--private",), ("invalid", "a", "b", "c", "d")):
            r = self.run_bash(self.work / "roaming_netns_isolation.sh", *args)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
            self.assertFalse(self.trace.exists())
