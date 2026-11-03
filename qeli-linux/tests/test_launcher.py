"""Unprivileged Linux launcher regression tests; no VPN or polkit required."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


LAUNCHER = Path(__file__).resolve().parents[1] / "launch-client.sh"
PROFILE = "[qeli]\nserver=192.0.2.1:443\nuser=fixture\npass=fixture-only\n"


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.runtime = self.directory / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.client = self.directory / "fake-client"
        self.client.write_text(
            "#!/bin/sh\nset -eu\n"
            'test "$#" -eq 2 && test "$1" = --config\n'
            'test -f "$2" && test ! -L "$2"\n'
            'cat "$2"\ncat "$2"\n', encoding="utf-8")
        self.client.chmod(0o700)

    def launch(self, runtime=None, args=None):
        env = dict(os.environ, RUNTIME_DIRECTORY=str(runtime or self.runtime))
        return subprocess.run(
            ["/bin/sh", str(LAUNCHER), *(args if args is not None else [str(self.client)])],
            input=PROFILE, text=True, capture_output=True, env=env, timeout=5)

    def test_regular_private_file_supports_repeated_core_reads(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, PROFILE * 2)
        config = self.runtime / "client.conf"
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertEqual(config.read_text(), PROFILE)

    def test_missing_runtime_is_rejected(self):
        result = self.launch(runtime=self.directory / "missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(PROFILE, result.stderr)

    def test_missing_client_argument_is_rejected(self):
        self.assertNotEqual(self.launch(args=[]).returncode, 0)

    def test_existing_file_is_not_overwritten(self):
        config = self.runtime / "client.conf"
        config.write_text("original")
        self.assertNotEqual(self.launch().returncode, 0)
        self.assertEqual(config.read_text(), "original")

    def test_symlink_is_not_followed(self):
        target = self.directory / "target"
        target.write_text("original")
        (self.runtime / "client.conf").symlink_to(target)
        self.assertNotEqual(self.launch().returncode, 0)
        self.assertEqual(target.read_text(), "original")

    @unittest.skipUnless(os.environ.get("QELI_TEST_SYSTEMD") == "1",
                         "enable with QELI_TEST_SYSTEMD=1 in a systemd user session")
    def test_systemd_runtime_directory_is_removed_after_exit(self):
        unit = f"qeli-launcher-test-{os.getpid()}"
        result = subprocess.run([
            "systemd-run", "--user", "--quiet", "--pipe", "--wait", "--collect",
            f"--unit={unit}", f"--property=RuntimeDirectory={unit}",
            "--property=RuntimeDirectoryMode=0700", "--property=UMask=0077",
            "/bin/sh", str(LAUNCHER), str(self.client)],
            input=PROFILE, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, PROFILE * 2)
        runtime_root = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
        self.assertFalse((runtime_root / unit).exists())


if __name__ == "__main__":
    unittest.main()
