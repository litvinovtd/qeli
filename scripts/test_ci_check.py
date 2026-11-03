"""Execute the local CI shell with isolated tools; never compile or touch networking."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/ci-check.sh"


@unittest.skipUnless(os.name == "posix", "requires a real POSIX shell")
class LocalCIGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="qeli-ci-fixtures-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "checkout with spaces"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "qeli").mkdir()
        self.runner = self.root / "scripts/ci-check.sh"
        self.runner.write_bytes(RUNNER.read_bytes().replace(b"\r\n", b"\n"))
        self.tools = Path(self.tmp.name) / "tools with spaces"
        self.tools.mkdir()
        self.log = Path(self.tmp.name) / "calls.jsonl"
        # A new output file and an isolated process environment per test. These tools
        # enforce lock/panic policy and inject child failures, not Rust compilation.
        source = '''#!PYTHON
import json, os, sys
from pathlib import Path
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
pin_arg = args.pop(0) if tool == "cargo" and args and args[0].startswith("+") else None
with open(os.environ["FIXTURE_LOG"], "a") as out:
    out.write(json.dumps(dict(tool=tool, args=args, cwd=os.getcwd(),
        pin=os.environ.get("RUSTUP_TOOLCHAIN"), pin_arg=pin_arg, panic=os.environ.get("CARGO_PROFILE_RELEASE_PANIC"))) + "\\n")
if tool == "python3" and args[:1] == ["-c"]:
    if os.environ.get("FAIL_TOOL") == "pin": sys.exit(27)
    print(os.environ.get("PIN_VALUE", "1.97.0")); sys.exit(0)
if tool == "cargo":
    if args[0] != "fmt" and "--locked" not in args:
        print("UNLOCKED_CARGO_REFUSED", file=sys.stderr); sys.exit(31)
    if os.environ.get("RUSTUP_TOOLCHAIN") != "1.97.0" or pin_arg != "+1.97.0":
        print("UNPINNED_RUST_REFUSED", file=sys.stderr); sys.exit(32)
    if "transport-core-ffi" in args and os.environ.get("CARGO_PROFILE_RELEASE_PANIC") != "unwind" and args[0] != "test":
        print("FFI_PANIC_POLICY_REFUSED", file=sys.stderr); sys.exit(33)
selector = tool + (":" + args[0] if tool == "cargo" else "")
if os.environ.get("FAIL_TOOL") == selector:
    print("INJECTED_FAILURE " + selector, file=sys.stderr); sys.exit(29)
'''.replace("#!PYTHON", "#!" + sys.executable)
        for tool in ("cargo", "python3", "node", "cc"):
            path = self.tools / tool
            path.write_text(source, encoding="utf-8", newline="\n")
            path.chmod(0o700)
        self.env = os.environ.copy()
        self.env.update(PATH=str(self.tools) + os.pathsep + os.environ["PATH"],
                        FIXTURE_LOG=str(self.log), RUSTUP_TOOLCHAIN="unreviewed-stable")
        self.env.pop("CARGO_PROFILE_RELEASE_PANIC", None)
        self.env.pop("FAIL_TOOL", None)
        self.env.pop("PIN_VALUE", None)

    def invoke(self, **changes):
        result = subprocess.run(["/bin/bash", str(self.runner)],
                                cwd=self.tmp.name, env=self.env | changes,
                                capture_output=True, text=True, timeout=25)
        self.calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result

    def test_success_uses_pinned_locked_feature_profiles_from_any_directory(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ALL GREEN", result.stdout)
        cargo = [call for call in self.calls if call["tool"] == "cargo"]
        self.assertTrue(cargo)
        for call in cargo:
            self.assertEqual(Path(call["cwd"]), self.root / "qeli")
            self.assertEqual(call["pin"], "1.97.0")
            self.assertEqual(call["pin_arg"], "+1.97.0")
            if call["args"][0] != "fmt":
                self.assertIn("--locked", call["args"])
        profiles = {tuple(call["args"]) for call in cargo}
        for feature in ("server", "client-bin", "transport-core-ffi"):
            self.assertTrue(any("--no-default-features" in args and feature in args for args in profiles), feature)
            self.assertIn(("test", "--locked", "--no-default-features", "--features",
                           feature, "--lib", "--", "--test-threads=1"), profiles)
        self.assertTrue(any("config_editor" in args for args in profiles))
        self.assertTrue(any("conformance-gen" in args for args in profiles))
        self.assertTrue(any("fuzz/Cargo.toml" in args for args in profiles))
        self.assertTrue(any(call["tool"] == "cc" for call in self.calls))
        python_args = [call["args"] for call in self.calls if call["tool"] == "python3"]
        for group in ("portable", "linux"):
            self.assertTrue(any("audit_test_suite.py" in " ".join(args) and group in args for args in python_args))

    def test_cargo_failure_is_retained_while_independent_checks_continue(self):
        result = self.invoke(FAIL_TOOL="cargo:test")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("INJECTED_FAILURE cargo:test", result.stderr)
        self.assertIn("FAILURES", result.stdout)
        self.assertNotIn("ALL GREEN", result.stdout)
        self.assertTrue(any(call["tool"] == "cargo" and call["args"][0] == "clippy" for call in self.calls))

    def test_non_cargo_failure_never_reports_green(self):
        result = self.invoke(FAIL_TOOL="node")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("INJECTED_FAILURE node", result.stderr)
        self.assertNotIn("ALL GREEN", result.stdout)
        self.assertTrue(any(call["tool"] == "cargo" for call in self.calls))

    def test_missing_pin_refuses_before_cargo(self):
        result = self.invoke(FAIL_TOOL="pin")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(any(call["tool"] == "cargo" for call in self.calls))
        self.assertNotIn("ALL GREEN", result.stdout)

    def test_malformed_pin_refuses_before_cargo(self):
        result = self.invoke(PIN_VALUE="stable; echo wrong")
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid pinned Rust toolchain", result.stderr)
        self.assertFalse(any(call["tool"] == "cargo" for call in self.calls))
        self.assertNotIn("ALL GREEN", result.stdout)


if __name__ == "__main__":
    unittest.main()
